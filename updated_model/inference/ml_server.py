"""
ml_server.py
=============
FastAPI inference server for FusionIDS.
Receives flow features from the C++ FeatureSender via HTTP POST /predict.

Request body:
    {
        "features": {"Flow Duration": 123, "Tot Fwd Pkts": 4, ...},
        "meta": {"src_ip": 123, "dst_ip": 456, "src_port": 80,
                 "dst_port": 443, "protocol": 6}
    }

Response:
    {
        "signature": { "label_id": 0, "label_name": "Benign", "confidence": 0.97 },
        "anomaly":   { "anomaly_score": -0.32 },
        "alert":     null | { "label_name": "...", "severity": "...", "fusion": "..." },
        "meta":      { "src_ip": ..., ... }
    }

Usage:
    pip install fastapi uvicorn
    python ml_server.py                        # default port 8000
    python ml_server.py --host 0.0.0.0 --port 8000 --node-url http://localhost:5000
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import argparse
import logging
import time
import requests as http_requests
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from inference.fusion_ids import FusionIDS

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt= "%H:%M:%S",
)
log = logging.getLogger("ml_server")

import os

# ── Globals ───────────────────────────────────────────────────────────────────
ids: Optional[FusionIDS] = None

# URL of the local blockchain node's /alert endpoint.
# Read from environment variable BLOCKCHAIN_NODE_URL so it survives
# uvicorn worker forking (setting a module global in __main__ doesn't
# carry over when uvicorn reimports the module string "ml_server:app").
BLOCKCHAIN_NODE_URL: Optional[str] = os.environ.get("BLOCKCHAIN_NODE_URL")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global ids
    log.info("=" * 55)
    log.info("  FusionIDS ML Server starting...")
    log.info("=" * 55)
    t0  = time.time()
    ids = FusionIDS()
    log.info(f"Models loaded in {time.time()-t0:.2f}s — ready for traffic")
    if BLOCKCHAIN_NODE_URL:
        log.info(f"Blockchain node : {BLOCKCHAIN_NODE_URL}/alert")
    else:
        log.warning("No blockchain node URL set — alerts will NOT be forwarded")
    log.info("=" * 55)
    yield
    log.info("Server shutting down.")


app = FastAPI(
    title    = "FusionIDS Inference Server",
    version  = "1.0.0",
    lifespan = lifespan,
)


# ── Request / Response schemas ────────────────────────────────────────────────
class PredictRequest(BaseModel):
    features: Dict[str, Any]
    meta:     Optional[Dict[str, Any]] = None


class PredictResponse(BaseModel):
    signature:  Dict[str, Any]
    anomaly:    Dict[str, Any]
    alert:      Optional[Dict[str, Any]]
    meta:       Optional[Dict[str, Any]]
    latency_ms: float


# ── Blockchain forwarding ─────────────────────────────────────────────────────

def forward_alert_to_blockchain(
    signature_info: dict,
    anomaly_info:   dict,
    alert_info:     dict,
    meta:           dict,
    features:       dict,
) -> None:
    """
    POST the alert to the local blockchain node's /alert endpoint.

    Runs in a background thread so it never blocks the /predict response.

    The blockchain node will:
      1. Build an AlertTransaction from this payload
      2. Sign it with its own private key
      3. Call submit_alert() → PBFT consensus → block committed

    The full features dict is included so peer nodes can re-run their
    own local IDS model on the same features to validate the alert
    before sending PREPARE.

    Only called when alert is not None (i.e. non-benign traffic detected).
    """
    if not BLOCKCHAIN_NODE_URL:
        return

    payload = {
        "signature": signature_info,
        "anomaly":   anomaly_info,
        "alert":     alert_info,
        "meta":      meta,
        "features":  features,      # raw flow features for peer validation
    }

    try:
        resp = http_requests.post(
            f"{BLOCKCHAIN_NODE_URL}/alert",
            json    = payload,
            timeout = 3,
        )
        if resp.status_code == 202:
            log.info(
                f"BLOCKCHAIN  accepted  "
                f"{alert_info.get('label_name','?')} | "
                f"tx_id={resp.json().get('tx_id','?')[:12]}…"
            )
        else:
            log.warning(
                f"BLOCKCHAIN  rejected  "
                f"status={resp.status_code} body={resp.text[:80]}"
            )
    except http_requests.RequestException as e:
        log.error(f"BLOCKCHAIN  unreachable — {e}")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Health check — C++ sender can poll this before starting capture."""
    return {"status": "ok", "model": "FusionIDS v1"}


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    """
    Main prediction endpoint.
    Called by C++ FeatureSender once per expired flow.

    If the result contains a non-null alert (non-benign traffic),
    the alert is forwarded to the local blockchain node in a background
    thread without blocking this response.
    """
    if ids is None:
        raise HTTPException(status_code=503, detail="Model not loaded yet")

    t0 = time.perf_counter()

    try:
        result = ids.predict(req.features)
    except KeyError as e:
        raise HTTPException(
            status_code=422,
            detail=f"Missing feature: {e}. Check feature names match features.json"
        )
    except Exception as e:
        log.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    latency_ms = (time.perf_counter() - t0) * 1000

    alert = result.get("alert")
    meta  = req.meta or {}
    sig   = result["signature"]

    # Log every flow
    log.info(
        f"FLOW   {sig.get('label_name','?'):20s}  "
        f"conf={sig.get('confidence',0)*100:5.1f}%  "
        f"src={meta.get('src_ip','?')}:{meta.get('src_port','?')}  "
        f"dst={meta.get('dst_ip','?')}:{meta.get('dst_port','?')}  "
        f"proto={meta.get('protocol','?')}  "
        f"{latency_ms:.1f}ms"
    )

    if alert:
        log.warning(
            f"ALERT  {alert.get('severity','?'):8s}  "
            f"{alert.get('label_name','?'):20s}  "
            f"fusion={alert.get('fusion','?'):20s}  "
            f"src={meta.get('src_ip','?')}:{meta.get('src_port','?')}  "
            f"dst={meta.get('dst_ip','?')}:{meta.get('dst_port','?')}  "
            f"{latency_ms:.1f}ms"
        )

        # ── Forward to blockchain node in background ──────────────────
        import threading
        threading.Thread(
            target  = forward_alert_to_blockchain,
            args    = (
                result["signature"],
                result["anomaly"],
                alert,
                meta,
                req.features,
            ),
            daemon  = True,
        ).start()

    return PredictResponse(
        signature  = result["signature"],
        anomaly    = result["anomaly"],
        alert      = alert,
        meta       = req.meta,
        latency_ms = round(latency_ms, 3),
    )


@app.post("/validate", response_model=PredictResponse)
def validate(req: PredictRequest):
    """
    Peer validation endpoint.
    Called by OTHER blockchain nodes during PBFT PRE-PREPARE phase
    to independently verify an alert using their own local IDS model.

    Identical to /predict in terms of inference — runs the same
    FusionIDS pipeline on the same raw features.

    Key difference: NEVER forwards result to blockchain.
    This prevents an infinite loop where peer validation triggers
    a new alert which triggers more peer validations.

    Return value is used by Is_Valid_Alert() in PBFT_Node:
        alert != null → non-benign → agree → send PREPARE
        alert == null → benign     → disagree → drop PRE-PREPARE
    """
    if ids is None:
        raise HTTPException(status_code=503, detail="Model not loaded yet")

    t0 = time.perf_counter()

    try:
        result = ids.predict(req.features)
    except KeyError as e:
        raise HTTPException(
            status_code=422,
            detail=f"Missing feature: {e}. Check feature names match features.json"
        )
    except Exception as e:
        log.error(f"Validation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    latency_ms = (time.perf_counter() - t0) * 1000

    alert = result.get("alert")
    if alert:
        log.info(
            f"VALIDATE  AGREE      "
            f"{alert.get('label_name','?'):20s}  "
            f"fusion={alert.get('fusion','?'):20s}  "
            f"severity={alert.get('severity','?'):8s}  "
            f"{latency_ms:.1f}ms"
        )
    else:
        log.info(
            f"VALIDATE  DISAGREE   "
            f"Benign                "
            f"anomaly_score={result['anomaly'].get('anomaly_score',0):.3f}  "
            f"{latency_ms:.1f}ms"
        )

    # No blockchain forwarding — just return the inference result
    return PredictResponse(
        signature  = result["signature"],
        anomaly    = result["anomaly"],
        alert      = alert,
        meta       = req.meta,
        latency_ms = round(latency_ms, 3),
    )


@app.get("/stats")
def stats():
    """Basic server stats."""
    return {
        "status":           "running",
        "model":            "FusionIDS v1",
        "sig_model":        str(ids.signature.model) if ids else None,
        "blockchain_node":  BLOCKCHAIN_NODE_URL,
    }


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FusionIDS ML Server")
    parser.add_argument("--host",     default="0.0.0.0",
                        help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port",     type=int, default=8000,
                        help="Port to bind (default: 8000)")
    parser.add_argument("--workers",  type=int, default=1,
                        help="Number of worker processes (default: 1)")
    parser.add_argument("--reload",   action="store_true",
                        help="Auto-reload on code changes (dev only)")
    parser.add_argument("--node-url", default=None,
                        dest="node_url",
                        help="Blockchain node base URL e.g. http://localhost:5000")
    args = parser.parse_args()

    if args.node_url:
        os.environ["BLOCKCHAIN_NODE_URL"] = args.node_url

    log.info(f"Starting server on {args.host}:{args.port}")
    uvicorn.run(
        "ml_server:app",
        host      = args.host,
        port      = args.port,
        workers   = args.workers,
        reload    = args.reload,
        log_level = "warning",
    )