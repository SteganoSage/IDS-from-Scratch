"""
fusion_ids.py — container-aware version

ENABLED_MODELS env var controls which models this node loads.

Signature keys : rf | lgbm | xgb
Anomaly key    : anomaly

Node combos (set in docker-compose):
  Node 0 → ENABLED_MODELS=rf,anomaly           (RF + anomaly)
  Node 1 → ENABLED_MODELS=lgbm,anomaly         (LGBM + anomaly)
  Node 2 → ENABLED_MODELS=xgb,anomaly          (XGB + anomaly)
  Node 3 → ENABLED_MODELS=rf,lgbm,xgb          (all 3 sig, majority vote, no anomaly)
  Node 4 → ENABLED_MODELS=anomaly              (anomaly only)

Stacking logic for node 3 (multiple signature models):
  - All 3 models vote on the flow
  - Majority label wins (2/3 agree = that label, avg confidence of agreeing models)
  - If all 3 disagree → highest confidence single prediction wins
"""

import os
from collections import Counter
from inference.signature_predictor import SignaturePredictor
from inference.anomaly_detector import AnomalyPredictor
from inference.fusion_engine import FusionEngine

MODEL_PATHS = {
    "rf":      "artifacts/rf_v1.pkl",
    "lgbm":    "artifacts/lgbm_v1.pkl",
    "xgb":     "artifacts/xgb_v1.pkl",
    "anomaly": "artifacts/anomaly_model_v2_tuned.joblib",
}

SIGNATURE_KEYS = {"rf", "lgbm", "xgb"}
ANOMALY_KEYS   = {"anomaly"}


class FusionIDS:

    def __init__(self):
        print("[INFO] Initializing FusionIDS pipeline...")

        # Default preserves original behaviour when no env var is set
        raw     = os.getenv("ENABLED_MODELS", "rf,anomaly")
        enabled = [k.strip().lower() for k in raw.split(",") if k.strip()]

        unknown = [k for k in enabled if k not in MODEL_PATHS]
        if unknown:
            raise ValueError(
                f"Unknown model keys in ENABLED_MODELS: {unknown}. "
                f"Valid keys: {list(MODEL_PATHS.keys())}"
            )

        sig_keys = [k for k in enabled if k in SIGNATURE_KEYS]
        ano_keys = [k for k in enabled if k in ANOMALY_KEYS]

        if len(ano_keys) > 1:
            raise ValueError(f"Only 1 anomaly model allowed per node, got: {ano_keys}")

        print(f"[INFO] Signature models : {sig_keys if sig_keys else 'none'}")
        print(f"[INFO] Anomaly  model   : {ano_keys[0] if ano_keys else 'none'}")
        if len(sig_keys) > 1:
            print(f"[INFO] Mode: stacked signature — majority vote across {len(sig_keys)} models")

        # Load all enabled signature models
        self.signature_models = {
            key: SignaturePredictor(model_path=MODEL_PATHS[key])
            for key in sig_keys
        }

        # Load anomaly model if enabled
        self.anomaly = AnomalyPredictor() if ano_keys else None

        self.fusion = FusionEngine()

        self._has_signature = bool(self.signature_models)
        self._has_anomaly   = self.anomaly is not None
        self._stacked       = len(self.signature_models) > 1

    # ── Stacked prediction (node 3 only) ──────────────────────────────────
    def _stacked_predict(self, flow) -> dict:
        """
        Majority vote across all loaded signature models.
        - 2+ models agree on label_id  → that label wins, confidence = avg of agreeing models
        - All models disagree          → highest confidence single prediction wins
        """
        votes = [m.predict(flow) for m in self.signature_models.values()]

        # Count votes per label_id
        label_counts = Counter(v["label_id"] for v in votes)
        majority_label, majority_count = label_counts.most_common(1)[0]

        if majority_count >= 2:
            # At least 2 models agree — use their average confidence
            agreeing = [v for v in votes if v["label_id"] == majority_label]
            avg_conf = sum(v["confidence"] for v in agreeing) / len(agreeing)
            winner   = dict(agreeing[0])   # copy label_name, family etc from first agreeing
            winner["confidence"] = round(avg_conf, 4)
            winner["stacked_votes"] = f"{majority_count}/{len(votes)}"
            return winner
        else:
            # No majority — highest confidence single prediction wins
            winner = max(votes, key=lambda v: v["confidence"])
            winner = dict(winner)
            winner["stacked_votes"] = f"1/{len(votes)} (no majority)"
            return winner

    # ── Main predict ──────────────────────────────────────────────────────
    def predict(self, flow) -> dict:

        # ── Signature ─────────────────────────────────────────────────────
        if self._has_signature:
            if self._stacked:
                sig_result = self._stacked_predict(flow)
            else:
                # Single signature model (nodes 0, 1, 2)
                sig_result = next(iter(self.signature_models.values())).predict(flow)
        else:
            # Anomaly-only node (node 4) — neutral signature result
            sig_result = {
                "label_id":   0,
                "label_name": "Benign",
                "family":     "Benign",
                "confidence": 1.0
            }

        # ── Anomaly ───────────────────────────────────────────────────────
        if self._has_anomaly:
            anomaly_result = self.anomaly.predict(flow)
        else:
            # Signature-only node (node 3) — neutral score, won't trigger anomaly path
            anomaly_result = {"anomaly_score": 0.0}

        # ── Fuse ──────────────────────────────────────────────────────────
        alert = self.fusion.fuse(sig_result, anomaly_result)

        return {
            "signature": sig_result,
            "anomaly":   anomaly_result,
            "alert":     alert
        }