"""
test_pipeline.py
================
End-to-end pipeline test for IDS → Blockchain integration.

Tests three levels:
  Level 1 — Blockchain node alone  (no ml_server needed)
  Level 2 — ml_server → blockchain node
  Level 3 — Full PBFT consensus across all 5 nodes

Usage:
    # Level 1 only (just node 0 running)
    python test_pipeline.py --level 1

    # Level 1 + 2 (node 0 + ml_server on port 8000)
    python test_pipeline.py --level 2

    # All levels (all 5 nodes + all 5 ml_servers running)
    python test_pipeline.py --level 3

    # Default runs all levels
    python test_pipeline.py
"""

import argparse
import json
import time
import requests
import sys

# ── Config ────────────────────────────────────────────────────────────────────

NODE_URLS = {
    0: "http://localhost:5000",
    1: "http://localhost:5001",
    2: "http://localhost:5002",
    3: "http://localhost:5003",
    4: "http://localhost:5004",
}

ML_URLS = {
    0: "http://0.0.0.0:8000",
    1: "http://0.0.0.0:8001",
    2: "http://0.0.0.0:8002",
    3: "http://0.0.0.0:8003",
    4: "http://0.0.0.0:8004",
}

# Fake alert payload — mimics what ml_server sends to /alert
FAKE_ALERT_PAYLOAD = {
    "signature": {
        "label_id":   2,
        "label_name": "DDoS",
        "confidence": 0.97
    },
    "anomaly": {
        "anomaly_score": -0.84
    },
    "alert": {
        "label_name": "DDoS",
        "severity":   "high",
        "fusion":     "both_agree"
    },
    "meta": {
        "src_ip":   "192.168.1.5",
        "dst_ip":   "10.0.0.1",
        "src_port": 443,
        "dst_port": 80,
        "protocol": 6
    },
    "features": {
        "Init Fwd Win Byts": 8192,
        "Fwd Seg Size Min": 20,
        "Flow IAT Mean": 5000000,
        "Fwd Header Len": 40,
        "Flow IAT Max": 10000000,
        "Flow Duration": 120000000,
        "Fwd IAT Tot": 100000000,
        "Fwd Pkts/s": 10,
        "Flow Pkts/s": 12,
        "Fwd IAT Max": 9000000,
        "Bwd Pkts/s": 1,
        "Flow IAT Min": 2000000,
        "Fwd IAT Mean": 5000000,
        "Fwd IAT Min": 1000000,
        "Bwd Header Len": 20,
        "Init Bwd Win Byts": 0,
        "Subflow Fwd Byts": 20000000,
        "Fwd Pkt Len Max": 1500,
        "Pkt Len Max": 1500,
        "Fwd Seg Size Avg": 1200,
        "Pkt Size Avg": 1100,
        "TotLen Fwd Pkts": 20000000,
        "Bwd Pkt Len Mean": 100,
        "Fwd Pkt Len Mean": 1200,
        "TotLen Bwd Pkts": 2000,
        "Tot Fwd Pkts": 15000,
        "Pkt Len Mean": 1000,
        "Bwd Seg Size Avg": 100,
        "Pkt Len Var": 1000,
        "Subflow Bwd Byts": 2000,
        "Bwd Pkt Len Max": 200,
        "Subflow Fwd Pkts": 15000,
        "Pkt Len Std": 30,
        "Subflow Bwd Pkts": 20,
        "Tot Bwd Pkts": 20,
        "Flow IAT Std": 500000,
        "Fwd Pkt Len Std": 50,
        "Bwd Pkt Len Std": 10,
        "Flow Byts/s": 200000000,
        "Bwd IAT Tot": 100000,
        "Bwd IAT Max": 10000,
        "Fwd IAT Std": 200000,
        "Bwd IAT Mean": 10000,
        "Fwd Act Data Pkts": 15000,
        "Bwd IAT Std": 1000,
        "Bwd IAT Min": 100,
        "ECE Flag Cnt": 0,
        "RST Flag Cnt": 0,
        "Fwd Pkt Len Min": 1000,
        "ACK Flag Cnt": 1,
        "Bwd Pkt Len Min": 60,
        "Idle Max": 1000000,
        "Down/Up Ratio": 0,
        "Idle Mean": 500000,
        "Idle Min": 100000,
        "Pkt Len Min": 60,
        "PSH Flag Cnt": 0,
        "URG Flag Cnt": 0,
        "Active Max": 50000,
        "Active Min": 20000,
        "Active Mean": 30000,
        "Idle Std": 200000,
        "Active Std": 5000,
        "Fwd PSH Flags": 0,
        "SYN Flag Cnt": 1,
        "FIN Flag Cnt": 0,
        "Fwd Byts/b Avg": 0,
        "Fwd URG Flags": 0
    }
}

# ── Helpers ───────────────────────────────────────────────────────────────────

PASS = "\033[92m✓ PASS\033[0m"
FAIL = "\033[91m✗ FAIL\033[0m"
INFO = "\033[94m→\033[0m"

def check(condition, label, detail=""):
    status = PASS if condition else FAIL
    print(f"  {status}  {label}")
    if detail and not condition:
        print(f"         {detail}")
    return condition

def section(title):
    print(f"\n{'─' * 55}")
    print(f"  {title}")
    print(f"{'─' * 55}")

def is_up(url, path="/health"):
    try:
        r = requests.get(f"{url}{path}", timeout=2)
        return r.status_code == 200
    except:
        return False

def get_chain_length(node_url):
    try:
        r = requests.get(f"{node_url}/sync/length", timeout=2)
        if r.status_code == 200:
            return r.json().get("chain_length", -1)
    except:
        pass
    return -1

def get_chain(node_url):
    try:
        r = requests.get(f"{node_url}/sync/chain", timeout=5)
        if r.status_code == 200:
            return r.json().get("chain", [])
    except:
        pass
    return []

# ── Level 1 — Blockchain node alone ──────────────────────────────────────────

def test_level_1():
    section("LEVEL 1 — Blockchain node alone")

    node_url = NODE_URLS[2]

    # 1.1 Health check
    up = is_up(node_url)
    check(up, "Node 0 is reachable at /health")
    if not up:
        print(f"  {INFO} Start node 0 with: python run_node.py 0")
        return False

    # 1.2 Identity endpoint
    try:
        r = requests.get(f"{node_url}/identity", timeout=2)
        data = r.json()
        has_pubkey = "public_key" in data and len(data["public_key"]) == 128
        check(r.status_code == 200, "/identity returns 200")
        check(has_pubkey, f"/identity has valid public_key (128 hex chars)",
              f"got: {data}")
    except Exception as e:
        check(False, "/identity reachable", str(e))

    # 1.3 Chain length starts at 1 (genesis only)
    length = get_chain_length(node_url)
    check(length >= 1, f"/sync/length returns >= 1 (got {length})")

    # 1.4 Send fake alert directly to /alert
    print(f"\n  {INFO} Sending fake DDoS alert directly to /alert...")
    try:
        r = requests.post(
            f"{node_url}/alert",
            json    = FAKE_ALERT_PAYLOAD,
            timeout = 5,
        )
        data = r.json()
        check(r.status_code == 202,
              f"/alert returns 202 Accepted (got {r.status_code})")
        check("tx_id" in data,
              f"/alert response contains tx_id",
              f"got: {data}")
        check(data.get("alert_type") == "DDoS",
              f"/alert response has correct alert_type (got {data.get('alert_type')})")

        tx_id = data.get("tx_id", "")
        print(f"  {INFO} tx_id = {tx_id[:20]}…")

    except Exception as e:
        check(False, "/alert reachable", str(e))
        return False

    # 1.5 Wait briefly for PBFT (will likely time out with only 1 node
    #     since it can't reach quorum — but block should be in pool)
    print(f"\n  {INFO} Waiting 3s for any consensus activity...")
    time.sleep(3)

    # 1.6 Check chain or pending state
    new_length = get_chain_length(node_url)
    if new_length > length:
        check(True, f"Chain grew: {length} → {new_length} blocks")
        chain = get_chain(node_url)
        if len(chain) > 1:
            last_block = chain[-1]
            check(
                last_block.get("alert_type") == "DDoS",
                f"Last block has alert_type=DDoS "
                f"(got {last_block.get('alert_type')})"
            )
            check(
                last_block.get("severity") == "high",
                f"Last block has severity=high "
                f"(got {last_block.get('severity')})"
            )
            alert = last_block.get("alert", {})
            check(
                "src_ip" in alert.get("features_summary", {}),
                "Block alert contains features_summary with src_ip"
            )
            check(
                "_raw_features" not in last_block,
                "Raw features are NOT stored on-chain (_raw_features absent)"
            )
    else:
        print(f"  {INFO} Chain length unchanged ({new_length}) — "
              f"expected with only 1 node (can't reach 2f+1=3 quorum)")
        print(f"  {INFO} This is correct behaviour — run Level 3 for full consensus")

    return True

# ── Level 2 — ml_server → blockchain node ────────────────────────────────────

def test_level_2():
    section("LEVEL 2 — ml_server → blockchain node")

    ml_url   = ML_URLS[0]
    node_url = NODE_URLS[0]

    # 2.1 ml_server health
    up = is_up(ml_url)
    check(up, f"ml_server reachable at {ml_url}/health")
    if not up:
        print(f"  {INFO} Start with: python ml_server.py --port 8000 "
              f"--node-url http://localhost:5000")
        return False

    # 2.2 /validate endpoint exists (peer IDS validation, no blockchain forward)
    # print(f"\n  {INFO} Testing /validate endpoint (peer IDS validation)...")
    # try:
    #     r = requests.post(
    #         f"{ml_url}/validate",
    #         json    = {"features": FAKE_ALERT_PAYLOAD["features"]},
    #         timeout = 5,
    #     )
    #     check(r.status_code == 200,
    #           f"/validate returns 200 (got {r.status_code})")
    #     result = r.json()
    #     check("signature" in result and "anomaly" in result,
    #           "/validate returns signature and anomaly fields")
    #     print(f"  {INFO} /validate result: "
    #           f"label={result.get('signature',{}).get('label_name','?')} "
    #           f"alert={'YES' if result.get('alert') else 'NO (benign)'}")
    # except Exception as e:
    #     check(False, "/validate reachable", str(e))

    # 2.3 /predict endpoint — should forward to blockchain if alert detected
    length_before = get_chain_length(node_url)
    print(f"\n  {INFO} Sending features to /predict "
          f"(chain length before: {length_before})...")
    try:
        r = requests.post(
            f"{ml_url}/predict",
            json = {
                "features": FAKE_ALERT_PAYLOAD["features"],
                "meta":     FAKE_ALERT_PAYLOAD["meta"],
            },
            timeout = 5,
        )
        check(r.status_code == 200,
              f"/predict returns 200 (got {r.status_code})")
        result = r.json()
        alert = result.get("alert")
        check("signature" in result,
              "/predict returns signature field")
        check("latency_ms" in result,
              f"/predict returns latency_ms "
              f"(got {result.get('latency_ms')}ms)")

        if alert:
            print(f"  {INFO} Alert detected: "
                  f"{alert.get('label_name')} | "
                  f"severity={alert.get('severity')} | "
                  f"fusion={alert.get('fusion')}")
            check(True, "ml_server detected non-benign traffic → forwarding to node")

            # Wait for /alert to be processed
            print(f"  {INFO} Waiting 3s for /alert forwarding...")
            time.sleep(3)

            length_after = get_chain_length(node_url)
            print(f"  {INFO} Chain length after: {length_after}")

            # With only 1 node still won't reach quorum
            # but we can check the node received the alert
            if length_after > length_before:
                check(True, f"Chain grew after /predict alert "
                      f"({length_before} → {length_after})")
            else:
                print(f"  {INFO} Chain didn't grow — expected with 1 node "
                      f"(needs quorum). Run Level 3 with all nodes.")
        else:
            print(f"  {INFO} ml_server classified traffic as BENIGN "
                  f"— no alert forwarded (this may be correct for fake features)")
            check(True, "/predict ran successfully (benign result)")

    except Exception as e:
        check(False, "/predict reachable", str(e))
        return False

    return True

# ── Level 3 — Full PBFT consensus ────────────────────────────────────────────

def test_level_3():
    section("LEVEL 3 — Full PBFT consensus (all 5 nodes)")

    # 3.1 Check all nodes are up
    print(f"  {INFO} Checking all nodes...")
    all_up = True
    for node_id, url in NODE_URLS.items():
        up = is_up(url)
        check(up, f"Node {node_id} reachable ({url})")
        if not up:
            all_up = False

    if not all_up:
        print(f"\n  {INFO} Start missing nodes:")
        for i in range(5):
            print(f"         python run_node.py {i}")
        return False

    # 3.2 Record chain lengths before
    lengths_before = {i: get_chain_length(NODE_URLS[i]) for i in range(5)}
    print(f"\n  {INFO} Chain lengths before: {lengths_before}")

    # 3.3 Send alert to node 0
    print(f"\n  {INFO} Sending fake DDoS alert to node 0...")
    try:
        r = requests.post(
            f"{NODE_URLS[0]}/alert",
            json    = FAKE_ALERT_PAYLOAD,
            timeout = 5,
        )
        check(r.status_code == 202,
              f"Node 0 /alert accepted (got {r.status_code})")
        tx_id = r.json().get("tx_id", "")
        print(f"  {INFO} tx_id = {tx_id[:20]}…")
    except Exception as e:
        check(False, "Node 0 /alert reachable", str(e))
        return False

    # 3.4 Wait for PBFT consensus
    print(f"\n  {INFO} Waiting for PBFT consensus (up to 10s)...")
    consensus_reached = False
    for attempt in range(10):
        time.sleep(1)
        lengths = {i: get_chain_length(NODE_URLS[i]) for i in range(5)}
        grew = all(lengths[i] > lengths_before[i] for i in range(5))
        if grew:
            consensus_reached = True
            print(f"  {INFO} Consensus reached after {attempt+1}s")
            print(f"  {INFO} Chain lengths after: {lengths}")
            break
        print(f"  {INFO} [{attempt+1}s] lengths: {lengths}")

    check(consensus_reached,
          "All 5 nodes grew their chain (consensus reached)",
          "Timeout — check node logs for PBFT errors")

    if not consensus_reached:
        return False

    # 3.5 Verify all nodes have the same block
    print(f"\n  {INFO} Verifying all nodes agree on the same block...")
    chains = {i: get_chain(NODE_URLS[i]) for i in range(5)}

    # All chains must have same length
    chain_lengths = {i: len(c) for i, c in chains.items()}
    check(len(set(chain_lengths.values())) == 1,
          f"All nodes have same chain length: {chain_lengths}")

    # All nodes must agree on the last block hash
    last_hashes = {}
    for i, chain in chains.items():
        if len(chain) > 1:
            last_hashes[i] = chain[-1].get("block_hash", "")
    unique_hashes = set(last_hashes.values())
    check(len(unique_hashes) == 1,
          f"All nodes agree on last block_hash "
          f"({'AGREE' if len(unique_hashes)==1 else 'DISAGREE'})",
          f"Hashes: {last_hashes}")

    # 3.6 Verify block content on node 0
    print(f"\n  {INFO} Verifying committed block contents...")
    if chains[0] and len(chains[0]) > 1:
        last = chains[0][-1]

        check(last.get("alert_type") == "DDoS",
              f"alert_type = DDoS (got {last.get('alert_type')})")

        check(last.get("severity") == "high",
              f"severity = high (got {last.get('severity')})")

        alert = last.get("alert", {})
        fs = alert.get("features_summary", {})
        check("src_ip" in fs,
              f"features_summary has src_ip (got {fs})")
        check(fs.get("src_ip") == "192.168.1.5",
              f"src_ip = 192.168.1.5 (got {fs.get('src_ip')})")

        check("_raw_features" not in last,
              "Raw features NOT stored on-chain ✓")

        det = alert.get("detector_outputs", {})
        check("signature_model" in det and "anomaly_model" in det,
              f"detector_outputs has both models: {det}")

        check(alert.get("signer_address") is not None,
              "Alert has signer_address (origin proof)")

        check(alert.get("signature") is not None,
              "Alert has ECDSA signature (tamper proof)")

    # 3.7 Verify chain integrity on all nodes
    print(f"\n  {INFO} Validating chain integrity on all nodes...")
    for node_id in range(5):
        chain = chains[node_id]
        valid = True
        for i in range(1, len(chain)):
            if chain[i]["previous_hash"] != chain[i-1]["block_hash"]:
                valid = False
                break
        check(valid, f"Node {node_id} chain has unbroken hash links")

    # 3.8 Check flow_features.jsonl was written (off-chain storage)
    print(f"\n  {INFO} Checking off-chain feature storage...")
    try:
        with open("flow_features.jsonl", "r") as f:
            lines = f.readlines()
        check(len(lines) > 0,
              f"flow_features.jsonl has {len(lines)} record(s)")
        if lines:
            last_record = json.loads(lines[-1])
            check("tx_id" in last_record,
                  "Record has tx_id (links to on-chain block)")
            check("features" in last_record,
                  "Record has raw features dict")
            check("block_number" in last_record,
                  f"Record has block_number "
                  f"(= {last_record.get('block_number')})")
    except FileNotFoundError:
        print(f"  {INFO} flow_features.jsonl not found — "
              f"features stored by proposer node only. "
              f"Check the node 0 working directory.")
    except Exception as e:
        check(False, "flow_features.jsonl readable", str(e))

    return True

# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDS → Blockchain pipeline test")
    parser.add_argument("--level", type=int, default=3,
                        choices=[1, 2, 3],
                        help="Test level: 1=node only, 2=+ml_server, 3=+full PBFT")
    args = parser.parse_args()

    print("=" * 55)
    print("  IDS → Blockchain Pipeline Test")
    print("=" * 55)

    if args.level >= 1:
        ok = test_level_1()
        if not ok and args.level > 1:
            print("\nLevel 1 failed — fix before running higher levels")
            sys.exit(1)

    if args.level >= 2:
        ok = test_level_2()
        if not ok and args.level > 2:
            print("\nLevel 2 failed — fix before running Level 3")
            sys.exit(1)

    if args.level >= 3:
        test_level_3()

    print(f"\n{'=' * 55}")
    print("  Done.")
    print(f"{'=' * 55}")


# cd /mnt/f
# cd updated_IEEE_project
# cd updated_blockchain/
# source \venv/bin/activate