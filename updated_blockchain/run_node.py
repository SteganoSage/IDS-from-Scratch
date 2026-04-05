# run_node.py — container-aware version
#
# Changes from original:
#   1. NODE_ID read from env var (Docker) with sys.argv fallback (local dev)
#   2. ml_server_url always http://127.0.0.1:8000 in Docker (same container)
#      Falls back to original port-offset behaviour for local dev
#   3. Everything else unchanged

import sys
import os
from module3.Node import Node
from module3.config import get_config
from module1.BlockChain import IDSBlockchain

print(">>> run_node.py started")

# ── Node ID ────────────────────────────────────────────────────────────────
# Docker  : NODE_ID env var set by docker-compose
# Local   : python run_node.py 0
node_id_env = os.getenv("NODE_ID")
if node_id_env is not None:
    node_id = int(node_id_env)
elif len(sys.argv) > 1:
    node_id = int(sys.argv[1])
else:
    raise ValueError(
        "NODE_ID not set. Either set NODE_ID env var "
        "or pass as argument: python run_node.py 0"
    )

print(f">>> Node ID: {node_id}")

config      = get_config(node_id)
total_nodes = len(config["peers"]) + 1
blockchain  = IDSBlockchain()

# ── ML server URL ──────────────────────────────────────────────────────────
# Docker : all 3 processes share the same container — ML server is always
#          on loopback port 8000 regardless of node id
# Local  : original port-offset behaviour (8000, 8001, 8002...)
ml_server_url = os.getenv("ML_SERVER_URL") or \
                f"http://localhost:{8000 + node_id}"

print(f">>> ML server URL : {ml_server_url}")
print(f">>> Blockchain port: {config['port']}")
print(f">>> Peers         : {config['peers']}")

# ── DB path ────────────────────────────────────────────────────────────────
db_path = f"database/node{node_id}.db"
os.makedirs("database", exist_ok=True)

# ── Start node ─────────────────────────────────────────────────────────────
node = Node(
    node_id       = node_id,
    port          = config["port"],
    peers         = config["peers"],
    total_nodes   = total_nodes,
    F             = 1,
    blockchain    = blockchain,
    ml_server_url = ml_server_url,
    db_path       = db_path,
)

node.start()