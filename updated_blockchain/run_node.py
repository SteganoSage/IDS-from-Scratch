# run_node.py
import sys
import os
from module3.Node import Node
from module3.config import get_config
from module1.BlockChain import IDSBlockchain

print(">>> run_node.py started")

node_id = int(sys.argv[1])
config  = get_config(node_id)

total_nodes = len(config["peers"]) + 1

blockchain = IDSBlockchain()

ML_SERVER_PORT_BASE = 8000
ml_server_url = f"http://localhost:{ML_SERVER_PORT_BASE + node_id}"

# Each node gets its own SQLite DB file in the data/ directory.
# In Docker, this maps to a volume mount so data survives restarts.
db_path = f"database/node{node_id}.db"
os.makedirs("database", exist_ok=True)

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