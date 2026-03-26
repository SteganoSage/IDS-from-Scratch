# run_node.py
import sys
from module3.Node import Node
from module3.config import get_config
from module1.BlockChain import IDSBlockchain

print(">>> run_node.py started")

node_id = int(sys.argv[1])
config  = get_config(node_id)

total_nodes = len(config["peers"]) + 1

blockchain = IDSBlockchain()

# Each node's ml_server runs on a fixed port offset from the node port.
# e.g. node 0 blockchain = 5000, ml_server = 8000
#      node 1 blockchain = 5001, ml_server = 8001
# Adjust ML_SERVER_PORT_BASE to match your actual ml_server ports.
ML_SERVER_PORT_BASE = 8000
ml_server_url = f"http://localhost:{ML_SERVER_PORT_BASE + node_id}"

node = Node(
    node_id        = node_id,
    port           = config["port"],
    peers          = config["peers"],
    total_nodes    = total_nodes,
    F              = 1,
    blockchain     = blockchain,
    ml_server_url  = ml_server_url,
)

node.start()