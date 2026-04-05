# module3/config.py — bridge network version
#
# In Docker bridge network, container names act as hostnames.
# Docker DNS resolves node0, node1 etc. automatically.
#
# All blockchain nodes run on port 5000 INSIDE their container.
# PBFT peers communicate via http://nodeX:5000
#
# Falls back to original hardcoded localhost config for local dev.

import os


def get_config(node_id: int) -> dict:

    # ── Docker bridge network path ─────────────────────────────────────────
    port_env = os.getenv("BLOCKCHAIN_PORT")
    if port_env:
        port  = int(port_env)
        peers = {}
        for i in range(5):
            if i == node_id:
                continue
            # Docker DNS resolves container names automatically
            peers[i] = f"http://node{i}:5000"
        return {"port": port, "peers": peers}

    # ── Local dev fallback: original hardcoded config ──────────────────────
    configs = {
        0: {
            "port": 5000,
            "peers": {
                1: "http://localhost:5001",
                2: "http://localhost:5002",
                3: "http://localhost:5003",
                4: "http://localhost:5004"
            }
        },
        1: {
            "port": 5001,
            "peers": {
                0: "http://localhost:5000",
                2: "http://localhost:5002",
                3: "http://localhost:5003",
                4: "http://localhost:5004"
            }
        },
        2: {
            "port": 5002,
            "peers": {
                0: "http://localhost:5000",
                1: "http://localhost:5001",
                3: "http://localhost:5003",
                4: "http://localhost:5004"
            }
        },
        3: {
            "port": 5003,
            "peers": {
                0: "http://localhost:5000",
                1: "http://localhost:5001",
                2: "http://localhost:5002",
                4: "http://localhost:5004"
            }
        },
        4: {
            "port": 5004,
            "peers": {
                0: "http://localhost:5000",
                1: "http://localhost:5001",
                2: "http://localhost:5002",
                3: "http://localhost:5003"
            }
        }
    }
    return configs[node_id]