# module3/config.py
def get_config(node_id):
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
        4:{
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



# wsl
# cd /mnt/d
# cd IEEE-Project/
# cd sample-blockchain-from\ scratch/
# cd Testing/
# source venv/bin/activate