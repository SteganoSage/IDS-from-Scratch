import requests
import threading


class PeerClient:
    def __init__(self, peers):
        """
        peers: dict {node_id: base_url}
        """
        self.peers = peers

    # ── Identity / DH ────────────────────────────────────────────────────

    def fetch_identity(self, node_id):
        try:
            r = requests.get(
                f"{self.peers[node_id]}/identity",
                timeout=2
            )
            if r.status_code == 200:
                return r.json()
        except requests.RequestException:
            pass
        return None

    def send_dh_key(self, node_id, payload):
        """
        payload should include:
        {
            "node_id":       int,
            "dh_public_key": hex,
            "public_key":    hex   ← identity key included so peer can
                                     register us in one round trip
        }
        Response also includes "public_key" of the peer.
        """
        try:
            r = requests.post(
                f"{self.peers[node_id]}/dh",
                json=payload,
                timeout=2
            )
            if r.status_code == 200:
                return r.json()
        except requests.RequestException:
            pass
        return None

    # ── PBFT messaging ───────────────────────────────────────────────────

    def send(self, node_id, msg):
        try:
            requests.post(
                f"{self.peers[node_id]}/pbft",
                json=msg,
                timeout=2
            )
        except requests.RequestException:
            pass

    def broadcast(self, msg):
        """
        Send the same msg to all peers simultaneously.
        Used when every peer gets an identical payload.
        """
        threads = [
            threading.Thread(target=self.send, args=(node_id, msg), daemon=True)
            for node_id in self.peers
        ]
        for t in threads: t.start()
        for t in threads: t.join()

    def broadcast_many(self, wire_msgs: dict):
        """
        Send a different pre-encrypted payload to each peer simultaneously.
        wire_msgs: { node_id: wire_msg_dict }

        Used by Node.Send_To_All_Nodes where each peer gets a message
        encrypted with its own session key.

        All sends fire at the same time so no peer receives a downstream
        message (e.g. PREPARE) before it has received PRE-PREPARE.
        """
        threads = [
            threading.Thread(target=self.send, args=(node_id, wire_msg), daemon=True)
            for node_id, wire_msg in wire_msgs.items()
        ]
        for t in threads: t.start()
        for t in threads: t.join()

    # ── Chain sync ───────────────────────────────────────────────────────

    def fetch_chain_length(self, node_id) -> int:
        """
        Ask a peer for its current chain length.
        Returns the length as an int, or -1 if the peer is unreachable.
        Called first so we only download the full chain from the best peer.
        """
        try:
            r = requests.get(
                f"{self.peers[node_id]}/sync/length",
                timeout=2
            )
            if r.status_code == 200:
                return r.json().get("chain_length", -1)
        except requests.RequestException:
            pass
        return -1

    def fetch_chain(self, node_id) -> list:
        """
        Download the full chain from a peer.
        Returns a list of block dicts, or empty list if unreachable.
        """
        try:
            r = requests.get(
                f"{self.peers[node_id]}/sync/chain",
                timeout=10          # larger timeout — chain can be big
            )
            if r.status_code == 200:
                return r.json().get("chain", [])
        except requests.RequestException:
            pass
        return []