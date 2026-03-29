from ecdsa import VerifyingKey, SECP256k1
import json
import threading
import time
import queue
from collections import defaultdict

from .PeerClient import PeerClient
from .NodeApi import NodeAPI
from module2.PBFT import PBFT_Node
from module1.CryptoUtils import CryptoUtils
from module1.BlockChain import Block, PendingBlockPool


class Node(PBFT_Node, CryptoUtils):

    def __init__(self, node_id, port, peers, total_nodes, F, blockchain,
                 ml_server_url: str = None, db_path: str = None):
        ids_model = self._make_ids_model(ml_server_url) if ml_server_url else None

        pool = PendingBlockPool()
        super().__init__(node_id, total_nodes, F, pending_pool=pool,
                         ids_model=ids_model)

        self.node_id     = node_id
        self.blockchain  = blockchain
        self.peer_client = PeerClient(peers)
        self.port        = port
        self.api         = NodeAPI(self)

        # ── Database ─────────────────────────────────────────────────────
        # Each node owns its own SQLite file — decentralized persistence.
        # No shared DB — consistent with blockchain's decentralization principle.
        from module4.db import NodeDB
        db_file  = db_path or f"data/node{node_id}.db"
        self.db  = NodeDB(db_file)

        # ── Crypto ───────────────────────────────────────────────────────
        self.private_key, self.public_key = self.generate_keypair()
        self.node_address  = self.public_key_to_address(self.public_key)
        self.dh_private_key, self.dh_public_key = self.generate_dh_keypair()

        self.peer_public_keys: dict = {}
        self.peer_dh_keys:     dict = {}
        self.session_keys:     dict = {}
        self.is_secure = False

        # ── Validator reputation ──────────────────────────────────────────
        self.alert_votes:  dict = defaultdict(dict)
        self.node_stats:   dict = defaultdict(lambda: {"correct": 0, "wrong": 0})
        self.alert_counter   = 0
        self.WRITE_THRESHOLD = 5

        self.stats_queue: queue.Queue = queue.Queue()
        threading.Thread(target=self._stats_writer, daemon=True).start()

        # tx_id -> raw_features (cached until block commits, then written to DB)
        self._pending_features: dict = {}

        # Set of alert tx_ids currently being processed in PBFT pool.
        # Prevents creating a second block for the same alert if it arrives
        # again before the first block commits.
        self._in_flight_alerts: set = set()

        # block_hash -> propose timestamp (float)
        # Used by the watchdog to detect blocks stuck without quorum.
        self._block_propose_time: dict = {}

        # Watchdog: checks every 5s for blocks that haven't committed.
        # If a block hasn't committed within POOL_TIMEOUT seconds, it is
        # dropped and its alert is discarded — either IDS rejection or
        # quorum failure. Either way the alert is gone; the IDS will
        # generate a fresh alert on the next detection cycle if the
        # threat is still active.
        self.POOL_TIMEOUT = 5
        threading.Thread(target=self._pool_watchdog, daemon=True).start()

    # ── IDS model callable ────────────────────────────────────────────────

    @staticmethod
    def _make_ids_model(ml_server_url: str):
        """
        Returns a callable used by PBFT_Node.Is_Valid_Alert().
        POSTs raw features to /validate (NOT /predict — avoids infinite loop).
        Returns True  → non-benign → send PREPARE
        Returns False → benign     → reject PRE-PREPARE
        Returns True  → unreachable → fail open
        """
        import requests as _requests

        def ids_model(block_dict: dict) -> bool:
            raw_features = block_dict.get("_raw_features")
            if not raw_features:
                return True   # no features to validate — fail open

            try:
                resp = _requests.post(
                    f"{ml_server_url}/validate",
                    json    = {"features": raw_features},
                    timeout = 3,
                )
                if resp.status_code != 200:
                    return True   # ml_server error — fail open
                return resp.json().get("alert") is not None

            except _requests.RequestException:
                return True   # unreachable — fail open

        return ids_model

    # ── Identity / DH ────────────────────────────────────────────────────

    def get_identity(self) -> dict:
        return {
            "node_id":    self.node_id,
            "public_key": self.public_key.to_string().hex(),
        }

    def get_dh_public(self) -> dict:
        return {
            "node_id":       self.node_id,
            "dh_public_key": self.dh_public_key.to_string().hex(),
        }

    def register_peer_identity(self, peer_id, pubkey_hex: str) -> None:
        self.peer_public_keys[peer_id] = VerifyingKey.from_string(
            bytes.fromhex(pubkey_hex), curve=SECP256k1
        )

    def register_peer_dh(self, peer_id, dh_pub_hex: str) -> None:
        peer_dh_key = VerifyingKey.from_string(
            bytes.fromhex(dh_pub_hex), curve=SECP256k1
        )
        self.peer_dh_keys[peer_id] = peer_dh_key
        shared_secret = self.derive_shared_secret(self.dh_private_key, peer_dh_key)
        self.session_keys[peer_id] = self.derive_session_key(shared_secret)

    # ── Alert proposal entry point ────────────────────────────────────────

    def submit_alert(self, alert, raw_features: dict = None) -> None:
        """
        Entry point from IDS pipeline.
        Queues the alert, creates a block, and kicks off PBFT consensus.
        raw_features are kept off-chain and written to DB after commit.
        """
        if not self.is_secure:
            print(f"[Node {self.node_id}] Not yet secure — alert dropped")
            return

        # Cache raw features — written to DB after block commits
        if raw_features and alert.tx_id:
            self._pending_features[alert.tx_id] = raw_features

        self.blockchain.add_alert(alert)
        print(f"[Node {self.node_id}] Alert queued tx={alert.tx_id[:12]}…")

        # Don't create a block if this alert is already being processed
        if alert.tx_id in self._in_flight_alerts:
            print(f"[Node {self.node_id}] Alert already in flight — skipping")
            return

        block = self.blockchain.create_block(proposer_id=str(self.node_id))
        if block is None:
            print(f"[Node {self.node_id}] create_block() returned None")
            return

        # Mark alert as in-flight — cleared when block commits or fails
        if block.alert:
            self._in_flight_alerts.add(block.alert.tx_id)

        # Check if we already have a block in the pool for this alert
        existing = self.pending_pool.get_top()
        if existing:
            existing_alert = existing.get("alert") or {}
            if existing_alert.get("tx_id") == (block.alert.tx_id if block.alert else None):
                print(f"[Node {self.node_id}] Block for this alert already "
                      f"in pool — skipping propose")
                return

        # Don't let the pool grow unbounded
        MAX_POOL_SIZE = 10
        if self.pending_pool.size() >= MAX_POOL_SIZE:
            print(f"[Node {self.node_id}] Pool full ({MAX_POOL_SIZE} blocks) "
                  f"— alert dropped, will retry on next detection")
            self._in_flight_alerts.discard(alert.tx_id)
            self.blockchain.pending_alerts = [
                a for a in self.blockchain.pending_alerts
                if a.tx_id != alert.tx_id
            ]
            return

        print(f"[Node {self.node_id}] Block #{block.block_number} created "
              f"hash={block.block_hash[:12]}…")

        block_dict = block.to_dict()

        # Record when this block was proposed for watchdog timeout tracking
        self._block_propose_time[block.block_hash] = time.time()

        # Attach raw features for peer IDS validation
        if raw_features:
            block_dict["_raw_features"] = raw_features

        print(f"[Node {self.node_id}] Calling propose_block…")
        self.propose_block(block_dict)

    # ── Networking ───────────────────────────────────────────────────────

    def Send_To_All_Nodes(self, msg: dict) -> None:
        """
        Encrypt msg per-peer and broadcast all simultaneously.
        Parallel sends prevent the race condition where early receivers
        send PREPARE before later receivers have seen PRE-PREPARE.
        """
        if not self.is_secure:
            return

        plaintext = json.dumps(msg).encode("utf-8")

        wire_msgs = {}
        for peer_id in self.peer_client.peers:
            key = self.session_keys.get(peer_id)
            if not key:
                continue
            enc = self.encrypt_message(key, plaintext)
            sig = self.sign_data(enc["ciphertext"], self.private_key)
            wire_msgs[peer_id] = {
                "sender":    self.node_id,
                "enc":       enc,
                "signature": sig.hex(),
            }

        print(f"[Node {self.node_id}] → {msg.get('Type')} "
              f"to {list(wire_msgs.keys())} "
              f"bh={str(msg.get('Block_Hash',''))[:12]}…")

        self.peer_client.broadcast_many(wire_msgs)

    def On_Message_Received_From_Network(self, wire_msg: dict) -> None:
        """
        Called by NodeApi /pbft endpoint for every inbound PBFT message.
        Verifies signature, decrypts, then dispatches to receive_message().
        """
        sender    = wire_msg.get("sender")
        enc       = wire_msg.get("enc")
        signature = bytes.fromhex(wire_msg.get("signature", ""))

        if sender not in self.session_keys:
            print(f"[Node {self.node_id}] Unknown sender {sender} — dropped")
            return

        peer_pub = self.peer_public_keys.get(sender)
        if not peer_pub:
            print(f"[Node {self.node_id}] No pubkey for {sender} — dropped")
            return

        if not self.verify_signature(enc["ciphertext"], signature, peer_pub):
            print(f"[Node {self.node_id}] Bad signature from {sender} — dropped")
            return

        key       = self.session_keys[sender]
        plaintext = self.decrypt_message(key, enc)
        pbft_msg  = json.loads(plaintext.decode("utf-8"))

        print(f"[Node {self.node_id}] ← {pbft_msg.get('Type')} "
              f"from {sender} "
              f"bh={str(pbft_msg.get('Block_Hash',''))[:12]}…")

        # Track PREPARE votes for reputation system
        if pbft_msg.get("Type") == "PREPARE":
            bh    = pbft_msg.get("Block_Hash")
            voter = pbft_msg.get("Sender")
            if bh and voter is not None:
                self.alert_votes[bh][voter] = True

        self.receive_message(pbft_msg)

    # ── Consensus callback (PBFT hook) ────────────────────────────────────

    def On_Block_Committed(self, block_hash: str) -> None:
        """
        Called by PBFT._on_commit() when 2f+1 COMMIT votes are collected.
        Reconstructs block, appends to chain, stores features, advances pool.
        """
        block_dict = self.Block_Pool.get(block_hash)
        if not block_dict:
            print(f"[Node {self.node_id}] DECIDED but block not in pool "
                  f"{block_hash[:12]}… — ignoring")
            return

        block   = Block.from_dict(block_dict)
        success = self.blockchain.add_block(block)

        if success:
            print(f"[Node {self.node_id}] ✓ Block {block.block_number} committed "
                  f"| {block.alert_type} | {block.severity}")

            # Persist block to DB — survives node restarts
            self.db.save_block(block)

            # Write raw features to off-chain DB after confirmed commit
            if block.alert and block.alert.tx_id:
                raw_features = self._pending_features.pop(block.alert.tx_id, None)
                if raw_features:
                    self._store_features(
                        tx_id        = block.alert.tx_id,
                        block_number = block.block_number,
                        features     = raw_features,
                    )
        else:
            print(f"[Node {self.node_id}] ✗ add_block failed "
                  f"bh={block_hash[:12]}…")

        # Remove from pool and permanently blacklist
        self.pending_pool.remove(block_hash)
        self.pending_pool.mark_committed(block_hash)

        # Clear in-flight and watchdog tracking
        if block.alert and block.alert.tx_id:
            self._in_flight_alerts.discard(block.alert.tx_id)
        self._block_propose_time.pop(block_hash, None)
        self._proposed_blocks.discard(block_hash)

        # Reputation update
        votes = self.alert_votes.get(block_hash, {})
        if votes:
            true_count = sum(1 for v in votes.values() if v)
            majority   = true_count >= (len(votes) - true_count)
            for nid, vote in votes.items():
                key = "correct" if vote == majority else "wrong"
                self.node_stats[nid][key] += 1
            self.alert_counter += 1
            if self.alert_counter >= self.WRITE_THRESHOLD:
                self.stats_queue.put(dict(self.node_stats))
                self.alert_counter = 0

        # Advance to next pool candidate
        self.try_advance()

    # ── Pool watchdog ─────────────────────────────────────────────────────

    def _pool_watchdog(self) -> None:
        """
        Checks every 5s for blocks stuck in pool past POOL_TIMEOUT.
        All timed-out blocks are dropped — no re-queuing.
        """
        while True:
            time.sleep(5)

            if not self.is_secure:
                continue

            now = time.time()
            timed_out = [
                bh for bh, t in list(self._block_propose_time.items())
                if now - t > self.POOL_TIMEOUT
            ]

            for bh in timed_out:
                prepare_votes = len(self.Prepare.get(bh, set()))
                print(f"[Node {self.node_id}] ⚠ Block {bh[:12]}… timed out "
                      f"({prepare_votes} PREPARE votes) — dropping")
                self._drop_block(bh, self.Block_Pool.get(bh))

    def _drop_block(self, block_hash: str, block_dict: dict) -> None:
        """
        Remove a stalled block and clean up all associated state.
        Alert is discarded — not re-queued.
        """
        # Remove from pool (keeps hash in seen_hashes to prevent replay)
        self.pending_pool.reject(block_hash)

        # Clean up PBFT vote state
        self.Prepare.pop(block_hash, None)
        self.Commit.pop(block_hash, None)
        self._prepared.discard(block_hash)
        self._committed_sent.discard(block_hash)
        self._block_propose_time.pop(block_hash, None)
        self._proposed_blocks.discard(block_hash)

        # Clear in-flight and features cache
        alert_tx_id = None
        if block_dict:
            alert_tx_id = (block_dict.get("alert") or {}).get("tx_id")
        if alert_tx_id:
            self._in_flight_alerts.discard(alert_tx_id)
            self._pending_features.pop(alert_tx_id, None)
            # Remove from blockchain pending queue so it isn't proposed again
            self.blockchain.pending_alerts = [
                a for a in self.blockchain.pending_alerts
                if a.tx_id != alert_tx_id
            ]
            print(f"[Node {self.node_id}] Alert {alert_tx_id[:12]}… dropped")

        # Start consensus on next pool candidate
        self.try_advance()

    def _store_features(self, tx_id: str, block_number: int,
                        features: dict) -> None:
        """
        Write raw CIC-IDS flow features to off-chain SQLite DB.
        Only called after block is confirmed on chain.
        Linked back to on-chain block via tx_id.
        """
        success = self.db.save_features(
            tx_id        = tx_id,
            block_number = block_number,
            node_id      = str(self.node_id),
            features     = features,
        )
        if success:
            print(f"[Node {self.node_id}] 💾 Features stored tx={tx_id[:12]}…")
        else:
            print(f"[Node {self.node_id}] ✗ Feature storage failed tx={tx_id[:12]}…")

    # ── Background stats writer ───────────────────────────────────────────

    def _stats_writer(self) -> None:
        while True:
            data = self.stats_queue.get()
            try:
                with open("validator_stats.json", "w") as f:
                    json.dump(data, f, indent=2)
                print(f"[Node {self.node_id}] 📁 Validator stats written")
            except OSError as e:
                print(f"[Node {self.node_id}] Stats write failed: {e}")

    # ── Chain sync ───────────────────────────────────────────────────────

    def _sync_chain(self) -> None:
        """
        Before joining consensus, download the longest valid chain from peers.
        Runs in parallel — asks all peers for length, downloads from the best.

        Note: replace_chain() (called here via blockchain.replace_chain) expects
        the full chain including genesis as the first element.  The /sync/chain
        endpoint on peers provides this automatically because it serialises
        self.blockchain.chain which always starts with genesis.
        """
        print(f"[Node {self.node_id}] Syncing chain from peers...")

        lengths = {}
        lock    = threading.Lock()

        def fetch_length(peer_id):
            length = self.peer_client.fetch_chain_length(peer_id)
            with lock:
                lengths[peer_id] = length

        threads = [
            threading.Thread(target=fetch_length, args=(pid,), daemon=True)
            for pid in self.peer_client.peers
        ]
        for t in threads: t.start()
        for t in threads: t.join()

        if not lengths:
            print(f"[Node {self.node_id}] No peers reachable — starting fresh")
            return

        best_peer   = None
        best_length = len(self.blockchain.chain)

        for peer_id, length in lengths.items():
            if length < 0:
                continue
            if length > best_length:
                best_length = length
                best_peer   = peer_id
            elif length == best_length and best_peer is not None:
                if peer_id < best_peer:
                    best_peer = peer_id

        if best_peer is None:
            print(f"[Node {self.node_id}] Already up to date "
                  f"(length {len(self.blockchain.chain)})")
            return

        print(f"[Node {self.node_id}] Downloading chain from peer {best_peer} "
              f"(length {best_length})...")

        block_dicts = self.peer_client.fetch_chain(best_peer)
        if not block_dicts:
            print(f"[Node {self.node_id}] Download failed — starting fresh")
            return

        # block_dicts from a peer includes genesis as element 0 because
        # NodeAPI.sync_chain serialises the full self.blockchain.chain.
        # replace_chain() handles the full-hash verification for untrusted
        # peer-sourced blocks.
        success = self.blockchain.replace_chain(block_dicts)
        if success:
            print(f"[Node {self.node_id}] ✓ Chain synced — "
                  f"at block {len(self.blockchain.chain) - 1}")
        else:
            print(f"[Node {self.node_id}] ✗ Sync rejected — invalid chain "
                  f"from peer {best_peer}")

    # ── Startup ───────────────────────────────────────────────────────────

    def start(self) -> None:
        # Start peer handshake in background so Flask can start immediately.
        threading.Thread(target=self._connect_peers, daemon=True).start()

        # Start Flask — this blocks, so it must be last
        self.api.start(self.port)

    def _load_chain_from_db(self) -> None:
        """
        Restore chain from local SQLite DB on startup.

        Called before _sync_chain() so we only download missed blocks
        from peers rather than the full chain from genesis.

        Key design decisions
        --------------------
        1. Calls db.verify_chain_integrity() first — a fast raw-SQL linkage
           check that detects DB corruption without constructing any Block
           objects.  If this fails, we skip the load and start from genesis.

        2. Calls blockchain.load_chain_from_db() (NOT replace_chain()).
           load_chain_from_db() is the trusted DB path:
             - Does NOT enforce "must be longer than current chain"
               (replace_chain() would reject a 1-block DB because the chain
               already has genesis, making lengths equal)
             - Does NOT recompute hashes — trusts the stored block_hash
             - Only validates linkage (previous_hash chain)
             - Stitches DB blocks onto the existing in-memory genesis;
               genesis is never stored in the DB so it is never in block_dicts

        3. After load, _sync_chain() will download any blocks missed while
           this node was offline.  replace_chain() (used by _sync_chain) DOES
           recompute hashes because peer-sourced blocks are untrusted.
        """
        # Step 1: fast integrity check on raw DB rows
        if not self.db.verify_chain_integrity():
            print(
                f"[Node {self.node_id}] DB integrity check failed — "
                f"skipping DB load, starting from genesis"
            )
            return

        # Step 2: load block dicts (block_number >= 1; genesis excluded)
        block_dicts = self.db.load_all_blocks()
        if not block_dicts:
            print(f"[Node {self.node_id}] No blocks in DB — starting from genesis")
            return

        # Step 3: restore via the trusted DB path (no hash recompute)
        success = self.blockchain.load_chain_from_db(block_dicts)
        if success:
            print(
                f"[Node {self.node_id}] ✓ Chain restored from DB — "
                f"at block {len(self.blockchain.chain) - 1}"
            )
        else:
            print(
                f"[Node {self.node_id}] ✗ DB chain invalid — "
                f"starting from genesis"
            )

    def _connect_peers(self) -> None:
        """
        Runs in background after Flask starts.
        Single pass — try each peer once.
        Late joiners are handled automatically via reverse DH in /dh endpoint.
        """
        # Wait for Flask to bind port before contacting peers
        time.sleep(2)

        print(f"[Node {self.node_id}] Connecting to peers...")

        for peer_id in self.peer_client.peers:
            payload = {
                "node_id":       self.node_id,
                "dh_public_key": self.dh_public_key.to_string().hex(),
                "public_key":    self.public_key.to_string().hex(),
            }
            resp = self.peer_client.send_dh_key(peer_id, payload)
            if resp:
                self.register_peer_dh(resp["node_id"], resp["dh_public_key"])
                if "public_key" in resp:
                    self.register_peer_identity(
                        resp["node_id"], resp["public_key"]
                    )
                print(f"[Node {self.node_id}] ✓ Connected to peer {peer_id}")
            else:
                print(f"[Node {self.node_id}] Peer {peer_id} not up yet "
                      f"— will connect when they join")

        # 1. Restore chain from local DB (fast, no network, no hash recompute)
        self._load_chain_from_db()

        # 2. Sync with peers to get any blocks missed while offline
        #    (uses replace_chain which does full hash verification)
        self._sync_chain()

        # Ready to participate in consensus
        self.is_secure = True
        print(
            f"[Node {self.node_id}] ✓ Secure — "
            f"{len(self.session_keys)} peers | "
            f"chain at block {len(self.blockchain.chain) - 1}"
        )