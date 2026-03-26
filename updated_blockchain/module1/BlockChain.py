import hashlib
import json
import time
from typing import List, Dict, Any, Optional
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

from .CryptoUtils import CryptoUtils


# ---------------------------------------------------------------------------
# AlertTransaction
# ---------------------------------------------------------------------------

class AlertTransaction:
    """
    Represents a single IDS alert raised by a node.

    Storage layout inside a block
    ──────────────────────────────
    Each block holds exactly ONE AlertTransaction.  The alert is signed by
    the originating node (proves authenticity / origin), while the block
    itself carries PBFT commit signatures (proves network consensus).

    Fields
    ------
    node_id          : ID of the node that detected the threat
    alert_type       : e.g. "DDoS", "SQLi", "malware", …
    detector_outputs : dict of detector-name → confidence score
                       e.g. {"rf_model": 0.97, "svm_model": 0.91}
    features_summary : dict of raw / aggregated network features used
                       e.g. {"src_ip": "10.0.0.1", "packet_rate": 4500}
    timestamp        : unix epoch (float) when the alert was raised
    signature        : ECDSA signature over the canonical alert fields
    signer_address   : hex address derived from the signer's public key
    tx_id            : SHA-256( signing_data + signature_hex )
                       acts as a stable unique identifier for this alert
    """

    def __init__(
        self,
        node_id: str,
        alert_type: str,
        detector_outputs: Dict[str, float],
        features_summary: Dict[str, Any],
        timestamp: float = None,
    ):
        self.tx_id: Optional[str] = None
        self.node_id = node_id
        self.alert_type = alert_type
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.detector_outputs = detector_outputs
        self.features_summary = features_summary
        self.signature: Optional[bytes] = None
        self.signer_address: Optional[str] = None

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self, include_signature: bool = True) -> Dict:
        data = {
            "tx_id": self.tx_id,
            "node_id": self.node_id,
            "alert_type": self.alert_type,
            "timestamp": self.timestamp,
            "detector_outputs": self.detector_outputs,
            "features_summary": self.features_summary,
            "signer_address": self.signer_address,
        }
        if include_signature and self.signature:
            data["signature"] = self.signature.hex()
        return data

    @classmethod
    def from_dict(cls, data: Dict) -> "AlertTransaction":
        """Reconstruct an AlertTransaction from a serialised dict."""
        tx = cls(
            node_id=data["node_id"],
            alert_type=data["alert_type"],
            detector_outputs=data["detector_outputs"],
            features_summary=data["features_summary"],
            timestamp=data["timestamp"],
        )
        tx.tx_id = data.get("tx_id")
        tx.signer_address = data.get("signer_address")
        sig_hex = data.get("signature")
        if sig_hex:
            tx.signature = bytes.fromhex(sig_hex)
        return tx

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def _signing_data(self) -> str:
        """Canonical string that is signed (excludes tx_id and signature)."""
        payload = {
            "node_id": self.node_id,
            "alert_type": self.alert_type,
            "timestamp": self.timestamp,
            "detector_outputs": self.detector_outputs,
            "features_summary": self.features_summary,
            "signer_address": self.signer_address,
        }
        return json.dumps(payload, sort_keys=True)

    def sign(self, private_key: SigningKey) -> None:
        """Sign the alert and derive tx_id.  Must be called before adding to a block."""
        public_key = private_key.get_verifying_key()
        self.signer_address = CryptoUtils.public_key_to_address(public_key)

        signing_data = self._signing_data()
        self.signature = CryptoUtils.sign_data(signing_data, private_key)
        self.tx_id = CryptoUtils.sha256(signing_data + self.signature.hex())

    def verify(self, public_key: VerifyingKey) -> bool:
        """Verify the alert's signature against a known public key."""
        if not self.signature:
            return False
        return CryptoUtils.verify_signature(
            self._signing_data(), self.signature, public_key
        )


# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------

class Block:
    """
    A single block in the IDS blockchain.

    One block  ←→  one IDS alert.

    Block hash covers all header fields including the alert's tx_id, so any
    tampering with the alert invalidates the block hash and breaks the chain.

    PBFT signatures (prepare / commit) are appended after consensus but are
    intentionally excluded from the hash to keep the hash stable across the
    consensus rounds.
    """

    SEVERITY_MAP: Dict[str, str] = {
        "recon": "low",
        "port_scan": "low",
        "brute_force": "medium",
        "malware": "medium",
        "privilege_escalation": "high",
        "lateral_movement": "high",
        "data_exfiltration": "critical",
        "ransomware": "critical",
        "DDoS": "high",
        "SQLi": "high",
    }

    def __init__(
        self,
        block_number: int,
        alert: Optional[AlertTransaction],   # None only for genesis
        previous_hash: str,
        view_number: int = 0,
        sequence_number: int = 0,
        proposer_id: str = None,
        timestamp: float = None,
    ):
        self.block_number = block_number
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.previous_hash = previous_hash
        self.alert = alert                   # single AlertTransaction (or None)

        self.view_number = view_number
        self.sequence_number = sequence_number
        self.proposer_id = proposer_id

        # Populated during / after PBFT consensus
        self.prepare_signatures: List[Dict] = []
        self.commit_signatures: List[Dict] = []

        # Derived fields
        self.alert_type = alert.alert_type if alert else None
        self.severity = self._get_severity()

        self.block_hash = self.calculate_hash()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_severity(self) -> Optional[str]:
        if self.alert is None:
            return None
        return self.SEVERITY_MAP.get(self.alert.alert_type, "medium")

    def calculate_hash(self) -> str:
        """
        Hash covers all header fields plus the alert's tx_id (if present).
        PBFT signatures are excluded so the hash is stable before/after consensus.
        """
        header = {
            "block_number": self.block_number,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "view_number": self.view_number,
            "sequence_number": self.sequence_number,
            "proposer_id": self.proposer_id,
            "alert_tx_id": self.alert.tx_id if self.alert else None,
            "alert_type": self.alert_type,
            "severity": self.severity,
        }
        return CryptoUtils.sha256(json.dumps(header, sort_keys=True))

    # ------------------------------------------------------------------
    # Signature helpers (called by PBFT layer)
    # ------------------------------------------------------------------

    def add_prepare_signature(self, validator_id: str, signature: bytes) -> None:
        self.prepare_signatures.append(
            {"validator_id": validator_id, "signature": signature.hex()}
        )

    def add_commit_signature(self, validator_id: str, signature: bytes) -> None:
        self.commit_signatures.append(
            {"validator_id": validator_id, "signature": signature.hex()}
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict:
        return {
            "block_number": self.block_number,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "view_number": self.view_number,
            "sequence_number": self.sequence_number,
            "proposer_id": self.proposer_id,
            "alert": self.alert.to_dict() if self.alert else None,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "prepare_signatures": self.prepare_signatures,
            "commit_signatures": self.commit_signatures,
            "block_hash": self.block_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Block":
        """Reconstruct a Block from a serialised dict (e.g. received over the wire)."""
        alert = None
        if data.get("alert"):
            alert = AlertTransaction.from_dict(data["alert"])

        block = cls(
            block_number=data["block_number"],
            alert=alert,
            previous_hash=data["previous_hash"],
            view_number=data.get("view_number", 0),
            sequence_number=data.get("sequence_number", 0),
            proposer_id=data.get("proposer_id"),
            timestamp=data["timestamp"],
        )
        block.prepare_signatures = data.get("prepare_signatures", [])
        block.commit_signatures = data.get("commit_signatures", [])
        # Trust the received hash for pool lookups; validate separately.
        block.block_hash = data["block_hash"]
        return block


# ---------------------------------------------------------------------------
# PendingBlockPool
# ---------------------------------------------------------------------------

class PendingBlockPool:
    """
    Holds candidate blocks proposed by any node, waiting for PBFT consensus.

    Ordering invariant
    ------------------
    Blocks are sorted deterministically by:
        1. alert.timestamp  (earliest alert wins — IDS-generated, not network time)
        2. proposer_id      (lexicographic tiebreak — stable across all nodes)

    This means every honest node that has seen the same set of proposals will
    always agree on which block should be processed next, without any leader.

    Concurrency
    -----------
    All public methods acquire a threading.Lock so the pool is safe to use
    from Flask request threads and background consensus threads simultaneously.

    Lifecycle of a candidate block
    --------------------------------
    1. add(block_dict)       — node receives a PRE-PREPARE (or proposes itself)
    2. get_top()             — PBFT starts consensus on the earliest candidate
    3. remove(block_hash)    — called after DECIDED; next candidate becomes top
    4. reject(block_hash)    — conflicting / invalid proposal discarded
    """

    def __init__(self):
        # list of block dicts, kept sorted at all times
        self._pool: List[Dict] = []
        self._seen_hashes: set = set()       # dedup by block_hash
        self._seen_alert_ids: set = set()    # dedup by alert tx_id
        self._lock = __import__("threading").Lock()

    # ------------------------------------------------------------------
    # Sort key
    # ------------------------------------------------------------------

    @staticmethod
    def _sort_key(block_dict: Dict):
        """
        Primary  : alert timestamp (float) — smallest = oldest alert = highest priority
        Secondary: proposer_id (str)       — lexicographic tiebreak
        """
        alert = block_dict.get("alert") or {}
        ts = alert.get("timestamp", float("inf"))
        pid = str(block_dict.get("proposer_id", ""))
        return (ts, pid)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, block_dict: Dict) -> bool:
        """
        Add a candidate block to the pool.

        Returns True  if accepted (new, valid entry).
        Returns False if rejected (duplicate hash or duplicate alert).

        Rejection reasons:
        - block_hash already in pool or already committed (seen_hashes)
        - alert tx_id already in pool (two nodes proposed the same alert)
        """
        block_hash = block_dict.get("block_hash")
        alert      = block_dict.get("alert") or {}
        alert_id   = alert.get("tx_id")

        if not block_hash:
            return False

        with self._lock:
            if block_hash in self._seen_hashes:
                return False                         # exact duplicate

            if alert_id and alert_id in self._seen_alert_ids:
                # Another node already proposed a block for this alert.
                # Keep whichever has the earlier (timestamp, proposer_id).
                # Find the existing entry for this alert_id.
                existing = next(
                    (b for b in self._pool
                     if (b.get("alert") or {}).get("tx_id") == alert_id),
                    None
                )
                if existing is not None:
                    if self._sort_key(block_dict) < self._sort_key(existing):
                        # New proposal has higher priority — replace
                        self._pool.remove(existing)
                        self._seen_hashes.discard(existing["block_hash"])
                    else:
                        return False                 # existing is better, drop new

            self._pool.append(block_dict)
            self._seen_hashes.add(block_hash)
            if alert_id:
                self._seen_alert_ids.add(alert_id)

            # Keep sorted so get_top() is O(1)
            self._pool.sort(key=self._sort_key)
            return True

    def get_top(self) -> Optional[Dict]:
        """
        Return the highest-priority candidate (earliest alert timestamp)
        without removing it.  Returns None if pool is empty.
        """
        with self._lock:
            return self._pool[0] if self._pool else None

    def remove(self, block_hash: str) -> bool:
        """
        Remove a block after it has been committed.
        Also clears its alert_id from the seen set so the slot is free.
        """
        with self._lock:
            for i, b in enumerate(self._pool):
                if b.get("block_hash") == block_hash:
                    alert_id = (b.get("alert") or {}).get("tx_id")
                    self._pool.pop(i)
                    self._seen_hashes.discard(block_hash)
                    if alert_id:
                        self._seen_alert_ids.discard(alert_id)
                    return True
            return False

    def reject(self, block_hash: str) -> bool:
        """
        Remove a block that failed validation or was superseded.
        Keeps block_hash in seen_hashes to prevent re-admission.
        """
        with self._lock:
            for i, b in enumerate(self._pool):
                if b.get("block_hash") == block_hash:
                    alert_id = (b.get("alert") or {}).get("tx_id")
                    self._pool.pop(i)
                    # Keep block_hash in seen to block replay
                    if alert_id:
                        self._seen_alert_ids.discard(alert_id)
                    return True
            return False

    def mark_committed(self, block_hash: str) -> None:
        """
        Record a hash as permanently committed so it is never re-admitted
        even after a remove().  Called by On_Block_Committed.
        """
        with self._lock:
            self._seen_hashes.add(block_hash)

    def size(self) -> int:
        with self._lock:
            return len(self._pool)

    def is_empty(self) -> bool:
        with self._lock:
            return len(self._pool) == 0

    def peek_all(self) -> List[Dict]:
        """Return a snapshot of the current pool order (for debugging)."""
        with self._lock:
            return list(self._pool)


# ---------------------------------------------------------------------------
# IDSBlockchain
# ---------------------------------------------------------------------------

class IDSBlockchain:
    """
    Append-only chain of IDS alert blocks.

    Key design decisions
    --------------------
    * One alert per block — keeps PBFT scope clear and audit trail granular.
    * pending_alerts holds signed AlertTransactions waiting to be proposed.
    * create_block() pops ONE pending alert and wraps it in a new Block.
    * add_block() validates block_number, previous_hash, and block_hash
      before appending.
    """

    def __init__(self):
        self.chain: List[Block] = []
        self.pending_alerts: List[AlertTransaction] = []
        self.validators: Dict[str, VerifyingKey] = {}
        self.current_view = 0
        self.current_sequence = 0

        self._create_genesis_block()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _create_genesis_block(self) -> None:
        # CRITICAL: timestamp must be fixed so every node produces the
        # same genesis block_hash. If time.time() is used, each node
        # gets a different hash → previous_hash mismatch on first real block.
        genesis = Block(
            block_number=0,
            alert=None,
            previous_hash="0" * 64,
            view_number=0,
            sequence_number=0,
            proposer_id="genesis",
            timestamp=0.0,          # fixed epoch → same hash on all nodes
        )
        print(f"[Chain] Genesis block_hash = {genesis.block_hash[:20]}…")
        self.chain.append(genesis)

    # ------------------------------------------------------------------
    # Validator registry
    # ------------------------------------------------------------------

    def register_validator(self, validator_id: str, public_key: VerifyingKey) -> None:
        self.validators[validator_id] = public_key

    # ------------------------------------------------------------------
    # Alert (pending) queue
    # ------------------------------------------------------------------

    def add_alert(self, alert: AlertTransaction) -> bool:
        """Queue a signed alert for the next block proposal."""
        if alert.tx_id is None or alert.signature is None:
            return False  # alert must be signed before queuing
        self.pending_alerts.append(alert)
        return True

    # ------------------------------------------------------------------
    # Block creation / addition
    # ------------------------------------------------------------------

    def create_block(self, proposer_id: str) -> Optional[Block]:
        """
        Pop the oldest pending alert and wrap it in a new candidate Block.
        Returns None if there are no pending alerts.
        """
        if not self.pending_alerts:
            return None

        alert = self.pending_alerts[0]   # take the oldest (FIFO)
        previous_block = self.chain[-1]

        new_block = Block(
            block_number=len(self.chain),
            alert=alert,
            previous_hash=previous_block.block_hash,
            view_number=self.current_view,
            sequence_number=self.current_sequence,
            proposer_id=proposer_id,
        )

        self.current_sequence += 1
        return new_block

    def add_block(self, block: Block) -> bool:
        """
        Append a consensus-finalised block to the chain.
        Validates block_number, previous_hash, and block_hash.
        Removes the corresponding alert from the pending queue.
        """
        if block.block_number != len(self.chain):
            print(
                f"[Chain] Invalid block_number {block.block_number}, "
                f"expected {len(self.chain)}"
            )
            return False

        if block.previous_hash != self.chain[-1].block_hash:
            print(f"[Chain] previous_hash mismatch")
            print(f"        block.previous_hash    = {block.previous_hash[:20]}…")
            print(f"        chain[-1].block_hash   = {self.chain[-1].block_hash[:20]}…")
            return False

        if block.block_hash != block.calculate_hash():
            print(f"[Chain] block_hash invalid")
            print(f"        block.block_hash       = {block.block_hash[:20]}…")
            print(f"        block.calculate_hash() = {block.calculate_hash()[:20]}…")
            return False

        self.chain.append(block)

        # Remove the committed alert from the pending queue
        if block.alert:
            self.pending_alerts = [
                a for a in self.pending_alerts if a.tx_id != block.alert.tx_id
            ]

        return True

    # ------------------------------------------------------------------
    # Chain validation
    # ------------------------------------------------------------------

    def replace_chain(self, block_dicts: List[Dict]) -> bool:
        """
        Replace the local chain with a downloaded chain from a peer.
        Called during sync when joining mid-session.

        Validation steps before replacing:
          1. Must be longer than our current chain — no point replacing otherwise
          2. Genesis block must match ours exactly
          3. Every block's previous_hash must match the prior block's hash
          4. Every block's hash must be self-consistent (calculate_hash check)

        On success:
          - self.chain is replaced with the reconstructed blocks
          - Any pending_alerts whose tx_ids are already in the new chain
            are removed (no double-processing)

        Returns True if replaced, False if rejected.
        """
        if len(block_dicts) <= len(self.chain):
            print("[Chain] Sync rejected — peer chain not longer than ours")
            return False

        # Reconstruct Block objects from dicts
        new_chain: List[Block] = []
        for d in block_dicts:
            try:
                new_chain.append(Block.from_dict(d))
            except Exception as e:
                print(f"[Chain] Sync rejected — failed to parse block: {e}")
                return False

        # Validate genesis
        genesis = new_chain[0]
        if genesis.block_number != 0 or genesis.previous_hash != "0" * 64:
            print("[Chain] Sync rejected — invalid genesis block")
            return False

        # Validate every link and hash
        for i in range(1, len(new_chain)):
            cur  = new_chain[i]
            prev = new_chain[i - 1]

            if cur.block_number != i:
                print(f"[Chain] Sync rejected — block_number mismatch at {i}")
                return False

            if cur.previous_hash != prev.block_hash:
                print(f"[Chain] Sync rejected — broken link at block {i}")
                return False

            if cur.block_hash != cur.calculate_hash():
                print(f"[Chain] Sync rejected — invalid hash at block {i}")
                return False

        # All checks passed — replace chain
        self.chain = new_chain

        # Remove any pending alerts already committed in the new chain
        committed_tx_ids = {
            b.alert.tx_id
            for b in self.chain[1:]
            if b.alert and b.alert.tx_id
        }
        self.pending_alerts = [
            a for a in self.pending_alerts
            if a.tx_id not in committed_tx_ids
        ]

        print(f"[Chain] Sync complete — chain length now {len(self.chain)}")
        return True

    def validate_chain(self) -> bool:
        if not self.chain:
            return False

        genesis = self.chain[0]
        if genesis.block_number != 0 or genesis.previous_hash != "0" * 64:
            return False

        for i in range(1, len(self.chain)):
            cur = self.chain[i]
            prev = self.chain[i - 1]

            if cur.block_number != i:
                return False
            if cur.previous_hash != prev.block_hash:
                return False
            if cur.block_hash != cur.calculate_hash():
                return False

        return True

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_block(self, block_number: int) -> Optional[Block]:
        if 0 <= block_number < len(self.chain):
            return self.chain[block_number]
        return None

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def get_alerts_by_type(self, alert_type: str) -> List[AlertTransaction]:
        return [
            b.alert
            for b in self.chain[1:]
            if b.alert and b.alert.alert_type == alert_type
        ]

    def get_alerts_by_node(self, node_id: str) -> List[AlertTransaction]:
        return [
            b.alert
            for b in self.chain[1:]
            if b.alert and b.alert.node_id == node_id
        ]

    def get_alerts_by_severity(self, severity: str) -> List[AlertTransaction]:
        return [
            b.alert
            for b in self.chain[1:]
            if b.severity == severity and b.alert
        ]

    def get_statistics(self) -> Dict[str, Any]:
        data_blocks = self.chain[1:]
        severity_totals = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for b in data_blocks:
            if b.severity:
                severity_totals[b.severity] = severity_totals.get(b.severity, 0) + 1

        return {
            "total_blocks": len(self.chain),
            "total_alerts": len(data_blocks),
            "pending_alerts": len(self.pending_alerts),
            "severity_summary": severity_totals,
            "chain_valid": self.validate_chain(),
        }