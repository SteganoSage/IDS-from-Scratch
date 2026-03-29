"""
db.py
=====
SQLite persistence layer for the IDS blockchain node.

Schema
------
Each node owns one SQLite file (e.g. node0.db).
Two tables:

  blocks        — on-chain data (one row per committed block)
  flow_features — off-chain raw CIC-IDS features (one row per alert,
                  linked to blocks via tx_id)

Key changes vs previous version
---------------------------------
1. alert_timestamp column added — stores alert.timestamp separately from
   block.timestamp.  This was the root cause of hash mismatches on restart:
   the old schema stored block.timestamp in the timestamp column and then
   used it to reconstruct alert.timestamp, making _signing_data() and
   tx_id verification produce different results after a reload.

2. verify_chain_integrity() — fast linkage-only check directly on raw DB
   rows without constructing any Block objects.  Called on startup before
   load_all_blocks() to detect DB corruption early.

3. load_all_blocks() — now reads alert_timestamp for the alert sub-dict
   and returns block_number >= 1 rows only.  Genesis is never stored and
   never returned; IDSBlockchain.load_chain_from_db() stitches the loaded
   blocks onto the in-memory genesis.

On restart, Node calls:
  1. db.verify_chain_integrity()       — fast sanity check
  2. blockchain.load_chain_from_db(    — trusted DB restore (no hash recompute)
         db.load_all_blocks()
     )
  3. node._sync_chain()                — download any missed blocks from peers
"""

import sqlite3
import json
import os
from typing import List, Optional, Dict, Any


# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

CREATE_BLOCKS_TABLE = """
CREATE TABLE IF NOT EXISTS blocks (
    -- Chain fields
    block_number    INTEGER PRIMARY KEY,
    block_hash      TEXT    NOT NULL UNIQUE,
    previous_hash   TEXT    NOT NULL,
    proposer_id     TEXT,
    timestamp       REAL    NOT NULL,        -- block.timestamp
    view_number     INTEGER DEFAULT 0,
    sequence_number INTEGER DEFAULT 0,

    -- Alert fields (on-chain audit trail)
    alert_tx_id     TEXT,
    alert_type      TEXT,
    alert_timestamp REAL,                    -- alert.timestamp (SEPARATE from block.timestamp)
    severity        TEXT,
    node_id         TEXT,
    signer_address  TEXT,
    alert_signature TEXT,

    -- Detector outputs (JSON)
    detector_outputs    TEXT,   -- JSON: {"signature_model": 0.97, ...}

    -- Features summary (JSON) — 5-tuple + severity + fusion
    features_summary    TEXT,   -- JSON: {"src_ip": ..., "dst_ip": ..., ...}

    -- PBFT proof (JSON arrays)
    prepare_signatures  TEXT,   -- JSON array
    commit_signatures   TEXT,   -- JSON array

    -- Metadata
    committed_at    REAL        -- unix timestamp when this node committed it
);
"""

CREATE_FLOW_FEATURES_TABLE = """
CREATE TABLE IF NOT EXISTS flow_features (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_id           TEXT    NOT NULL UNIQUE,   -- links to blocks.alert_tx_id
    block_number    INTEGER NOT NULL,
    node_id         TEXT    NOT NULL,          -- which node proposed this alert
    features        TEXT    NOT NULL,          -- JSON: all 80 CIC-IDS features
    stored_at       REAL    NOT NULL           -- unix timestamp
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_blocks_hash     ON blocks(block_hash);",
    "CREATE INDEX IF NOT EXISTS idx_blocks_alert    ON blocks(alert_type);",
    "CREATE INDEX IF NOT EXISTS idx_blocks_node     ON blocks(node_id);",
    "CREATE INDEX IF NOT EXISTS idx_features_tx     ON flow_features(tx_id);",
    "CREATE INDEX IF NOT EXISTS idx_features_block  ON flow_features(block_number);",
]

# Migration: add alert_timestamp to existing databases that were created
# before this column existed.  Runs at startup; safe to run multiple times
# because "ADD COLUMN" is a no-op if the column already exists in SQLite
# (well, SQLite raises OperationalError which we catch and ignore).
MIGRATE_ADD_ALERT_TIMESTAMP = """
ALTER TABLE blocks ADD COLUMN alert_timestamp REAL;
"""


# ─────────────────────────────────────────────────────────────────────────────
# Database class
# ─────────────────────────────────────────────────────────────────────────────

class NodeDB:
    """
    SQLite wrapper for one blockchain node.

    Usage
    -----
    db = NodeDB("node0.db")
    db.save_block(block)
    db.save_features(tx_id, block_number, node_id, features)
    if db.verify_chain_integrity():
        blocks = db.load_all_blocks()
    """

    def __init__(self, db_path: str):
        """
        db_path: path to the SQLite file, e.g. "data/node0.db"
        Creates the file and schema if they don't exist.
        Runs migration to add alert_timestamp column if missing.
        """
        self.db_path = db_path

        # Ensure parent directory exists
        os.makedirs(
            os.path.dirname(db_path) if os.path.dirname(db_path) else ".",
            exist_ok=True
        )

        # Create schema and run migrations
        with self._connect() as conn:
            conn.execute(CREATE_BLOCKS_TABLE)
            conn.execute(CREATE_FLOW_FEATURES_TABLE)
            for idx in CREATE_INDEXES:
                conn.execute(idx)

            # Migration: add alert_timestamp if it doesn't exist yet.
            # Existing databases (written without this column) will have
            # NULL for alert_timestamp; load_all_blocks() falls back to
            # block.timestamp in that case so old data still loads.
            try:
                conn.execute(MIGRATE_ADD_ALERT_TIMESTAMP)
                print(f"[DB] Migrated — added alert_timestamp column")
            except sqlite3.OperationalError:
                pass  # column already exists

            conn.commit()

        print(f"[DB] Initialized at {db_path}")

    def _connect(self) -> sqlite3.Connection:
        """
        Open a connection with WAL mode for better concurrent read performance.
        WAL (Write-Ahead Logging) allows reads while a write is in progress.
        """
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row   # access columns by name
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    # ── Startup integrity check ───────────────────────────────────────────

    def verify_chain_integrity(self) -> bool:
        """
        Fast linkage-only check directly on raw DB rows.

        Does NOT construct Block objects — avoids any hash-recompute risk.
        Simply verifies that each row's previous_hash matches the prior
        row's block_hash, confirming the chain is unbroken in the DB.

        Called on startup BEFORE load_all_blocks() so corruption is caught
        early with a clear error message rather than a cryptic hash mismatch
        during Block construction.

        Returns True  if the chain is intact (or empty).
        Returns False if a broken link is detected — caller should not
                      attempt to load blocks and should start from genesis.
        """
        try:
            with self._connect() as conn:
                rows = conn.execute("""
                    SELECT block_number, block_hash, previous_hash
                    FROM blocks
                    ORDER BY block_number ASC
                """).fetchall()

            if not rows:
                return True   # empty DB is valid

            for i in range(1, len(rows)):
                if rows[i]["previous_hash"] != rows[i - 1]["block_hash"]:
                    print(
                        f"[DB] Integrity check FAILED at block "
                        f"{rows[i]['block_number']}: "
                        f"previous_hash {rows[i]['previous_hash'][:16]}… "
                        f"!= prior block_hash {rows[i - 1]['block_hash'][:16]}…"
                    )
                    return False

            print(f"[DB] Integrity check passed — {len(rows)} blocks linked correctly")
            return True

        except Exception as e:
            print(f"[DB] verify_chain_integrity failed: {e}")
            return False

    # ── Block persistence ─────────────────────────────────────────────────

    def save_block(self, block) -> bool:
        """
        Persist a committed Block object to the database.
        Called by Node.On_Block_Committed() after blockchain.add_block() succeeds.
        Skips genesis block (block_number=0) — it's always reconstructed in memory.

        Stores alert.timestamp in the dedicated alert_timestamp column,
        separate from block.timestamp, so both can be restored exactly on reload.

        Returns True on success, False if block already exists (idempotent).
        """
        if block.block_number == 0:
            return True   # genesis is always reconstructed, never stored

        import time as _time

        alert = block.alert
        try:
            with self._connect() as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO blocks (
                        block_number, block_hash, previous_hash,
                        proposer_id, timestamp,
                        view_number, sequence_number,
                        alert_tx_id, alert_type, alert_timestamp,
                        severity,
                        node_id, signer_address, alert_signature,
                        detector_outputs, features_summary,
                        prepare_signatures, commit_signatures,
                        committed_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?,
                        ?,
                        ?, ?, ?,
                        ?, ?,
                        ?, ?,
                        ?
                    )
                """, (
                    block.block_number,
                    block.block_hash,
                    block.previous_hash,
                    block.proposer_id,
                    block.timestamp,                            # block.timestamp
                    block.view_number  if block.view_number  is not None else 0,
                    block.sequence_number if block.sequence_number is not None else 0,

                    # Alert identity
                    alert.tx_id           if alert else None,
                    alert.alert_type      if alert else None,
                    alert.timestamp       if alert else None,  # alert.timestamp (separate!)
                    block.severity,

                    # Alert auth fields
                    alert.node_id         if alert else None,
                    alert.signer_address  if alert else None,
                    alert.signature.hex() if (alert and alert.signature) else None,

                    # JSON blobs
                    json.dumps(alert.detector_outputs) if alert else None,
                    json.dumps(alert.features_summary) if alert else None,
                    json.dumps(block.prepare_signatures),
                    json.dumps(block.commit_signatures),

                    _time.time(),
                ))
                conn.commit()
            return True
        except Exception as e:
            print(f"[DB] save_block failed: {e}")
            return False

    def load_all_blocks(self) -> List[Dict]:
        """
        Load all non-genesis blocks from DB in order, as dicts ready for
        Block.from_dict().

        Returns block_number >= 1 rows only.  Genesis is NOT in the DB and
        NOT returned here — IDSBlockchain.load_chain_from_db() stitches the
        returned blocks onto the in-memory genesis block.

        alert_timestamp is read from its own column and used for the alert
        sub-dict timestamp, NOT block.timestamp.  This is the fix for the
        hash mismatch bug: previously, block.timestamp was incorrectly used
        for alert reconstruction, breaking _signing_data() and tx_id
        verification after a restart.

        Fallback: if alert_timestamp is NULL (row written by old code before
        the migration), block.timestamp is used instead — this preserves
        compatibility with existing databases while new writes use the
        correct column.
        """
        try:
            with self._connect() as conn:
                rows = conn.execute("""
                    SELECT * FROM blocks ORDER BY block_number ASC
                """).fetchall()

            block_dicts = []
            for row in rows:
                alert_dict = None
                if row["alert_tx_id"]:
                    # Use alert_timestamp if stored; fall back to block timestamp
                    # for rows written before the migration (will be NULL).
                    alert_ts = row["alert_timestamp"]
                    if alert_ts is None:
                        alert_ts = row["timestamp"]
                        print(
                            f"[DB] Block {row['block_number']}: alert_timestamp is NULL "
                            f"(pre-migration row) — using block.timestamp as fallback"
                        )

                    alert_dict = {
                        "tx_id":            row["alert_tx_id"],
                        "node_id":          row["node_id"],
                        "alert_type":       row["alert_type"],
                        "timestamp":        alert_ts,           # alert.timestamp, correctly separated
                        "detector_outputs": json.loads(row["detector_outputs"] or "{}"),
                        "features_summary": json.loads(row["features_summary"] or "{}"),
                        "signer_address":   row["signer_address"],
                        "signature":        row["alert_signature"],
                    }

                block_dicts.append({
                    "block_number":       row["block_number"],
                    "block_hash":         row["block_hash"],
                    "previous_hash":      row["previous_hash"],
                    "proposer_id":        row["proposer_id"],
                    "timestamp":          row["timestamp"],     # block.timestamp
                    "view_number":        row["view_number"] or 0,
                    "sequence_number":    row["sequence_number"] or 0,
                    "alert":              alert_dict,
                    "alert_type":         row["alert_type"],
                    "severity":           row["severity"],
                    "prepare_signatures": json.loads(row["prepare_signatures"] or "[]"),
                    "commit_signatures":  json.loads(row["commit_signatures"]  or "[]"),
                })

            print(f"[DB] Loaded {len(block_dicts)} blocks from {self.db_path}")
            return block_dicts

        except Exception as e:
            print(f"[DB] load_all_blocks failed: {e}")
            return []

    def get_chain_length(self) -> int:
        """Returns number of blocks in DB (not counting genesis)."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM blocks"
                ).fetchone()
                return row["cnt"]
        except Exception:
            return 0

    # ── Feature persistence ───────────────────────────────────────────────

    def save_features(self, tx_id: str, block_number: int,
                      node_id: str, features: dict) -> bool:
        """
        Persist raw CIC-IDS flow features off-chain.
        Called by Node._store_features() after block commits.
        Linked to on-chain block via tx_id.
        """
        import time as _time
        try:
            with self._connect() as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO flow_features
                        (tx_id, block_number, node_id, features, stored_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    tx_id,
                    block_number,
                    node_id,
                    json.dumps(features),
                    _time.time(),
                ))
                conn.commit()
            return True
        except Exception as e:
            print(f"[DB] save_features failed: {e}")
            return False

    def get_features(self, tx_id: str) -> Optional[Dict]:
        """Retrieve raw features for a given alert tx_id."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT features FROM flow_features WHERE tx_id = ?",
                    (tx_id,)
                ).fetchone()
                if row:
                    return json.loads(row["features"])
        except Exception as e:
            print(f"[DB] get_features failed: {e}")
        return None

    # ── Query helpers ─────────────────────────────────────────────────────

    def get_alerts_by_type(self, alert_type: str) -> List[Dict]:
        """Query all committed alerts of a given type."""
        try:
            with self._connect() as conn:
                rows = conn.execute("""
                    SELECT block_number, block_hash, alert_tx_id,
                           alert_type, severity, node_id, timestamp
                    FROM blocks
                    WHERE alert_type = ?
                    ORDER BY block_number ASC
                """, (alert_type,)).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            print(f"[DB] get_alerts_by_type failed: {e}")
            return []

    def get_alerts_by_node(self, node_id: str) -> List[Dict]:
        """Query all alerts proposed by a given node."""
        try:
            with self._connect() as conn:
                rows = conn.execute("""
                    SELECT block_number, block_hash, alert_tx_id,
                           alert_type, severity, timestamp
                    FROM blocks
                    WHERE node_id = ?
                    ORDER BY block_number ASC
                """, (node_id,)).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            print(f"[DB] get_alerts_by_node failed: {e}")
            return []

    def get_statistics(self) -> Dict[str, Any]:
        """Summary statistics for this node's view of the chain."""
        try:
            with self._connect() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) as cnt FROM blocks"
                ).fetchone()["cnt"]

                severity_rows = conn.execute("""
                    SELECT severity, COUNT(*) as cnt
                    FROM blocks
                    WHERE severity IS NOT NULL
                    GROUP BY severity
                """).fetchall()

                severity = {r["severity"]: r["cnt"] for r in severity_rows}

                features_count = conn.execute(
                    "SELECT COUNT(*) as cnt FROM flow_features"
                ).fetchone()["cnt"]

            return {
                "total_blocks":     total,
                "severity_summary": severity,
                "features_stored":  features_count,
            }
        except Exception as e:
            print(f"[DB] get_statistics failed: {e}")
            return {}