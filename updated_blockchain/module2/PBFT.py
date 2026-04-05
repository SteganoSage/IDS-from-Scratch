from collections import defaultdict


class PBFT_Node:
    """
    Leaderless PBFT — any node may propose a block at any time.

    Every message (PRE-PREPARE, PREPARE, COMMIT) carries the full block dict
    so no node is ever stuck waiting for a message it may have missed.

    Flow
    ────
    PRE-PREPARE  →  IDS validate, store block, send PREPARE
    PREPARE      →  store block if first msg, count vote, 2f+1 → send COMMIT
    COMMIT       →  store block if first msg, count vote, 2f+1 → DECIDED
    DECIDED      →  On_Block_Committed() hook called, pool advances
    """

    def __init__(self, node_id: int, total_nodes: int, F: int,
                 pending_pool, ids_model=None):
        self.Node_Id      = node_id
        self.Total_Nodes  = total_nodes
        self.F            = F
        self.pending_pool = pending_pool
        self.ids_model    = ids_model

        self.Prepare    = defaultdict(set)  # bh -> {node_ids that sent PREPARE}
        self.Commit     = defaultdict(set)  # bh -> {node_ids that sent COMMIT}
        self.Committed  = {}                # bh -> "done"
        self.Block_Pool = {}                # bh -> full block dict

        self._prepared       = set()        # bh: already sent PREPARE
        self._committed_sent = set()        # bh: already sent COMMIT
        self._proposed_blocks = set()       # bh: blocks THIS node proposed
                                            # proposer's PREPARE doesn't count
                                            # towards quorum — only validators do

    # ── IDS validation ────────────────────────────────────────────────────

    def Is_Valid_Alert(self, block_dict: dict) -> bool:
        """
        Called on PRE-PREPARE receipt. Passes full block_dict to ids_model
        so it can access _raw_features for local IDS re-validation.
        Returns True if no ids_model set (testing / IDS down).
        """
        if self.ids_model is None:
            return True
        return bool(self.ids_model(block_dict))

    # ── Propose ───────────────────────────────────────────────────────────

    def propose_block(self, block_dict: dict) -> None:
        """
        Called by Node when it has a new signed alert wrapped in a block.
        Stores locally, adds to pool, broadcasts PRE-PREPARE if top candidate.
        """
        bh = block_dict["block_hash"]
        self.Block_Pool[bh] = block_dict
        print(f"[PBFT {self.Node_Id}] propose_block bh={bh[:12]}…")

        if not self.pending_pool.add(block_dict):
            print(f"[PBFT {self.Node_Id}] Pool rejected block (dup/lower priority)")
            return

        top      = self.pending_pool.get_top()
        top_hash = top["block_hash"] if top else ""
        print(f"[PBFT {self.Node_Id}] Pool top={top_hash[:12]}… ours={bh[:12]}…")

        if top_hash != bh:
            print(f"[PBFT {self.Node_Id}] Not top — waiting in pool")
            return

        print(f"[PBFT {self.Node_Id}] Broadcasting PRE-PREPARE…")
        # Mark this block as proposed by us — our PREPARE won't count
        # towards quorum since we didn't run IDS validation on it
        self._proposed_blocks.add(bh)
        self.Send_To_All_Nodes({
            "Type":       "PRE-PREPARE",
            "Block_Hash": bh,
            "Block":      block_dict,
            "Alert":      block_dict.get("alert"),
            "Sender":     self.Node_Id,
        })

        # Proposer sends its own PREPARE immediately (already has the block)
        self._send_prepare(bh)

    # ── Message entry point ───────────────────────────────────────────────

    def receive_message(self, msg: dict) -> None:
        """
        Single entry point for all inbound PBFT messages.
        Called by Node.On_Message_Received_From_Network() after
        decrypt + verify. Handles all phases internally.
        """
        t = msg.get("Type")
        if   t == "PRE-PREPARE": self._on_pre_prepare(msg)
        elif t == "PREPARE":     self._on_prepare(msg)
        elif t == "COMMIT":      self._on_commit(msg)
        else:
            print(f"[PBFT {self.Node_Id}] Unknown message type: {t}")

    # ── Phase handlers ────────────────────────────────────────────────────

    def _on_pre_prepare(self, msg: dict) -> None:
        bh         = msg["Block_Hash"]
        block_dict = msg.get("Block")

        if not block_dict:
            print(f"[PBFT {self.Node_Id}] PRE-PREPARE missing Block — dropped")
            return

        # IDS validation on full block_dict (_raw_features lives here)
        if not self.Is_Valid_Alert(block_dict):
            print(f"[PBFT {self.Node_Id}] IDS rejected alert bh={bh[:12]}…")
            return

        self._store_block(bh, block_dict)
        self._send_prepare(bh)

    def _on_prepare(self, msg: dict) -> None:
        bh         = msg["Block_Hash"]
        block_dict = msg.get("Block")
        sender     = msg.get("Sender")

        # Store block in case PRE-PREPARE was missed (race condition fallback)
        self._store_block(bh, block_dict)

        # Send our own PREPARE if we haven't yet and we now have the block
        # self._send_prepare(bh)

        self.Prepare[bh].add(sender)
        print(f"[PBFT {self.Node_Id}] PREPARE votes for {bh[:12]}…: "
              f"{len(self.Prepare[bh])}/{2*self.F+1} needed")

        if (len(self.Prepare[bh]) >= 2 * self.F + 1
                and bh not in self._committed_sent):
            self._send_commit(bh)

    def _on_commit(self, msg: dict) -> None:
        bh         = msg["Block_Hash"]
        block_dict = msg.get("Block")
        sender     = msg.get("Sender")

        # Store block as fallback
        self._store_block(bh, block_dict)
        # self._send_prepare(bh)

        self.Commit[bh].add(sender)
        print(f"[PBFT {self.Node_Id}] COMMIT votes for {bh[:12]}…: "
              f"{len(self.Commit[bh])}/{2*self.F+1} needed")

        if (len(self.Commit[bh]) >= 2 * self.F + 1
                and self.Committed.get(bh) != "done"):
            self.Committed[bh] = "done"
            print(f"[PBFT {self.Node_Id}] DECIDED bh={bh[:12]}…")
            self.On_Block_Committed(bh)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _store_block(self, bh: str, block_dict) -> None:
        """Store block in Block_Pool and pool if not already present."""
        if block_dict and bh not in self.Block_Pool:
            self.Block_Pool[bh] = block_dict
            self.pending_pool.add(block_dict)

    def _send_prepare(self, bh: str) -> None:
        """Send PREPARE once — only if bh is current top candidate."""
        if bh in self._prepared:
            return
        if self._get_top_hash() != bh:
            return
        if bh not in self.Block_Pool:
            return
        self._prepared.add(bh)

        # Only count our own PREPARE vote if we are a validator (peer node).
        # If we are the proposer, we never ran IDS validation so our vote
        # must not count towards the 2f+1 quorum.
        if bh not in self._proposed_blocks:
            self.Prepare[bh].add(self.Node_Id)

        print(f"[PBFT {self.Node_Id}] Sending PREPARE bh={bh[:12]}… "
              f"({'proposer — vote not counted' if bh in self._proposed_blocks else 'validator'})")
        self.Send_To_All_Nodes({
            "Type":       "PREPARE",
            "Block_Hash": bh,
            "Block":      self.Block_Pool[bh],
            "Sender":     self.Node_Id,
        })

    def _send_commit(self, bh: str) -> None:
        """Send COMMIT once."""
        if bh in self._committed_sent:
            return
        self._committed_sent.add(bh)

        # Same rule — proposer's COMMIT doesn't count towards quorum
        if bh not in self._proposed_blocks:
            self.Commit[bh].add(self.Node_Id)

        print(f"[PBFT {self.Node_Id}] Sending COMMIT bh={bh[:12]}…")
        self.Send_To_All_Nodes({
            "Type":       "COMMIT",
            "Block_Hash": bh,
            "Block":      self.Block_Pool.get(bh),
            "Sender":     self.Node_Id,
        })

    def _get_top_hash(self) -> str:
        top = self.pending_pool.get_top()
        return top["block_hash"] if top else ""

    # ── Advance after commit ──────────────────────────────────────────────

    def try_advance(self) -> None:
        """
        Called after a block commits. Starts consensus on the next pool
        candidate if one exists by re-broadcasting its PRE-PREPARE.
        """
        top = self.pending_pool.get_top()
        if not top:
            return
        bh = top["block_hash"]
        self._store_block(bh, top)
        print(f"[PBFT {self.Node_Id}] Advancing to next candidate bh={bh[:12]}…")
        self.Send_To_All_Nodes({
            "Type":       "PRE-PREPARE",
            "Block_Hash": bh,
            "Block":      top,
            "Alert":      top.get("alert"),
            "Sender":     self.Node_Id,
        })
        self._send_prepare(bh)

    # ── Hooks (overridden by Node) ────────────────────────────────────────

    def Send_To_All_Nodes(self, msg: dict) -> None:
        pass

    def On_Block_Committed(self, block_hash: str) -> None:
        pass