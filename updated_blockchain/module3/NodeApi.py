from flask import Flask, request, jsonify


class NodeAPI:
    def __init__(self, node):
        """
        node: instance of Node (PBFT + Crypto wrapper)
        """
        self.node = node
        self.app = Flask(__name__)
        self._register_routes()

    def _register_routes(self):

        @self.app.route("/health", methods=["GET"])
        def health():
            return jsonify({"status": "ok"}), 200

        @self.app.route("/identity", methods=["GET"])
        def identity():
            return jsonify(self.node.get_identity()), 200

        @self.app.route("/dh", methods=["POST"])
        def dh_exchange():
            data = request.json
            if not data:
                return jsonify({"error": "Invalid DH payload"}), 400

            peer_id     = data.get("node_id")
            peer_dh_key = data.get("dh_public_key")
            peer_pub_key = data.get("public_key")   # identity key (optional)

            if peer_id is None or peer_dh_key is None:
                return jsonify({"error": "Missing DH fields"}), 400

            # Register identity key if included in payload
            if peer_pub_key and peer_id not in self.node.peer_public_keys:
                self.node.register_peer_identity(peer_id, peer_pub_key)

            # Register DH key and derive session key
            self.node.register_peer_dh(peer_id, peer_dh_key)

            # If this peer is new (not in our session_keys yet), do a full
            # reverse DH exchange back to them so we also get their session key.
            # Without this, we have their pubkey but no session key, so
            # Send_To_All_Nodes would skip them entirely.
            if peer_id not in self.node.session_keys:
                import threading
                def reverse_dh(pid):
                    payload = {
                        "node_id":       self.node.node_id,
                        "dh_public_key": self.node.dh_public_key.to_string().hex(),
                        "public_key":    self.node.public_key.to_string().hex(),
                    }
                    resp = self.node.peer_client.send_dh_key(pid, payload)
                    if resp:
                        self.node.register_peer_dh(
                            resp["node_id"], resp["dh_public_key"]
                        )
                        if "public_key" in resp and pid not in self.node.peer_public_keys:
                            self.node.register_peer_identity(
                                resp["node_id"], resp["public_key"]
                            )
                        print(f"[Node {self.node.node_id}] ✓ Late peer {pid} "
                              f"registered via reverse DH")
                threading.Thread(
                    target=reverse_dh, args=(peer_id,), daemon=True
                ).start()

            # Return our own DH key AND identity key so the caller
            # can register both in one round trip
            resp = self.node.get_dh_public()
            resp["public_key"] = self.node.public_key.to_string().hex()
            return jsonify(resp), 200

        @self.app.route("/pbft", methods=["POST"])
        def receive_pbft():
            msg = request.json
            if not msg or "enc" not in msg or "signature" not in msg:
                return jsonify({"error": "Encrypted PBFT required"}), 400

            self.node.On_Message_Received_From_Network(msg)
            return jsonify({"status": "received"}), 200

        # ── IDS alert ingestion ───────────────────────────────────────────

        @self.app.route("/alert", methods=["POST"])
        def receive_alert():
            """
            Called by ml_server.py when FusionIDS detects a non-benign alert.

            Expected payload (mirrors ml_server.py PredictResponse):
            {
                "signature": {
                    "label_id":   2,
                    "label_name": "DDoS",
                    "confidence": 0.97
                },
                "anomaly": {
                    "anomaly_score": -0.84
                },
                "alert": {
                    "label_name": "DDoS",
                    "severity":   "high",
                    "fusion":     "both_agree"
                },
                "meta": {
                    "src_ip":   "192.168.1.5",
                    "dst_ip":   "10.0.0.1",
                    "src_port": 443,
                    "dst_port": 80,
                    "protocol": 6
                }
            }

            Flow:
              1. Validate payload
              2. Build AlertTransaction from IDS output
              3. Sign it with this node's private key
              4. Call node.submit_alert() → PBFT consensus
            """
            if not self.node.is_secure:
                return jsonify({
                    "error": "Node not ready — still establishing secure channels"
                }), 503

            data = request.json
            if not data:
                return jsonify({"error": "Empty payload"}), 400

            alert_info = data.get("alert")
            if not alert_info:
                # Benign flow — ml_server should not have sent this
                return jsonify({"status": "ignored", "reason": "benign"}), 200

            signature_info = data.get("signature", {})
            anomaly_info   = data.get("anomaly", {})
            meta           = data.get("meta", {})

            # ── Build AlertTransaction ────────────────────────────────────
            from module1.BlockChain import AlertTransaction

            alert_type = alert_info.get("label_name", "unknown")

            # detector_outputs: confidence scores from each detector
            detector_outputs = {
                "signature_model": round(
                    float(signature_info.get("confidence", 0.0)), 4
                ),
                "anomaly_model": round(
                    float(anomaly_info.get("anomaly_score", 0.0)), 4
                ),
            }

            # features_summary: only the audit trail goes on-chain.
            # Raw features are stored off-chain in the database after the
            # block is committed, linked back to the block via tx_id.
            features_summary = {
                "src_ip":   meta.get("src_ip"),
                "dst_ip":   meta.get("dst_ip"),
                "src_port": meta.get("src_port"),
                "dst_port": meta.get("dst_port"),
                "protocol": meta.get("protocol"),
                "severity": alert_info.get("severity"),
                "fusion":   alert_info.get("fusion"),
            }

            # Raw features kept separately — NOT stored in AlertTransaction.
            # Passed to submit_alert() so they can be written to the DB
            # after the block is committed.
            raw_features = data.get("features", {})

            tx = AlertTransaction(
                node_id          = str(self.node.node_id),
                alert_type       = alert_type,
                detector_outputs = detector_outputs,
                features_summary = features_summary,
            )

            # Sign with this node's private key — proves this node raised alert
            tx.sign(self.node.private_key)

            print(f"[Node {self.node.node_id}] ← IDS alert: "
                  f"{alert_type} | severity: {alert_info.get('severity')} | "
                  f"src: {meta.get('src_ip')}")

            # Return immediately to ml_server — PBFT runs in background.
            # submit_alert() is non-blocking: it queues the alert and
            # fires propose_block() which uses Send_To_All_Nodes (threaded).
            # No need to re-validate here — this node's ml_server already
            # classified this flow as non-benign in Phase 1.
            import threading
            threading.Thread(
                target = self.node.submit_alert,
                args   = (tx, raw_features),
                daemon = True
            ).start()

            return jsonify({
                "status":     "accepted",
                "alert_type": alert_type,
                "tx_id":      tx.tx_id,
            }), 202

        # ── Chain sync endpoints ──────────────────────────────────────────

        @self.app.route("/sync/length", methods=["GET"])
        def sync_length():
            """
            Returns the current chain length.
            Called by a joining node to find which peer has the longest chain
            without downloading the full chain from everyone.
            """
            return jsonify({
                "node_id":      self.node.node_id,
                "chain_length": len(self.node.blockchain.chain)
            }), 200

        @self.app.route("/sync/chain", methods=["GET"])
        def sync_chain():
            """
            Returns the full chain as a list of serialised block dicts.
            Called by a joining node after identifying the peer with the
            longest valid chain.

            Each block is serialised via Block.to_dict() so the joining
            node can reconstruct it via Block.from_dict().
            """
            chain_data = [
                block.to_dict()
                for block in self.node.blockchain.chain
            ]
            return jsonify({
                "node_id": self.node.node_id,
                "chain":   chain_data
            }), 200

    def start(self, port):
        print(f"[NodeAPI] Listening on port {port}")
        self.app.run(host="0.0.0.0", port=port, threaded=True)