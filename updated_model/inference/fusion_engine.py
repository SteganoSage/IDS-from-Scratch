class FusionEngine:

    def __init__(self,
                 sig_threshold=0.40,
                 anomaly_threshold=-0.45,
                 strong_anomaly_threshold=-0.55,
                 benign_confidence_threshold=0.80):

        self.sig_threshold            = sig_threshold
        self.anomaly_threshold        = anomaly_threshold
        self.strong_anomaly_threshold = strong_anomaly_threshold

        # If signature says Benign but confidence is below this AND
        # anomaly score is suspicious, treat as Suspicious.
        # e.g. Benign at 68% + anomaly=-0.55 → Suspicious
        self.benign_confidence_threshold = benign_confidence_threshold

    def fuse(self, sig_result, anomaly_result):

        label_id  = sig_result["label_id"]
        confidence= sig_result["confidence"]
        score     = anomaly_result["anomaly_score"]

        signature_detected = (
            label_id != 0 and
            confidence >= self.sig_threshold
        )

        strong_anomaly = score <= self.strong_anomaly_threshold
        weak_anomaly   = score <= self.anomaly_threshold   # -0.5 to -0.7

        # ── Case 1: Both agree — highest confidence ────────────────────────
        if signature_detected and strong_anomaly:
            result = dict(sig_result)
            result["severity"]     = "Critical"
            result["fusion"]       = "Signature+Anomaly"
            result["anomaly_score"]= score
            return result

        # ── Case 2: Signature only ─────────────────────────────────────────
        if signature_detected:
            result = dict(sig_result)
            result["severity"]     = "Medium"
            result["fusion"]       = "SignatureOnly"
            result["anomaly_score"]= score
            return result

        # ── Case 3: Strong anomaly only (possible zero-day) ────────────────
        if strong_anomaly:
            return {
                "label_id":   -1,
                "label_name": "Unknown Attack",
                "family":     "Anomalous Behavior",
                "severity":   "High",
                "fusion":     "AnomalyOnly",
                "anomaly_score": score,
            }

        # ── Case 4 (NEW): Uncertain Benign + weak anomaly → Suspicious ─────
        # Signature said Benign but wasn't confident, AND anomaly detector
        # flagged something (score between -0.5 and -0.7).
        # Neither threshold alone fires, but together they're suspicious.
        # Examples:
        #   Benign @ 68% confidence + anomaly=-0.55 → Suspicious
        #   Benign @ 75% confidence + anomaly=-0.62 → Suspicious
        benign_uncertain = (
            label_id == 0 and
            confidence < self.benign_confidence_threshold
        )
        if (benign_uncertain and weak_anomaly) or (benign_uncertain and strong_anomaly):
            return {
                "label_id":   -2,
                "label_name": "Suspicious",
                "family":     "Suspicious Behavior",
                "severity":   "Unknown",
                "fusion":     "Signature+Anomaly",
                "anomaly_score":   score,
                "sig_confidence":  confidence,
            }

        # ── Case 5 (NEW): Confident non-Benign but weak anomaly ───────────
        # Signature detected an attack class but confidence is below
        # sig_threshold (so Case 2 didn't fire), yet anomaly also sees
        # something. Worth logging as Suspicious rather than dropping.
        # Example: PortScan @ 35% confidence + anomaly=-0.52 → Suspicious
        weak_signature = (
            label_id != 0 and
            confidence < self.sig_threshold and
            confidence >= 0.20              # ignore near-random predictions
        )
        if weak_signature and weak_anomaly:
            result = dict(sig_result)
            result["label_name"]   = f"Suspicious ({sig_result['label_name']})"
            result["severity"]     = "Low"
            result["fusion"]       = "Signature+Anomaly"
            result["anomaly_score"]= score
            return result

        return None