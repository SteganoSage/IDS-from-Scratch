class FusionEngine:

    def __init__(self,
                 sig_threshold=0.40,
                 anomaly_threshold=-0.5,
                 strong_anomaly_threshold=-0.7):

        self.sig_threshold = sig_threshold
        self.anomaly_threshold = anomaly_threshold
        self.strong_anomaly_threshold = strong_anomaly_threshold

    def fuse(self, sig_result, anomaly_result):

        signature_detected = (
            sig_result["label_id"] != 0 and
            sig_result["confidence"] >= self.sig_threshold
        )

        score = anomaly_result["anomaly_score"]

        strong_anomaly = score <= self.strong_anomaly_threshold

        # Both models agree
        if signature_detected and strong_anomaly:

            result = dict(sig_result)
            result["severity"] = "Critical"
            result["fusion"] = "Signature+Anomaly"
            result["anomaly_score"] = score
            return result

        # Signature attack only
        if signature_detected:

            result = dict(sig_result)
            result["severity"] = "Medium"
            result["fusion"] = "SignatureOnly"
            return result

        # Possible zero-day attack
        if strong_anomaly:

            return {
                "label_id": -1,
                "label_name": "Unknown Attack",
                "family": "Anomalous Behavior",
                "severity": "Low",
                "fusion": "AnomalyOnly",
                "anomaly_score": score
            }

        return None