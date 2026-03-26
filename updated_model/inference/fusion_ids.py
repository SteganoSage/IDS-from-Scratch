from inference.signature_predictor import SignaturePredictor
from inference.anomaly_detector import AnomalyPredictor
from inference.fusion_engine import FusionEngine


class FusionIDS:

    def __init__(self):

        print("[INFO] Initializing FusionIDS pipeline...")

        self.signature = SignaturePredictor()
        self.anomaly = AnomalyPredictor()
        self.fusion = FusionEngine()

    def predict(self, flow):

        sig_result = self.signature.predict(flow)
        anomaly_result = self.anomaly.predict(flow)

        alert = self.fusion.fuse(sig_result, anomaly_result)

        return {
            "signature": sig_result,
            "anomaly": anomaly_result,
            "alert": alert
        }