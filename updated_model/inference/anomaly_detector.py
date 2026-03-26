import joblib
import json
import pandas as pd

MODEL_PATH = "artifacts/anomaly_model_v2_tuned.joblib"
FEATURES_PATH = "config/features_v2.json"
class AnomalyPredictor:

    def __init__(self):

        # bundle = joblib.load(r"artifacts\iforest_v1.pkl")

        # self.model = bundle["model"]
        # self.features = bundle["features"]
        # self.medians = bundle["medians"]

        with open(FEATURES_PATH) as f:
            self._features_json = json.load(f)["features"]

        # Load ONLY the model (no preprocessing pipeline)
        self.model = joblib.load(MODEL_PATH)

        # Use training column order from model, not features.json importance order
        if hasattr(self.model, "feature_names_in_"):
            self.features = list(self.model.feature_names_in_)
            print(f"[INFO] Anomaly model feature order from feature_names_in_ ({len(self.features)} features)")
        else:
            self.features = self._features_json
            print(f"[WARN] Anomaly model has no feature_names_in_ — using features.json order")

    def predict(self, flow):

        df = pd.DataFrame([flow])[self.features]

        # apply same preprocessing as training
        # for col in df.columns:
        #     df[col] = df[col].fillna(self.medians.get(col, 0))

        df = df.fillna(df.median())

        score = float(self.model.score_samples(df)[0])

        return {
            "anomaly_score": score
        }