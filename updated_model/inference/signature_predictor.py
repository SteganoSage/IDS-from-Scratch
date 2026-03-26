import json
import joblib
import numpy as np
import pandas as pd


class SignaturePredictor:

    def __init__(
        self,
        model_path="artifacts/xgb_v1.pkl",
        features_path="config/features.json",
        labels_path="config/labels.json"
    ):

        print("[INFO] Loading signature model...")
        self.model = joblib.load(model_path)

        with open(features_path) as f:
            self._features_json = json.load(f)["features"]  # importance-ranked, NOT used for column order

        # Use the feature order the model was actually trained with.
        # XGBoost stores this in model.feature_names_in_ (sklearn wrapper)
        # or model.get_booster().feature_names (native API).
        # Feeding features in importance order instead of training order
        # causes every prediction to be wrong — this was the root bug.
        if hasattr(self.model, "feature_names_in_"):
            self.features = list(self.model.feature_names_in_)
            print(f"[INFO] Using feature order from model.feature_names_in_ ({len(self.features)} features)")
        elif hasattr(self.model, "get_booster") and self.model.get_booster().feature_names:
            self.features = self.model.get_booster().feature_names
            print(f"[INFO] Using feature order from booster.feature_names ({len(self.features)} features)")
        else:
            # Fallback: use features.json order (may be wrong — retrain recommended)
            self.features = self._features_json
            print(f"[WARN] Could not read feature order from model — falling back to features.json order")

        with open(labels_path) as f:
            label_cfg = json.load(f)

        self.label_names = label_cfg["label_names"]
        self.label_col = label_cfg["label_column"]

    def predict(self, flow):

        df = pd.DataFrame([flow])
        X = df[self.features].values

        probs = self.model.predict_proba(X)[0]
        label_id = int(np.argmax(probs))
        confidence = float(np.max(probs))

        label_info = self.label_names[str(label_id)]

        return {
            "label_id": label_id,
            "label_name": label_info["name"],
            "family": label_info["name"],
            "confidence": confidence
        }