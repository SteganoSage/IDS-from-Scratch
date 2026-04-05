import json
import joblib
import numpy as np
import pandas as pd


class SignaturePredictor:

    def __init__(
        self,
        model_path=None,                      # ← was hardcoded "artifacts/xgb_v1.pkl"
        features_path="config/features.json",
        labels_path="config/labels.json"
    ):
        # Fallback to original default when no path given (local dev)
        if model_path is None:
            model_path = "artifacts/lgbm_v1.pkl"

        print(f"[INFO] Loading signature model from {model_path} ...")
        self.model = joblib.load(model_path)

        with open(features_path) as f:
            self._features_json = json.load(f)["features"]

        # Use the feature order the model was actually trained with.
        # XGBoost stores this in model.feature_names_in_ (sklearn wrapper)
        # or model.get_booster().feature_names (native API).
        if hasattr(self.model, "feature_names_in_"):
            self.features = list(self.model.feature_names_in_)
            print(f"[INFO] Using feature order from model.feature_names_in_ ({len(self.features)} features)")
        elif hasattr(self.model, "get_booster") and self.model.get_booster().feature_names:
            self.features = self.model.get_booster().feature_names
            print(f"[INFO] Using feature order from booster.feature_names ({len(self.features)} features)")
        else:
            self.features = self._features_json
            print(f"[WARN] Could not read feature order from model — falling back to features.json order")

        with open(labels_path) as f:
            label_cfg = json.load(f)

        self.label_names = label_cfg["label_names"]
        self.label_col   = label_cfg["label_column"]

        # Build underscore↔space mapping once at load time.
        # LightGBM converts "Flow Duration" → "Flow_Duration" during training.
        # This map lets us transparently handle both naming styles at predict time.
        self._underscore_to_space = {
            f.replace(" ", "_"): f for f in self._features_json
        }
        # Map from space-name → model-name (what self.features actually contains)
        self._space_to_model = {
            self._underscore_to_space.get(mf, mf): mf
            for mf in self.features
        }

    def _normalize_flow(self, flow: dict) -> dict:
        """Convert flow keys to space-style names regardless of source format."""
        return {self._underscore_to_space.get(k, k): v for k, v in flow.items()}

    def predict(self, flow):

        flow = self._normalize_flow(flow)        # unify to space-style keys
        df   = pd.DataFrame([flow])
        df   = df.rename(columns=self._space_to_model)  # rename to model-style
        X    = df[self.features].values

        probs      = self.model.predict_proba(X)[0]
        label_id   = int(np.argmax(probs))
        confidence = float(np.max(probs))

        label_info = self.label_names[str(label_id)]

        return {
            "label_id":   label_id,
            "label_name": label_info["name"],
            "family":     label_info["name"],
            "confidence": confidence
        }