import json
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

print("\n==============================================")
print(" TRAINING FINAL ANOMALY MODEL (v2 TUNED) ")
print("==============================================\n")

# ----------------------------
# Load features
# ----------------------------
with open("config/features_v2.json") as f:
    FEATURES = json.load(f)["features"]

# ----------------------------
# Load data
# ----------------------------
df = pd.read_csv(
    "data/cleaned_data_sampled.csv",
    on_bad_lines="skip",
    low_memory=False
)

# ----------------------------
# Use ONLY benign data
# ----------------------------
benign_df = df[df["Label"] == 0]

X_benign = benign_df[FEATURES].copy()
X_benign = X_benign.fillna(X_benign.median())

print("[INFO] Benign samples used:", len(X_benign))

# ----------------------------
# Final tuned config (LOCKED)
# ----------------------------
model = IsolationForest(
    n_estimators=600,
    max_samples=0.9,
    contamination=0.10,
    max_features=0.5,
    random_state=42,
    n_jobs=-1
)

print("\n[INFO] Training Isolation Forest with tuned hyperparameters...")
model.fit(X_benign)

# ----------------------------
# Save model
# ----------------------------
joblib.dump(model, "artifacts/anomaly_model_v2_tuned.joblib")

print("\n[OK] Saved artifacts/anomaly_model_v2_tuned.joblib")
print("\n[DONE] Final anomaly model training complete.")