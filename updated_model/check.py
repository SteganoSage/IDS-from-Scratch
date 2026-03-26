import pickle, json
import pandas as pd
import numpy as np

model = pickle.load(open('artifacts/rf_v1.pkl', 'rb'))

print("=== Model internals ===")
print(f"Type: {type(model)}")
print(f"n_features_in_: {getattr(model, 'n_features_in_', 'NOT FOUND')}")
print(f"feature_names_in_: {getattr(model, 'feature_names_in_', 'NOT FOUND')}")

# Try booster
if hasattr(model, 'get_booster'):
    booster = model.get_booster()
    fn = booster.feature_names
    print(f"booster.feature_names: {fn[:5] if fn else 'None'}")
    print(f"booster.feature_names count: {len(fn) if fn else 0}")

# Check train.csv column order
df = pd.read_csv('data/splits/train.csv')
train_cols = [c for c in df.columns if c != 'Label']
print(f"\n=== train.csv ===")
print(f"Feature columns: {len(train_cols)}")
print(f"First 5: {train_cols[:5]}")

# Check features.json
feat_json = json.load(open('config/features.json'))['features']
print(f"\n=== features.json ===")
print(f"Count: {len(feat_json)}")
print(f"First 5: {feat_json[:5]}")

# Test predict with train.csv order vs features.json order
flow = {
    "Flow Duration":17.0,"Tot Fwd Pkts":1.0,"Tot Bwd Pkts":1.0,
    "TotLen Fwd Pkts":40.0,"TotLen Bwd Pkts":40.0,"Fwd Pkt Len Max":40.0,
    "Fwd Pkt Len Min":40.0,"Fwd Pkt Len Mean":40.0,"Fwd Pkt Len Std":0.0,
    "Bwd Pkt Len Max":40.0,"Bwd Pkt Len Min":40.0,"Bwd Pkt Len Mean":40.0,
    "Bwd Pkt Len Std":0.0,"Flow Byts/s":4705882.5,"Flow Pkts/s":117647.0547,
    "Flow IAT Mean":17.0,"Flow IAT Std":0.0,"Flow IAT Max":17.0,"Flow IAT Min":17.0,
    "Fwd IAT Tot":0.0,"Fwd IAT Mean":0.0,"Fwd IAT Std":0.0,"Fwd IAT Max":0.0,
    "Fwd IAT Min":0.0,"Bwd IAT Tot":0.0,"Bwd IAT Mean":0.0,"Bwd IAT Std":0.0,
    "Bwd IAT Max":0.0,"Bwd IAT Min":0.0,"Fwd PSH Flags":0.0,"Fwd URG Flags":0.0,
    "Fwd Header Len":40.0,"Bwd Header Len":40.0,"Fwd Pkts/s":58823.5273,
    "Bwd Pkts/s":58823.5273,"Pkt Len Min":40.0,"Pkt Len Max":40.0,
    "Pkt Len Mean":40.0,"Pkt Len Std":0.0,"Pkt Len Var":0.0,"FIN Flag Cnt":0.0,
    "SYN Flag Cnt":1.0,"RST Flag Cnt":1.0,"PSH Flag Cnt":0.0,"ACK Flag Cnt":1.0,
    "URG Flag Cnt":0.0,"ECE Flag Cnt":0.0,"Down/Up Ratio":1.0,"Pkt Size Avg":40.0,
    "Fwd Seg Size Avg":40.0,"Bwd Seg Size Avg":40.0,"Fwd Byts/b Avg":0.0,
    "Subflow Fwd Pkts":1.0,"Subflow Fwd Byts":40.0,"Subflow Bwd Pkts":1.0,
    "Subflow Bwd Byts":40.0,"Init Fwd Win Byts":0.0,"Init Bwd Win Byts":512.0,
    "Fwd Act Data Pkts":0.0,"Fwd Seg Size Min":20.0,"Active Mean":17.0,
    "Active Std":0.0,"Active Max":17.0,"Active Min":17.0,"Idle Mean":0.0,
    "Idle Std":0.0,"Idle Max":0.0,"Idle Min":0.0
}

print("\n=== Prediction with train.csv column order ===")
X_train_order = pd.DataFrame([flow])[train_cols]
proba = model.predict_proba(X_train_order)[0]
pred = np.argmax(proba)
labels = json.load(open('config/labels.json'))['label_names']
print(f"Prediction: {labels[str(pred)]['name']} ({pred}) confidence={proba[pred]:.4f}")
print(f"All probs: { {labels[str(i)]['name']: round(float(p),4) for i,p in enumerate(proba)} }")

print("\n=== Prediction with features.json order ===")
X_feat_order = pd.DataFrame([flow])[feat_json]
proba2 = model.predict_proba(X_feat_order)[0]
pred2 = np.argmax(proba2)
print(f"Prediction: {labels[str(pred2)]['name']} ({pred2}) confidence={proba2[pred2]:.4f}")
print(f"All probs: { {labels[str(i)]['name']: round(float(p),4) for i,p in enumerate(proba2)} }")

print("\n=== Are the two orderings different? ===")
print(f"train_cols == feat_json: {train_cols == feat_json}")
print(f"train_cols[:5]: {train_cols[:5]}")
print(f"feat_json[:5]:  {feat_json[:5]}")