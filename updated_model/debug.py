"""
debug_model.py
Run this in your project root:
    python3 debug_model.py
"""
import sys, json
import numpy as np
import pandas as pd
import pickle
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.append(str(ROOT))

# ── Load model ────────────────────────────────────────────────────────────────
with open(ROOT / "artifacts/xgb_v1.pkl", "rb") as f:
    model = pickle.load(f)

with open(ROOT / "config/features.json") as f:
    FEATURES = json.load(f)

with open(ROOT / "config/labels.json") as f:
    LABELS = json.load(f)

# ── Flows to test ─────────────────────────────────────────────────────────────
flow1 = {
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

flow2 = {
    "Flow Duration":2082983.0,"Tot Fwd Pkts":203.0,"Tot Bwd Pkts":205.0,
    "TotLen Fwd Pkts":27764.0,"TotLen Bwd Pkts":45584.0,"Fwd Pkt Len Max":138.0,
    "Fwd Pkt Len Min":52.0,"Fwd Pkt Len Mean":136.7685,"Fwd Pkt Len Std":10.0658,
    "Bwd Pkt Len Max":236.0,"Bwd Pkt Len Min":52.0,"Bwd Pkt Len Mean":222.3610,
    "Bwd Pkt Len Std":26.8760,"Flow Byts/s":35212.9609,"Flow Pkts/s":195.8729,
    "Flow IAT Mean":5169.0444,"Flow IAT Std":5071.1392,"Flow IAT Max":11061.0,
    "Flow IAT Min":4.0,"Fwd IAT Tot":2082945.0,"Fwd IAT Mean":10311.6094,
    "Fwd IAT Std":969.7296,"Fwd IAT Max":11252.0,"Fwd IAT Min":302.0,
    "Bwd IAT Tot":2082983.0,"Bwd IAT Mean":10210.7012,"Bwd IAT Std":1396.6696,
    "Bwd IAT Max":11440.0,"Bwd IAT Min":19.0,"Fwd PSH Flags":200.0,
    "Fwd URG Flags":0.0,"Fwd Header Len":10564.0,"Bwd Header Len":10668.0,
    "Fwd Pkts/s":97.4564,"Bwd Pkts/s":98.4165,"Pkt Len Min":52.0,
    "Pkt Len Max":236.0,"Pkt Len Mean":179.7745,"Pkt Len Std":47.3795,
    "Pkt Len Var":2244.8169,"FIN Flag Cnt":2.0,"SYN Flag Cnt":2.0,
    "RST Flag Cnt":0.0,"PSH Flag Cnt":400.0,"ACK Flag Cnt":407.0,
    "URG Flag Cnt":0.0,"ECE Flag Cnt":0.0,"Down/Up Ratio":1.0099,
    "Pkt Size Avg":179.7745,"Fwd Seg Size Avg":136.7685,"Bwd Seg Size Avg":222.3610,
    "Fwd Byts/b Avg":0.0,"Subflow Fwd Pkts":203.0,"Subflow Fwd Byts":27764.0,
    "Subflow Bwd Pkts":205.0,"Subflow Bwd Byts":45584.0,"Init Fwd Win Byts":65483.0,
    "Init Bwd Win Byts":65495.0,"Fwd Act Data Pkts":200.0,"Fwd Seg Size Min":32.0,
    "Active Mean":2082983.0,"Active Std":0.0,"Active Max":2082983.0,
    "Active Min":2082983.0,"Idle Mean":0.0,"Idle Std":0.0,"Idle Max":0.0,"Idle Min":0.0
}

def predict_and_explain(flow, name):
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")

    X = pd.DataFrame([flow])[FEATURES]
    proba = model.predict_proba(X)[0]
    pred  = np.argmax(proba)

    print(f"  Prediction : {LABELS[str(pred)]} (class {pred})")
    print(f"  Confidence : {proba[pred]:.4f}")
    print(f"\n  Class probabilities:")
    for i, p in enumerate(proba):
        label = LABELS.get(str(i), str(i))
        bar   = "█" * int(p * 40)
        print(f"    {label:20s} {p:.4f}  {bar}")

    # Top 15 feature importances
    importances = model.feature_importances_
    feat_imp = sorted(zip(FEATURES, importances), key=lambda x: -x[1])[:15]
    print(f"\n  Top 15 features by model importance vs this flow's value:")
    print(f"  {'Feature':<30} {'Importance':>10}  {'Flow Value':>15}")
    print(f"  {'-'*58}")
    for feat, imp in feat_imp:
        val = flow.get(feat, "MISSING")
        print(f"  {feat:<30} {imp:>10.4f}  {val:>15}")

predict_and_explain(flow1, "Flow 1 — Port Scan / SYN+RST (1 pkt each direction)")
predict_and_explain(flow2, "Flow 2 — DoS flood (203 pkts, PSH=400)")

# ── Check if features.json matches model ──────────────────────────────────────
print(f"\n{'='*60}")
print(f"  Sanity checks")
print(f"{'='*60}")
print(f"  features.json count : {len(FEATURES)}")
print(f"  model n_features    : {model.n_features_in_}")
print(f"  match               : {len(FEATURES) == model.n_features_in_}")

# ── Training data stats for top features ──────────────────────────────────────
try:
    df = pd.read_csv(ROOT / "data/splits/train.csv")
    top_feats = [f for f,_ in feat_imp[:5]]
    print(f"\n  Training distribution for top 5 features:")
    for feat in top_feats:
        for label_id, label_name in [(0,'Benign'),(1,'BruteForce'),(2,'DoS'),(5,'PortScan')]:
            cls = df[df['Label']==label_id]
            if feat in cls.columns:
                print(f"    {label_name:12s} {feat:<30} mean={cls[feat].mean():.2f}  max={cls[feat].max():.2f}")
        print()
except FileNotFoundError:
    print("  (train.csv not found — skipping training distribution check)")