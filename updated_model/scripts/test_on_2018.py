import sys, json, numpy as np
sys.path.append('.')

features = json.load(open('config/features.json'))['features']
label_names = json.load(open('config/labels.json'))['label_names']

# 3 real flows from C++ capturer
flows = [
    {
        "name": "Flow 1 (UDP, 1+1 pkts, 166ms)",
        "Flow Duration": 166601.0, "Tot Fwd Pkts": 1.0, "Tot Bwd Pkts": 1.0,
        "TotLen Fwd Pkts": 76.0, "TotLen Bwd Pkts": 76.0,
        "Fwd Pkt Len Max": 76.0, "Fwd Pkt Len Min": 76.0, "Fwd Pkt Len Mean": 76.0, "Fwd Pkt Len Std": 0.0,
        "Bwd Pkt Len Max": 76.0, "Bwd Pkt Len Min": 76.0, "Bwd Pkt Len Mean": 76.0, "Bwd Pkt Len Std": 0.0,
        "Flow Byts/s": 912.3594, "Flow Pkts/s": 12.0047,
        "Flow IAT Mean": 166601.0, "Flow IAT Std": 0.0, "Flow IAT Max": 166601.0, "Flow IAT Min": 166601.0,
        "Fwd IAT Tot": 0.0, "Fwd IAT Mean": 0.0, "Fwd IAT Std": 0.0, "Fwd IAT Max": 0.0, "Fwd IAT Min": 0.0,
        "Bwd IAT Tot": 0.0, "Bwd IAT Mean": 0.0, "Bwd IAT Std": 0.0, "Bwd IAT Max": 0.0, "Bwd IAT Min": 0.0,
        "Fwd PSH Flags": 0.0, "Fwd URG Flags": 0.0,
        "Fwd Header Len": 28.0, "Bwd Header Len": 28.0,
        "Fwd Pkts/s": 6.0024, "Bwd Pkts/s": 6.0024,
        "Pkt Len Min": 76.0, "Pkt Len Max": 76.0, "Pkt Len Mean": 76.0, "Pkt Len Std": 0.0, "Pkt Len Var": 0.0,
        "FIN Flag Cnt": 0.0, "SYN Flag Cnt": 0.0, "RST Flag Cnt": 0.0, "PSH Flag Cnt": 0.0,
        "ACK Flag Cnt": 0.0, "URG Flag Cnt": 0.0, "ECE Flag Cnt": 0.0,
        "Down/Up Ratio": 1.0, "Pkt Size Avg": 76.0, "Fwd Seg Size Avg": 76.0, "Bwd Seg Size Avg": 76.0,
        "Fwd Byts/b Avg": 0.0, "Subflow Fwd Pkts": 1.0, "Subflow Fwd Byts": 76.0,
        "Subflow Bwd Pkts": 1.0, "Subflow Bwd Byts": 76.0,
        "Init Fwd Win Byts": 0.0, "Init Bwd Win Byts": 0.0, "Fwd Act Data Pkts": 1.0, "Fwd Seg Size Min": 8.0,
        "Active Mean": 166601.0, "Active Std": 0.0, "Active Max": 166601.0, "Active Min": 166601.0,
        "Idle Mean": 0.0, "Idle Std": 0.0, "Idle Max": 0.0, "Idle Min": 0.0,
    },
    {
        "name": "Flow 2 (UDP, 1+1 pkts, 140ms)",
        "Flow Duration": 140988.0, "Tot Fwd Pkts": 1.0, "Tot Bwd Pkts": 1.0,
        "TotLen Fwd Pkts": 76.0, "TotLen Bwd Pkts": 76.0,
        "Fwd Pkt Len Max": 76.0, "Fwd Pkt Len Min": 76.0, "Fwd Pkt Len Mean": 76.0, "Fwd Pkt Len Std": 0.0,
        "Bwd Pkt Len Max": 76.0, "Bwd Pkt Len Min": 76.0, "Bwd Pkt Len Mean": 76.0, "Bwd Pkt Len Std": 0.0,
        "Flow Byts/s": 1078.1058, "Flow Pkts/s": 14.1856,
        "Flow IAT Mean": 140988.0, "Flow IAT Std": 0.0, "Flow IAT Max": 140988.0, "Flow IAT Min": 140988.0,
        "Fwd IAT Tot": 0.0, "Fwd IAT Mean": 0.0, "Fwd IAT Std": 0.0, "Fwd IAT Max": 0.0, "Fwd IAT Min": 0.0,
        "Bwd IAT Tot": 0.0, "Bwd IAT Mean": 0.0, "Bwd IAT Std": 0.0, "Bwd IAT Max": 0.0, "Bwd IAT Min": 0.0,
        "Fwd PSH Flags": 0.0, "Fwd URG Flags": 0.0,
        "Fwd Header Len": 28.0, "Bwd Header Len": 28.0,
        "Fwd Pkts/s": 7.0928, "Bwd Pkts/s": 7.0928,
        "Pkt Len Min": 76.0, "Pkt Len Max": 76.0, "Pkt Len Mean": 76.0, "Pkt Len Std": 0.0, "Pkt Len Var": 0.0,
        "FIN Flag Cnt": 0.0, "SYN Flag Cnt": 0.0, "RST Flag Cnt": 0.0, "PSH Flag Cnt": 0.0,
        "ACK Flag Cnt": 0.0, "URG Flag Cnt": 0.0, "ECE Flag Cnt": 0.0,
        "Down/Up Ratio": 1.0, "Pkt Size Avg": 76.0, "Fwd Seg Size Avg": 76.0, "Bwd Seg Size Avg": 76.0,
        "Fwd Byts/b Avg": 0.0, "Subflow Fwd Pkts": 1.0, "Subflow Fwd Byts": 76.0,
        "Subflow Bwd Pkts": 1.0, "Subflow Bwd Byts": 76.0,
        "Init Fwd Win Byts": 0.0, "Init Bwd Win Byts": 0.0, "Fwd Act Data Pkts": 1.0, "Fwd Seg Size Min": 8.0,
        "Active Mean": 140988.0, "Active Std": 0.0, "Active Max": 140988.0, "Active Min": 140988.0,
        "Idle Mean": 0.0, "Idle Std": 0.0, "Idle Max": 0.0, "Idle Min": 0.0,
    },
    {
        "name": "Flow 3 (UDP, 3+0 pkts, 1.8s)",
        "Flow Duration": 1845670.0, "Tot Fwd Pkts": 3.0, "Tot Bwd Pkts": 0.0,
        "TotLen Fwd Pkts": 594.0, "TotLen Bwd Pkts": 0.0,
        "Fwd Pkt Len Max": 198.0, "Fwd Pkt Len Min": 198.0, "Fwd Pkt Len Mean": 198.0, "Fwd Pkt Len Std": 0.0,
        "Bwd Pkt Len Max": 0.0, "Bwd Pkt Len Min": 0.0, "Bwd Pkt Len Mean": 0.0, "Bwd Pkt Len Std": 0.0,
        "Flow Byts/s": 321.8344, "Flow Pkts/s": 1.6254,
        "Flow IAT Mean": 922835.0, "Flow IAT Std": 5379.0, "Flow IAT Max": 928214.0, "Flow IAT Min": 917456.0,
        "Fwd IAT Tot": 1845670.0, "Fwd IAT Mean": 922835.0, "Fwd IAT Std": 5379.0, "Fwd IAT Max": 928214.0, "Fwd IAT Min": 917456.0,
        "Bwd IAT Tot": 0.0, "Bwd IAT Mean": 0.0, "Bwd IAT Std": 0.0, "Bwd IAT Max": 0.0, "Bwd IAT Min": 0.0,
        "Fwd PSH Flags": 0.0, "Fwd URG Flags": 0.0,
        "Fwd Header Len": 84.0, "Bwd Header Len": 0.0,
        "Fwd Pkts/s": 1.6254, "Bwd Pkts/s": 0.0,
        "Pkt Len Min": 198.0, "Pkt Len Max": 198.0, "Pkt Len Mean": 198.0, "Pkt Len Std": 0.0, "Pkt Len Var": 0.0,
        "FIN Flag Cnt": 0.0, "SYN Flag Cnt": 0.0, "RST Flag Cnt": 0.0, "PSH Flag Cnt": 0.0,
        "ACK Flag Cnt": 0.0, "URG Flag Cnt": 0.0, "ECE Flag Cnt": 0.0,
        "Down/Up Ratio": 0.0, "Pkt Size Avg": 198.0, "Fwd Seg Size Avg": 198.0, "Bwd Seg Size Avg": 0.0,
        "Fwd Byts/b Avg": 0.0, "Subflow Fwd Pkts": 3.0, "Subflow Fwd Byts": 594.0,
        "Subflow Bwd Pkts": 0.0, "Subflow Bwd Byts": 0.0,
        "Init Fwd Win Byts": 0.0, "Init Bwd Win Byts": 0.0, "Fwd Act Data Pkts": 3.0, "Fwd Seg Size Min": 8.0,
        "Active Mean": 1845670.0, "Active Std": 0.0, "Active Max": 1845670.0, "Active Min": 1845670.0,
        "Idle Mean": 0.0, "Idle Std": 0.0, "Idle Max": 0.0, "Idle Min": 0.0,
    },
]

import joblib
import json
model     = joblib.load('artifacts/xgb_v1.pkl')
feat_cfg  = json.load(open('config/features.json'))
feat_list = feat_cfg['features']
medians   = feat_cfg['imputer_medians']

print("\n" + "="*60)
print("  Real Flow Predictions — XGBoost (2017 trained)")
print("="*60)

for flow in flows:
    name = flow.pop('name')
    X = []
    for f in feat_list:
        val = flow.get(f, medians.get(f, 0.0))
        if val is None or (isinstance(val, float) and (np.isnan(val) or np.isinf(val))):
            val = medians.get(f, 0.0)
        X.append(float(val))

    X     = np.array(X).reshape(1, -1)
    probs = model.predict_proba(X)[0]
    pred  = int(np.argmax(probs))
    conf  = float(np.max(probs))
    label = label_names[str(pred)]['name']

    print(f"\n  {name}")
    print(f"  Prediction : {label} (class {pred})  confidence={conf*100:.1f}%")
    print(f"  All probs  : { {label_names[str(i)]['name']: round(float(p)*100,1) for i,p in enumerate(probs)} }")

print("\n" + "="*60 + "\n")