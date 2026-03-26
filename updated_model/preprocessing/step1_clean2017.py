"""
preprocessing/step1_prepare_2017.py
=====================================
Prepares CIC-IDS 2017 sampled dataset for the pipeline.

Classes:
  0 → Benign
  1 → BruteForce   (FTP-Patator, SSH-Patator)
  2 → DoS          (Hulk, Slowloris, Slowhttptest, GoldenEye, Heartbleed)
  3 → Bot
  4 → WebAttack    (Brute Force, XSS, Sql Injection)
  5 → PortScan
  6 → Infiltration

No DDoS in this sample — excluded from label map.

Usage:
    python -m preprocessing.step1_prepare_2017
"""

import numpy as np
import pandas as pd
from pathlib import Path

INPUT_PATH = Path("data/processed/cleaned2017.csv")
OUT_PATH   = Path("data/processed/sampled.csv")

RENAME_MAP = {
    "Total Fwd Packets"            : "Tot Fwd Pkts",
    "Total Backward Packets"       : "Tot Bwd Pkts",
    "Total Length of Fwd Packets"  : "TotLen Fwd Pkts",
    "Total Length of Bwd Packets"  : "TotLen Bwd Pkts",
    "Fwd Packet Length Max"        : "Fwd Pkt Len Max",
    "Fwd Packet Length Min"        : "Fwd Pkt Len Min",
    "Fwd Packet Length Mean"       : "Fwd Pkt Len Mean",
    "Fwd Packet Length Std"        : "Fwd Pkt Len Std",
    "Bwd Packet Length Max"        : "Bwd Pkt Len Max",
    "Bwd Packet Length Min"        : "Bwd Pkt Len Min",
    "Bwd Packet Length Mean"       : "Bwd Pkt Len Mean",
    "Bwd Packet Length Std"        : "Bwd Pkt Len Std",
    "Flow Bytes/s"                 : "Flow Byts/s",
    "Flow Packets/s"               : "Flow Pkts/s",
    "Fwd IAT Total"                : "Fwd IAT Tot",
    "Bwd IAT Total"                : "Bwd IAT Tot",
    "Fwd Header Length"            : "Fwd Header Len",
    "Bwd Header Length"            : "Bwd Header Len",
    "Fwd Packets/s"                : "Fwd Pkts/s",
    "Bwd Packets/s"                : "Bwd Pkts/s",
    "Min Packet Length"            : "Pkt Len Min",
    "Max Packet Length"            : "Pkt Len Max",
    "Packet Length Mean"           : "Pkt Len Mean",
    "Packet Length Std"            : "Pkt Len Std",
    "Packet Length Variance"       : "Pkt Len Var",
    "FIN Flag Count"               : "FIN Flag Cnt",
    "SYN Flag Count"               : "SYN Flag Cnt",
    "RST Flag Count"               : "RST Flag Cnt",
    "PSH Flag Count"               : "PSH Flag Cnt",
    "ACK Flag Count"               : "ACK Flag Cnt",
    "URG Flag Count"               : "URG Flag Cnt",
    "ECE Flag Count"               : "ECE Flag Cnt",
    "Average Packet Size"          : "Pkt Size Avg",
    "Avg Fwd Segment Size"         : "Fwd Seg Size Avg",
    "Avg Bwd Segment Size"         : "Bwd Seg Size Avg",
    "Fwd Header Length.1"          : "Fwd Seg Size Min",
    "Fwd Avg Bytes/Bulk"           : "Fwd Byts/b Avg",
    "Fwd Avg Packets/Bulk"         : "Fwd Pkts/b Avg",
    "Fwd Avg Bulk Rate"            : "Fwd Blk Rate Avg",
    "Bwd Avg Bytes/Bulk"           : "Bwd Byts/b Avg",
    "Bwd Avg Packets/Bulk"         : "Bwd Pkts/b Avg",
    "Bwd Avg Bulk Rate"            : "Bwd Blk Rate Avg",
    "Subflow Fwd Packets"          : "Subflow Fwd Pkts",
    "Subflow Fwd Bytes"            : "Subflow Fwd Byts",
    "Subflow Bwd Packets"          : "Subflow Bwd Pkts",
    "Subflow Bwd Bytes"            : "Subflow Bwd Byts",
    "Init_Win_bytes_forward"       : "Init Fwd Win Byts",
    "Init_Win_bytes_backward"      : "Init Bwd Win Byts",
    "act_data_pkt_fwd"             : "Fwd Act Data Pkts",
    "min_seg_size_forward"         : "Fwd Seg Size Min",
}

LABEL_MAP = {
    "BENIGN"        : 0,
    "BruteForce"    : 1,
    "DoS"           : 2,
    "Bot"           : 3,
    "WebAttack"     : 4,
    "PortScan"      : 5,
    "Infiltration"  : 6,
}

LABEL_NAMES = {
    0:"Benign", 1:"BruteForce", 2:"DoS", 3:"Bot",
    4:"WebAttack", 5:"PortScan", 6:"Infiltration"
}


def main():
    print(f"\n{'='*65}")
    print(f"  FusionIDS - Step 1: Prepare CIC-IDS 2017 Dataset")
    print(f"{'='*65}\n")

    print(f"[INFO] Loading {INPUT_PATH}...")
    df = pd.read_csv(INPUT_PATH, low_memory=False)
    df.columns = df.columns.str.strip()
    print(f"  Shape: {df.shape}")

    # Rename columns
    df = df.rename(columns=RENAME_MAP)
    print(f"[INFO] Columns renamed to 2018 convention")

    # Map labels
    label_col = "Label"
    df[label_col] = df[label_col].astype(str).str.strip()

    unknown = set(df[label_col].unique()) - set(LABEL_MAP.keys())
    if unknown:
        print(f"[WARN] Unknown labels (will be dropped): {unknown}")
        for u in unknown:
            LABEL_MAP[u] = -1

    df[label_col] = df[label_col].map(LABEL_MAP)
    before = len(df)
    df = df[df[label_col] != -1].dropna(subset=[label_col])
    df[label_col] = df[label_col].astype(int)
    if before - len(df):
        print(f"[INFO] Dropped {before - len(df):,} unknown rows")

    # Drop duplicate columns caused by rename (e.g. Fwd Header Length.1 → Fwd Seg Size Min)
    df = df.loc[:, ~df.columns.duplicated(keep='first')]

    # Replace inf with NaN
    num_cols  = df.select_dtypes(include=[np.number]).columns
    inf_count = np.isinf(df[num_cols].values).sum()
    for col in num_cols:
        df[col] = df[col].replace([float('inf'), float('-inf')], float('nan'))
    nan_count = df[num_cols].isna().sum().sum()
    print(f"[INFO] Replaced {inf_count:,} inf values with NaN")
    print(f"[INFO] Total NaN remaining: {nan_count:,} (step4 imputer handles these)")

    # Label distribution
    print(f"\n[INFO] Final label distribution:")
    print(f"  {'Class':<8} {'Name':<16} {'Count':>8}")
    print(f"  {'─'*36}")
    for cls, cnt in df[label_col].value_counts().sort_index().items():
        print(f"  {cls:<8} {LABEL_NAMES.get(cls,'?'):<16} {cnt:>8,}")
    print(f"  {'─'*36}")
    print(f"  {'Total':<24} {len(df):>8,}")

    df.to_csv(OUT_PATH, index=False)
    print(f"\n[OK] Saved -> {OUT_PATH}")
    print(f"\n  Next: python -m preprocessing.step4_feature_selection_and_split")
    print(f"{'='*65}\n")


if __name__ == "__main__":
    main()