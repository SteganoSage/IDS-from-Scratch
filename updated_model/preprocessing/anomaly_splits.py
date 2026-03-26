"""
training/prepare_anomaly_splits.py
====================================
Creates a dedicated train/test split from data/processed/sampled.csv
(our step3 output) specifically for anomaly model training/evaluation.

Split strategy:
  - Benign: 80% train, 20% test  (stratified by nothing — all same class)
  - Attacks: 100% go to test set (anomaly models train on Benign only)

Output:
  data/anomaly_splits/benign_train.csv
  data/anomaly_splits/benign_test.csv
  data/anomaly_splits/attack_test.csv

Usage:
    python -m training.prepare_anomaly_splits
"""

import json
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split

SAMPLED_PATH = Path("data/processed/sampled.csv")
OUT_DIR      = Path("data/anomaly_splits")
OUT_DIR.mkdir(parents=True, exist_ok=True)

LABELS_CFG   = Path("config/labels.json")
RANDOM_SEED  = 42
BENIGN_SPLIT = 0.8   # 80% train, 20% test


def main():
    with open(LABELS_CFG) as f:
        label_cfg = json.load(f)
    label_col = label_cfg["label_column"]

    print(f"\n{'='*60}")
    print(f"  Anomaly Split Preparation")
    print(f"  Source: data/processed/sampled.csv")
    print(f"{'='*60}\n")

    print(f"[INFO] Loading sampled.csv...")
    df = pd.read_csv(SAMPLED_PATH, low_memory=False)
    print(f"  Total rows : {len(df):,}")

    # ── Separate Benign and Attack ─────────────────────────────────────────
    benign  = df[df[label_col] == 0].copy()
    attacks = df[df[label_col] != 0].copy()

    print(f"  Benign rows  : {len(benign):,}")
    print(f"  Attack rows  : {len(attacks):,}")
    print(f"\n  Attack class distribution:")
    for cls, cnt in attacks[label_col].value_counts().sort_index().items():
        print(f"    Class {cls}: {cnt:,}")

    # ── Split Benign 80/20 ─────────────────────────────────────────────────
    benign_train, benign_test = train_test_split(
        benign,
        train_size   = BENIGN_SPLIT,
        random_state = RANDOM_SEED,
        shuffle      = True,
    )

    print(f"\n[INFO] Benign split:")
    print(f"  Train : {len(benign_train):,} rows  (Flow Duration mean={benign_train['Flow Duration'].mean():.1f})")
    print(f"  Test  : {len(benign_test):,}  rows  (Flow Duration mean={benign_test['Flow Duration'].mean():.1f})")

    # ── Save ───────────────────────────────────────────────────────────────
    benign_train.to_csv(OUT_DIR / "benign_train.csv", index=False)
    benign_test.to_csv(OUT_DIR  / "benign_test.csv",  index=False)
    attacks.to_csv(OUT_DIR      / "attack_test.csv",  index=False)

    print(f"\n[OK] Saved:")
    print(f"  data/anomaly_splits/benign_train.csv  ({len(benign_train):,} rows)")
    print(f"  data/anomaly_splits/benign_test.csv   ({len(benign_test):,} rows)")
    print(f"  data/anomaly_splits/attack_test.csv   ({len(attacks):,} rows)")
    print(f"\n✅  Done. Run anomaly training scripts next.")


if __name__ == "__main__":
    main()