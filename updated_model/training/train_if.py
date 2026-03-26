"""
training/train_iforest.py
==========================
Trains Isolation Forest anomaly detection model on Benign-only traffic.

Principle:
  - Trains ONLY on Benign traffic (800k rows from cleaned.csv)
  - Learns what normal network traffic looks like
  - At inference: high anomaly score = deviates from normal = ALERT
  - Contamination parameter lets the model decide its own threshold

Isolation Forest works by:
  - Randomly selecting a feature and split value
  - Anomalies require fewer splits to isolate (shorter path = more anomalous)
  - Fast, scales well to 68 features, handles high dimensions

Evaluated on:
  - Infiltration rows from cleaned.csv (primary target)
  - All attack classes from test.csv (secondary evaluation)

Usage:
    python -m training.train_iforest

Input:   data/processed/cleaned.csv   (source of 800k Benign + Infiltration)
         data/splits/test.csv          (attack evaluation)
         config/features.json
         config/labels.json

Output:  artifacts/iforest_v1.pkl
         artifacts/iforest_v1_report.json
"""

import json
import time
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_fscore_support,
)

# ── Paths ─────────────────────────────────────────────────────────────────────
CLEANED_PATH = Path("data/processed/cleaned.csv")
TEST_PATH    = Path("data/splits/test.csv")
FEATURES_CFG = Path("config/features.json")
LABELS_CFG   = Path("config/labels.json")
ARTIFACT_DIR = Path("artifacts")
ARTIFACT_DIR.mkdir(exist_ok=True)

MODEL_OUT    = ARTIFACT_DIR / "iforest_v1.pkl"
REPORT_OUT   = ARTIFACT_DIR / "iforest_v1_report.json"

# ── Config ────────────────────────────────────────────────────────────────────
BENIGN_SAMPLE   = 800_000    # Benign rows to train on
RANDOM_SEED     = 42
CHUNK_SIZE      = 50_000

# Isolation Forest params
# contamination = estimated fraction of outliers in training data
# 'auto' lets sklearn decide based on the original paper's threshold
IF_PARAMS = dict(
    n_estimators  = 600,
    max_samples   = 0.9,
    contamination = "auto",    # 1% contamination — tighter threshold, fewer false positives
    max_features  = 0.5,
    bootstrap     = False,
    n_jobs        = -1,
    random_state  = 42,
)


def load_configs():
    with open(FEATURES_CFG) as f:
        feat_cfg = json.load(f)
    with open(LABELS_CFG) as f:
        label_cfg = json.load(f)
    return feat_cfg["features"], feat_cfg["imputer_medians"], label_cfg


def extract_benign(features, label_col, n_samples):
    """
    Two-pass shuffled Benign extraction:
      Pass 1 — scan label column only, collect all Benign row indices
      Pass 2 — randomly sample n_samples indices, read only those rows
    Ensures representative sample from ALL 10 daily files,
    not just the first n rows which are from the earliest files.
    """
    print(f"[INFO] Pass 1 — scanning Benign row indices...")
    benign_indices = []
    total_read     = 0

    reader = pd.read_csv(CLEANED_PATH, chunksize=CHUNK_SIZE,
                         low_memory=False, usecols=[label_col])
    for chunk in reader:
        chunk_start = total_read
        local_idx   = np.where((chunk[label_col] == 0).values)[0]
        benign_indices.extend((chunk_start + local_idx).tolist())
        total_read += len(chunk)

    print(f"  Found {len(benign_indices):,} Benign rows total")

    # Randomly sample n_samples indices
    rng      = np.random.default_rng(RANDOM_SEED)
    cap      = min(n_samples, len(benign_indices))
    selected = set(rng.choice(benign_indices, size=cap, replace=False).tolist())
    print(f"  Randomly selected {cap:,} rows (shuffled)")

    # Pass 2 — read only selected rows
    print(f"[INFO] Pass 2 — reading selected rows...")
    frames     = []
    total_read = 0
    reader2    = pd.read_csv(CLEANED_PATH, chunksize=CHUNK_SIZE, low_memory=False)
    for chunk in reader2:
        chunk_start = total_read
        mask = [(chunk_start + i) in selected for i in range(len(chunk))]
        rows = chunk[mask][features]
        if not rows.empty:
            frames.append(rows)
        total_read += len(chunk)

    X = pd.concat(frames, ignore_index=True)
    X = X.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    print(f"  Collected: {len(X):,} shuffled Benign rows")
    return X



def extract_infiltration(features):
    """
    Extract Infiltration rows directly from combined_raw.csv
    since they were dropped during step2_clean.py (unmapped label)
    """
    raw_path = Path("data/processed/combined_raw.csv")
    if not raw_path.exists():
        print("  ⚠ combined_raw.csv not found — skipping Infiltration eval")
        return None

    print(f"[INFO] Extracting Infiltration rows from combined_raw.csv...")

    infil_frames = []
    total_read   = 0

    reader = pd.read_csv(
        raw_path,
        chunksize  = CHUNK_SIZE,
        low_memory = False,
    )

    for chunk in reader:
        chunk.columns = chunk.columns.str.strip()
        infil = chunk[chunk["Label"].str.strip() == "Infilteration"]
        if not infil.empty:
            # Keep only features that exist in this file
            avail = [f for f in features if f in infil.columns]
            infil_frames.append(infil[avail])
        total_read += len(chunk)

    if not infil_frames:
        print("  ⚠ No Infiltration rows found")
        return None

    X_infil = pd.concat(infil_frames, ignore_index=True)

    # Fill missing feature columns with NaN
    for f in features:
        if f not in X_infil.columns:
            X_infil[f] = np.nan

    X_infil = X_infil[features]
    print(f"  Infiltration rows: {len(X_infil):,}")
    return X_infil


def train():
    features, medians, label_cfg = load_configs()
    label_col   = label_cfg["label_column"]
    label_names = label_cfg["label_names"]

    print(f"\n{'='*65}")
    print(f"  FusionIDS - Phase 3: Isolation Forest Anomaly Model")
    print(f"  Train on : {BENIGN_SAMPLE:,} Benign rows only")
    print(f"  Features : {len(features)}")
    print(f"{'='*65}\n")

    # ── Extract training data (Benign only) ───────────────────────────────
    X_benign = extract_benign(features, label_col, BENIGN_SAMPLE)

    # ── Impute + Scale ────────────────────────────────────────────────────
    print(f"\n[INFO] Imputing and scaling...")
    imputer = SimpleImputer(strategy="median")
    X_benign_imp = imputer.fit_transform(X_benign)

    scaler = StandardScaler()
    X_benign_scaled = scaler.fit_transform(X_benign_imp)

    # ── Train Isolation Forest ────────────────────────────────────────────
    print(f"[INFO] Training Isolation Forest...")
    print(f"  Params: {IF_PARAMS}\n")

    model = IsolationForest(**IF_PARAMS)
    t0    = time.time()
    model.fit(X_benign_scaled)
    train_time = time.time() - t0

    print(f"  Training time : {train_time:.1f}s")
    print(f"  Threshold     : {model.offset_:.6f}")

    # ── Evaluate on Benign sample (should be mostly normal) ───────────────
    benign_scores = model.score_samples(X_benign_scaled)
    benign_preds  = model.predict(X_benign_scaled)   # 1=normal, -1=anomaly
    benign_anomaly_rate = (benign_preds == -1).mean()
    print(f"\n  Benign anomaly rate (should be ~0%): {benign_anomaly_rate*100:.2f}%")


    # ── Evaluate on test.csv attack classes ───────────────────────────────
    print(f"\n[INFO] Evaluating on test.csv attack classes...")
    test_df     = pd.read_csv(TEST_PATH, low_memory=False)
    attack_df   = test_df[test_df[label_col] != 0]  # exclude Benign
    benign_test = test_df[test_df[label_col] == 0]

    attack_feat = attack_df[features].values
    benign_feat = benign_test[features].values

    attack_imp    = imputer.transform(attack_feat)
    attack_scaled = scaler.transform(attack_imp)
    attack_preds  = model.predict(attack_scaled)
    attack_scores = model.score_samples(attack_scaled)

    benign_imp    = imputer.transform(benign_feat)
    benign_scaled = scaler.transform(benign_imp)
    benign_preds2 = model.predict(benign_scaled)

    attack_recall  = (attack_preds == -1).mean()
    benign_spec    = (benign_preds2 == 1).mean()   # specificity

    print(f"\n  Test Set Evaluation:")
    print(f"  {'Metric':<30} {'Value':>10}")
    print(f"  {'─'*45}")
    print(f"  {'Attack Detection Recall':<30} {attack_recall*100:>9.2f}%")
    print(f"  {'Benign Specificity':<30} {benign_spec*100:>9.2f}%")
    print(f"  {'False Positive Rate':<30} {(1-benign_spec)*100:>9.2f}%")

    # Per-class detection rate
    print(f"\n  Per-Class Detection Rate:")
    print(f"  {'Class':<8} {'Family':<16} {'Detected':>10}  {'Total':>8}  {'Rate':>8}")
    print(f"  {'─'*55}")
    per_class = {}
    for cls in sorted(attack_df[label_col].unique()):
        cls_mask   = attack_df[label_col].values == cls
        cls_preds  = attack_preds[cls_mask]
        detected   = (cls_preds == -1).sum()
        total      = cls_mask.sum()
        rate       = detected / total
        name       = label_names[str(cls)]["name"]
        print(f"  {cls:<8} {name:<16} {detected:>10,}  {total:>8,}  {rate*100:>7.2f}%")
        per_class[name] = {"detected": int(detected), "total": int(total),
                           "rate": round(float(rate), 4)}

    # ── Save model + scaler + imputer ─────────────────────────────────────
    bundle = {
        "model":   model,
        "scaler":  scaler,
        "imputer": imputer,
        "features": features,
        "threshold": float(model.offset_),
    }
    joblib.dump(bundle, MODEL_OUT)
    print(f"\n[OK] Model bundle saved -> {MODEL_OUT}")

    # ── Save report ───────────────────────────────────────────────────────
    report = {
        "model":              "IsolationForest",
        "train_benign_rows":  len(X_benign),
        "train_time_sec":     round(train_time, 2),
        "threshold":          round(float(model.offset_), 6),
        "benign_anomaly_rate":round(float(benign_anomaly_rate), 4),
        "attack_recall":      round(float(attack_recall), 4),
        "benign_specificity": round(float(benign_spec), 4),
        "false_positive_rate":round(float(1 - benign_spec), 4),
        "per_class_detection":per_class,
        "hyperparameters":    IF_PARAMS,
    }
    with open(REPORT_OUT, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[OK] Report saved       -> {REPORT_OUT}")

    print(f"\n{'='*65}")
    print(f"  ✅  Isolation Forest training complete")
    print(f"  Attack recall      : {attack_recall*100:.2f}%")
    print(f"  Benign specificity : {benign_spec*100:.2f}%")
    print(f"{'='*65}\n")

    return bundle


if __name__ == "__main__":
    train()