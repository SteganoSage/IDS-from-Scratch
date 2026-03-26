"""
preprocessing/step4_feature_selection_and_split.py
====================================================
Clean rewrite — trains on RAW values from sampled.csv.

What this version does:
  1. Load sampled.csv
  2. Replace inf/-inf with NaN
  3. Stratified train/val/test split
  4. Median imputation (NaN only — does NOT transform valid values)
  5. SMOTE on train only (WebAttack 87 -> 1000)
  6. Feature selection (RF + MI)
  7. Save splits with correct column mapping (fixed bug)
  8. Save features.json with correct medians

What this version does NOT do:
  - No scaling
  - No clipping/capping of valid values
  - No value transformation
  - Raw flow values preserved as-is

This ensures the model learns from real traffic distributions
and will work correctly on real-time C++ capturer output.

Usage:
    python -m preprocessing.step4_feature_selection_and_split
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.impute import SimpleImputer
from imblearn.over_sampling import SMOTE

# ── Paths ─────────────────────────────────────────────────────────────────────
INPUT_PATH   = Path("data/processed/sampled.csv")
SPLITS_DIR   = Path("data/splits")
REPORT_PATH  = Path("data/splits/split_report.json")
FEATURES_CFG = Path("config/features.json")
LABELS_CFG   = Path("config/labels.json")
SPLITS_DIR.mkdir(parents=True, exist_ok=True)

# ── Config ────────────────────────────────────────────────────────────────────
RANDOM_SEED  = 42
TEST_SIZE    = 0.15
VAL_SIZE     = 0.15
SMOTE_TARGETS = {6: 1500}    # Infiltration 36 -> 1500

RF_IMPORTANCE_THRESHOLD = 0.001
MI_THRESHOLD_PERCENTILE = 10
RF_PROBE_ESTIMATORS     = 150
RF_PROBE_DEPTH          = 12


def load_label_config():
    with open(LABELS_CFG) as f:
        return json.load(f)


def print_distribution(y, title, label_names):
    counts = pd.Series(y).value_counts().sort_index()
    total  = len(y)
    print(f"\n  {title} ({total:,} samples)")
    print(f"  {'Class':<8} {'Family':<16} {'Count':>10}  {'%':>7}")
    print(f"  {'─'*48}")
    for cls, cnt in counts.items():
        name = label_names[str(cls)]["name"]
        print(f"  {cls:<8} {name:<16} {cnt:>10,}  ({cnt/total*100:.2f}%)")


def run():
    label_cfg   = load_label_config()
    label_col   = label_cfg["label_column"]
    label_names = label_cfg["label_names"]

    print(f"\n{'='*65}")
    print(f"  FusionIDS - Step 4: Feature Selection + Split (Raw Values)")
    print(f"{'='*65}")

    # ── 1. Load ───────────────────────────────────────────────────────────
    print(f"\n[INFO] Loading {INPUT_PATH}...")
    df = pd.read_csv(INPUT_PATH, low_memory=False)
    print(f"  Shape: {df.shape}")

    y             = df[label_col].values
    X_df          = df.drop(columns=[label_col])
    feature_names = X_df.columns.tolist()

    # Replace inf/-inf with NaN — only change to raw values
    print(f"\n[INFO] Replacing inf values with NaN...")
    inf_count = np.isinf(X_df.values).sum()
    X_df      = X_df.replace([float('inf'), float('-inf')], float('nan'))
    print(f"  Inf values replaced: {inf_count:,}")

    X = X_df.values
    print_distribution(y, "Input distribution", label_names)

    # ── 2. Stratified split ───────────────────────────────────────────────
    print(f"\n[INFO] Splitting — test={TEST_SIZE}, val={VAL_SIZE}...")
    X_tv, X_test, y_tv, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_SEED)

    val_size_adj = VAL_SIZE / (1 - TEST_SIZE)
    X_train, X_val, y_train, y_val = train_test_split(
        X_tv, y_tv, test_size=val_size_adj, stratify=y_tv, random_state=RANDOM_SEED)

    print(f"  Train: {len(X_train):,}  Val: {len(X_val):,}  Test: {len(X_test):,}")

    # ── 3. Fit imputer on train, apply to all splits ──────────────────────
    # Imputer only fills NaN — does NOT touch valid values
    print(f"\n[INFO] Fitting median imputer on train (NaN only)...")
    imputer = SimpleImputer(strategy="median")
    imputer.fit(X_train)
    medians = dict(zip(feature_names, imputer.statistics_.tolist()))

    X_train = imputer.transform(X_train)
    X_val   = imputer.transform(X_val)
    X_test  = imputer.transform(X_test)
    print(f"  Medians computed for {len(medians)} features")

    # ── 4. SMOTE on train only ────────────────────────────────────────────
    train_counts = pd.Series(y_train).value_counts()
    smote_needed = {
        cls: target for cls, target in SMOTE_TARGETS.items()
        if cls in train_counts.index and train_counts[cls] < target
    }

    if smote_needed:
        print(f"\n[INFO] Applying SMOTE...")
        for cls, target in smote_needed.items():
            print(f"  Class {cls}: {train_counts[cls]} -> {target}")
        smote = SMOTE(
            sampling_strategy = smote_needed,
            random_state      = RANDOM_SEED,
            k_neighbors       = min(5, train_counts.get(5, 5) - 1),
        )
        X_train, y_train = smote.fit_resample(X_train, y_train)
        print(f"  Train size after SMOTE: {len(X_train):,}")

    print_distribution(y_train, "Train after SMOTE", label_names)

    # ── 5. Feature selection ──────────────────────────────────────────────
    print(f"\n{'─'*65}")
    print(f"  Feature Selection: RF Importance + Mutual Information")
    print(f"{'─'*65}")

    print(f"\n[INFO] Running RF importance probe...")
    rf = RandomForestClassifier(
        n_estimators=RF_PROBE_ESTIMATORS, max_depth=RF_PROBE_DEPTH,
        class_weight="balanced", n_jobs=-1, random_state=RANDOM_SEED,
    )
    rf.fit(X_train, y_train)
    rf_scores = pd.Series(rf.feature_importances_, index=feature_names)

    print(f"[INFO] Computing Mutual Information scores...")
    mi_raw    = mutual_info_classif(X_train, y_train, discrete_features=False,
                                    random_state=RANDOM_SEED, n_jobs=-1)
    mi_scores = pd.Series(mi_raw, index=feature_names)

    rf_norm  = rf_scores / rf_scores.max()
    mi_norm  = mi_scores / mi_scores.max()
    combined = ((rf_norm + mi_norm) / 2).sort_values(ascending=False)

    mi_threshold = np.percentile(mi_scores.values, MI_THRESHOLD_PERCENTILE)
    keep_rf      = set(rf_scores[rf_scores >= RF_IMPORTANCE_THRESHOLD].index)
    keep_mi      = set(mi_scores[mi_scores >= mi_threshold].index)

    # Sort selected features by combined importance score (descending)
    selected = sorted(keep_rf | keep_mi, key=lambda f: -combined[f])
    dropped  = [f for f in feature_names if f not in selected]

    print(f"\n  Total features : {len(feature_names)}")
    print(f"  Selected       : {len(selected)}")
    print(f"  Dropped        : {len(dropped)}")
    if dropped:
        print(f"  Dropped: {dropped}")

    print(f"\n  Top 10 features:")
    for f in selected[:10]:
        print(f"    {f:<45} combined={combined[f]:.4f}")

    # ── 6. Save splits with CORRECT column mapping ────────────────────────
    # CRITICAL FIX: use rf_scores.index (original CSV order) NOT combined.index
    # combined.index is importance-sorted — using it to index numpy arrays
    # causes completely wrong column mapping (the original bug)
    all_feature_names = list(rf_scores.index)   # original CSV order
    selected_indices  = [all_feature_names.index(f) for f in selected]

    def to_df(X, y):
        df = pd.DataFrame(X[:, selected_indices], columns=selected)
        df[label_col] = y
        return df

    train_df = to_df(X_train, y_train)
    val_df   = to_df(X_val,   y_val)
    test_df  = to_df(X_test,  y_test)

    train_df.to_csv(SPLITS_DIR / "train.csv", index=False)
    val_df.to_csv(  SPLITS_DIR / "val.csv",   index=False)
    test_df.to_csv( SPLITS_DIR / "test.csv",  index=False)

    print(f"\n[OK] train.csv  -> {len(train_df):,} rows x {len(selected)} features")
    print(f"[OK] val.csv    -> {len(val_df):,} rows x {len(selected)} features")
    print(f"[OK] test.csv   -> {len(test_df):,} rows x {len(selected)} features")

    # Verify distributions are preserved
    print(f"\n  Flow Duration verification:")
    for cls in [0,1,2,3,4]:
        rows = test_df[test_df[label_col]==cls]['Flow Duration']
        print(f"    Class {cls}: mean={rows.mean():.1f}  median={rows.median():.1f}  max={rows.max():.1f}")

    # ── 7. Save features.json ─────────────────────────────────────────────
    features_cfg = {
        "features":         selected,
        "n_features":       len(selected),
        "dropped_features": dropped,
        "imputer_medians":  {f: medians[f] for f in selected if f in medians},
        "selection_method": "RF_importance + Mutual_Information (union)",
        "rf_importance_threshold": RF_IMPORTANCE_THRESHOLD,
        "mi_threshold_percentile": MI_THRESHOLD_PERCENTILE,
    }
    with open(FEATURES_CFG, "w") as f:
        json.dump(features_cfg, f, indent=2)
    print(f"\n[OK] features.json saved ({len(selected)} features)")

    # ── 8. Save report ────────────────────────────────────────────────────
    report = {
        "train_rows": len(train_df), "val_rows": len(val_df), "test_rows": len(test_df),
        "n_features": len(selected), "dropped_features": dropped,
        "smote_applied": SMOTE_TARGETS,
        "train_distribution": train_df[label_col].value_counts().sort_index().to_dict(),
        "test_distribution":  test_df[label_col].value_counts().sort_index().to_dict(),
    }
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{'='*65}")
    print(f"  ✅  Step 4 complete — raw values preserved")
    print(f"  Next: retrain all signature + anomaly models")
    print(f"{'='*65}\n")


if __name__ == "__main__":
    run()