"""
training/train_xgb.py
======================
Trains the XGBoost signature classifier on CIC-IDS 2018.

Reads:  data/splits/train.csv  (924,999 rows, 68 features)
        data/splits/val.csv    (187,513 rows — used for early stopping)
        data/splits/test.csv   (187,514 rows — final evaluation)
        config/features.json   (68 selected features)
        config/labels.json     (7 family classes)

Saves:  artifacts/xgb_v1.pkl
        artifacts/xgb_v1_report.json

Usage:
    python -m training.train_xgb
"""

import json
import time
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
)
import xgboost as xgb

# ── Paths ─────────────────────────────────────────────────────────────────────
TRAIN_PATH   = Path("data/splits/train.csv")
VAL_PATH     = Path("data/splits/val.csv")
TEST_PATH    = Path("data/splits/test.csv")
FEATURES_CFG = Path("config/features.json")
LABELS_CFG   = Path("config/labels.json")
ARTIFACT_DIR = Path("artifacts")
ARTIFACT_DIR.mkdir(exist_ok=True)

MODEL_OUT    = ARTIFACT_DIR / "xgb_v1.pkl"
REPORT_OUT   = ARTIFACT_DIR / "xgb_v1_report.json"

# ── XGBoost hyperparameters ───────────────────────────────────────────────────
# Tuned for CIC-IDS 2018 7-class problem:
#   - max_depth=8: deep enough for complex attack patterns
#   - subsample + colsample: reduce overfitting on dominant classes
#   - reg_alpha (L1): helps with correlated flow features
#   - early_stopping_rounds: stops when val loss plateaus
XGB_PARAMS = dict(
    n_estimators          = 500,
    max_depth             = 8,
    learning_rate         = 0.1,
    subsample             = 0.85,
    colsample_bytree      = 0.75,
    min_child_weight      = 5,
    gamma                 = 0.1,
    reg_alpha             = 0.1,
    reg_lambda            = 1.5,
    eval_metric           = "mlogloss",
    early_stopping_rounds = 20,
    n_jobs                = -1,
    random_state          = 42,
    tree_method           = "hist",   # fastest for large datasets
)

# Class weights removed — relying on increased Infiltration sample cap (200k)
# and SMOTE for class balance instead of weight penalization.
# Weights were too aggressive and caused Benign recall to drop significantly.

RANDOM_SEED = 42


def load_configs():
    with open(FEATURES_CFG) as f:
        features = json.load(f)["features"]
    with open(LABELS_CFG) as f:
        label_cfg = json.load(f)
    return features, label_cfg


def load_split(path, features, label_col):

    df = pd.read_csv(path, low_memory=False)

    # Ensure feature order
    X = df[features].values.astype(np.float32)

    # Force integer labels
    y = df[label_col].values.astype(np.int32)

    # Safety checks
    if np.isnan(X).any():
        raise ValueError(f"{path} contains NaN features")

    if np.isnan(y).any():
        raise ValueError(f"{path} contains NaN labels")

    if np.isinf(X).any():
        raise ValueError(f"{path} contains Inf features")

    return X, y


def print_evaluation(y_true, y_pred, y_prob, label_names, split_name):
    print(f"\n{'='*65}")
    print(f"  {split_name} Evaluation")
    print(f"{'='*65}")

    # ── Overall accuracy ──────────────────────────────────────────────────
    acc = accuracy_score(y_true, y_pred)
    print(f"\n  Overall Accuracy: {acc*100:.4f}%")

    # ── Per-class accuracy ────────────────────────────────────────────────
    cm = confusion_matrix(y_true, y_pred)
    print(f"\n  Per-Class Accuracy:")
    print(f"  {'Class':<8} {'Family':<16} {'Correct':>10}  {'Total':>10}  {'Acc':>8}")
    print(f"  {'─'*58}")
    classes = sorted(np.unique(y_true))
    for i, cls in enumerate(classes):
        name    = label_names[str(cls)]["name"]
        total   = cm[i].sum()
        correct = cm[i][i]
        cls_acc = correct / total * 100 if total > 0 else 0
        print(f"  {cls:<8} {name:<16} {correct:>10,}  {total:>10,}  {cls_acc:>7.2f}%")

    # ── Classification report ─────────────────────────────────────────────
    target_names = [label_names[str(c)]["name"] for c in classes]
    print(f"\n  Classification Report:")
    print(classification_report(
        y_true, y_pred,
        target_names = target_names,
        digits       = 4,
        zero_division= 0,
    ))

    # ── Confusion matrix ──────────────────────────────────────────────────
    print(f"  Confusion Matrix:")
    print(f"  (rows=actual, cols=predicted)\n")
    header = "  " + "".join(f"{c:>8}" for c in classes)
    print(header)
    for i, cls in enumerate(classes):
        row = "  " + f"{cls:<4}" + "".join(f"{cm[i][j]:>8}" for j in range(len(classes)))
        print(row)

    return acc, cm


def train():
    features, label_cfg = load_configs()
    label_col   = label_cfg["label_column"]
    label_names = label_cfg["label_names"]
    n_classes   = len(label_names)

    print(f"\n{'='*65}")
    print(f"  FusionIDS - Phase 2: Train XGBoost Signature Model")
    print(f"  Features : {len(features)}")
    print(f"  Classes  : {n_classes}")
    print(f"{'='*65}\n")

    # ── Load splits ───────────────────────────────────────────────────────
    print("[INFO] Loading splits...")
    X_train, y_train = load_split(TRAIN_PATH, features, label_col)
    X_val,   y_val   = load_split(VAL_PATH,   features, label_col)
    X_test,  y_test  = load_split(TEST_PATH,  features, label_col)

    print(f"  Train : {X_train.shape}")
    print(f"  Val   : {X_val.shape}")
    print(f"  Test  : {X_test.shape}")

    # ── Train ─────────────────────────────────────────────────────────────
    print(f"\n[INFO] Training XGBoost...")
    print(f"  Params: {XGB_PARAMS}\n")

    model = xgb.XGBClassifier(**XGB_PARAMS)

    t0 = time.time()
    model.fit(
        X_train, y_train,
        eval_set = [(X_val, y_val)],
        verbose  = 50,
    )
    train_time = time.time() - t0

    print(f"\n  Training time    : {train_time:.1f}s")
    print(f"  Best iteration   : {model.best_iteration}")

    # ── Evaluate on val ───────────────────────────────────────────────────
    y_val_pred = model.predict(X_val)
    y_val_prob = model.predict_proba(X_val)
    val_acc, _ = print_evaluation(y_val, y_val_pred, y_val_prob, label_names, "Validation")

    # ── Evaluate on test ──────────────────────────────────────────────────
    y_test_pred = model.predict(X_test)
    y_test_prob = model.predict_proba(X_test)
    test_acc, test_cm = print_evaluation(y_test, y_test_pred, y_test_prob, label_names, "Test")

    # ── Feature importance (top 20) ───────────────────────────────────────
    importances = pd.Series(model.feature_importances_, index=features)
    importances = importances.sort_values(ascending=False)

    print(f"\n  Top 20 Feature Importances (XGBoost):")
    print(f"  {'Feature':<45} {'Importance':>12}")
    print(f"  {'─'*60}")
    for feat, imp in importances.head(20).items():
        bar = "█" * int(imp / importances.max() * 25)
        print(f"  {feat:<45} {imp:>10.5f}  {bar}")

    # ── Save model ────────────────────────────────────────────────────────
    joblib.dump(model, MODEL_OUT)
    print(f"\n[OK] Model saved -> {MODEL_OUT}")

    # ── Save report ───────────────────────────────────────────────────────
    report = {
        "model":          "XGBoost",
        "artifact":       str(MODEL_OUT),
        "n_features":     len(features),
        "n_classes":      n_classes,
        "train_rows":     len(X_train),
        "val_rows":       len(X_val),
        "test_rows":      len(X_test),
        "best_iteration": int(model.best_iteration),
        "train_time_sec": round(train_time, 2),
        "val_accuracy":   round(float(val_acc),  6),
        "test_accuracy":  round(float(test_acc), 6),
        "hyperparameters": XGB_PARAMS,
        "test_confusion_matrix": test_cm.tolist(),
        "top_20_features": importances.head(20).to_dict(),
    }
    with open(REPORT_OUT, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"[OK] Report saved -> {REPORT_OUT}")
    print(f"\n{'='*65}")
    print(f"  ✅  XGBoost training complete")
    print(f"  Val  accuracy : {val_acc*100:.4f}%")
    print(f"  Test accuracy : {test_acc*100:.4f}%")
    print(f"{'='*65}\n")

    return model


if __name__ == "__main__":
    train()