"""
training/train_rf.py
=====================
Trains the Random Forest signature classifier on CIC-IDS 2018.

Reads:  data/splits/train.csv
        data/splits/val.csv
        data/splits/test.csv
        config/features.json
        config/labels.json

Saves:  artifacts/rf_v1.pkl
        artifacts/rf_v1_report.json

Usage:
    python -m training.train_rf
"""

import json
import time
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
)

# ── Paths ─────────────────────────────────────────────────────────────────────
TRAIN_PATH   = Path("data/splits/train.csv")
VAL_PATH     = Path("data/splits/val.csv")
TEST_PATH    = Path("data/splits/test.csv")
FEATURES_CFG = Path("config/features.json")
LABELS_CFG   = Path("config/labels.json")
ARTIFACT_DIR = Path("artifacts")
ARTIFACT_DIR.mkdir(exist_ok=True)

MODEL_OUT    = ARTIFACT_DIR / "rf_v1.pkl"
REPORT_OUT   = ARTIFACT_DIR / "rf_v1_report.json"

# ── RF hyperparameters ────────────────────────────────────────────────────────
# Tuned for CIC-IDS 2018:
#   - n_estimators=300: enough trees for stable predictions on 7 classes
#   - max_depth=25: deep enough to capture complex patterns
#   - min_samples_leaf=3: prevents overfitting to SMOTE'd synthetic rows
#   - class_weight=balanced: handles remaining class imbalance after sampling
#   - max_features=sqrt: standard for classification, reduces correlation between trees
RF_PARAMS = dict(
    n_estimators  = 300,
    max_depth     = 25,
    min_samples_leaf = 3,
    max_features  = "sqrt",
    class_weight  = "balanced",
    n_jobs        = -1,
    random_state  = 42,
)

RANDOM_SEED = 42


def load_configs():
    with open(FEATURES_CFG) as f:
        features = json.load(f)["features"]
    with open(LABELS_CFG) as f:
        label_cfg = json.load(f)
    return features, label_cfg


def load_split(path, features, label_col):
    df = pd.read_csv(path, low_memory=False)
    X  = df[features].values
    y  = df[label_col].values
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
        target_names  = target_names,
        digits        = 4,
        zero_division = 0,
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
    print(f"  FusionIDS - Phase 2: Train Random Forest Signature Model")
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
    # Note: RF doesn't use a val set during training (no early stopping)
    # Val set is used for post-training evaluation only
    print(f"\n[INFO] Training Random Forest...")
    print(f"  Params: {RF_PARAMS}\n")

    model = RandomForestClassifier(**RF_PARAMS)

    t0 = time.time()
    model.fit(X_train, y_train)
    train_time = time.time() - t0

    print(f"  Training time : {train_time:.1f}s")

    # ── Evaluate on val ───────────────────────────────────────────────────
    print(f"\n[INFO] Evaluating on validation set...")
    y_val_pred = model.predict(X_val)
    y_val_prob = model.predict_proba(X_val)
    val_acc, _ = print_evaluation(y_val, y_val_pred, y_val_prob, label_names, "Validation")

    # ── Evaluate on test ──────────────────────────────────────────────────
    print(f"\n[INFO] Evaluating on test set...")
    y_test_pred = model.predict(X_test)
    y_test_prob = model.predict_proba(X_test)
    test_acc, test_cm = print_evaluation(y_test, y_test_pred, y_test_prob, label_names, "Test")

    # ── Feature importance (top 20) ───────────────────────────────────────
    importances = pd.Series(model.feature_importances_, index=features)
    importances = importances.sort_values(ascending=False)

    print(f"\n  Top 20 Feature Importances (Random Forest):")
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
        "model":          "RandomForest",
        "artifact":       str(MODEL_OUT),
        "n_features":     len(features),
        "n_classes":      n_classes,
        "train_rows":     len(X_train),
        "val_rows":       len(X_val),
        "test_rows":      len(X_test),
        "train_time_sec": round(train_time, 2),
        "val_accuracy":   round(float(val_acc),  6),
        "test_accuracy":  round(float(test_acc), 6),
        "hyperparameters": RF_PARAMS,
        "test_confusion_matrix": test_cm.tolist(),
        "top_20_features": importances.head(20).to_dict(),
    }
    with open(REPORT_OUT, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"[OK] Report saved -> {REPORT_OUT}")
    print(f"\n{'='*65}")
    print(f"  ✅  Random Forest training complete")
    print(f"  Val  accuracy : {val_acc*100:.4f}%")
    print(f"  Test accuracy : {test_acc*100:.4f}%")
    print(f"{'='*65}\n")

    return model


if __name__ == "__main__":
    train()