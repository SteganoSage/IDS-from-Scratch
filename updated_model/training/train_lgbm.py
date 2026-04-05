"""
training/train_lgbm.py — FIXED version
FIX: Pass DataFrame (not .values) to model.fit() so feature names
     are preserved in model.feature_names_in_
"""

import json, time, joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import lightgbm as lgb

TRAIN_PATH   = Path("data/splits/train.csv")
VAL_PATH     = Path("data/splits/val.csv")
TEST_PATH    = Path("data/splits/test.csv")
FEATURES_CFG = Path("config/features.json")
LABELS_CFG   = Path("config/labels.json")
ARTIFACT_DIR = Path("artifacts")
ARTIFACT_DIR.mkdir(exist_ok=True)
MODEL_OUT    = ARTIFACT_DIR / "lgbm_v1.pkl"
REPORT_OUT   = ARTIFACT_DIR / "lgbm_v1_report.json"

LGBM_PARAMS = dict(
    n_estimators=500, num_leaves=127, max_depth=8,
    learning_rate=0.1, subsample=0.85, subsample_freq=1,
    colsample_bytree=0.75, min_child_samples=20,
    reg_alpha=0.1, reg_lambda=1.5, class_weight="balanced",
    n_jobs=-1, random_state=42, verbose=-1,
)
EARLY_STOPPING_ROUNDS = 20

def load_configs():
    with open(FEATURES_CFG) as f: features = json.load(f)["features"]
    with open(LABELS_CFG)   as f: label_cfg = json.load(f)
    return features, label_cfg

def load_split(path, features, label_col):
    df = pd.read_csv(path, low_memory=False)
    # ── FIX: Keep as DataFrame — preserves column names ──────────────────
    # Old: X = df[features].values  ← strips names → Column_0, Column_1...
    X  = df[features]               # ← DataFrame with real feature names
    y  = df[label_col].values
    return X, y

def print_evaluation(y_true, y_pred, y_prob, label_names, split_name):
    acc     = accuracy_score(y_true, y_pred)
    cm      = confusion_matrix(y_true, y_pred)
    classes = sorted(np.unique(y_true))
    target_names = [label_names[str(c)]["name"] for c in classes]
    print(f"\n{'='*65}\n  {split_name} — Accuracy: {acc*100:.4f}%\n{'='*65}")
    print(classification_report(y_true, y_pred, target_names=target_names,
                                 digits=4, zero_division=0))
    return acc, cm

def train():
    features, label_cfg = load_configs()
    label_col   = label_cfg["label_column"]
    label_names = label_cfg["label_names"]

    print(f"[INFO] Loading splits...")
    X_train, y_train = load_split(TRAIN_PATH, features, label_col)
    X_val,   y_val   = load_split(VAL_PATH,   features, label_col)
    X_test,  y_test  = load_split(TEST_PATH,  features, label_col)
    print(f"  Train: {X_train.shape} | Val: {X_val.shape} | Test: {X_test.shape}")
    print(f"  First 3 feature names: {list(X_train.columns[:3])}")

    model = lgb.LGBMClassifier(**LGBM_PARAMS)
    t0    = time.time()
    model.fit(
        X_train, y_train,
        eval_set  = [(X_val, y_val)],
        callbacks = [
            lgb.early_stopping(EARLY_STOPPING_ROUNDS, verbose=True),
            lgb.log_evaluation(period=50),
        ],
    )
    print(f"  Trained in {time.time()-t0:.1f}s | Best iter: {model.best_iteration_}")
    print(f"  Saved feature names (first 3): {list(model.feature_names_in_[:3])}")

    y_val_pred  = model.predict(X_val)
    y_val_prob  = model.predict_proba(X_val)
    val_acc, _  = print_evaluation(y_val,  y_val_pred, y_val_prob,  label_names, "Validation")

    y_test_pred      = model.predict(X_test)
    y_test_prob      = model.predict_proba(X_test)
    test_acc, test_cm = print_evaluation(y_test, y_test_pred, y_test_prob, label_names, "Test")

    joblib.dump(model, MODEL_OUT)
    print(f"\n[OK] Model saved → {MODEL_OUT}")

    report = {
        "model": "LightGBM", "n_features": len(features),
        "best_iteration": int(model.best_iteration_),
        "val_accuracy": round(float(val_acc), 6),
        "test_accuracy": round(float(test_acc), 6),
        "hyperparameters": LGBM_PARAMS,
        "test_confusion_matrix": test_cm.tolist(),
    }
    with open(REPORT_OUT, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[OK] Report saved → {REPORT_OUT}")
    print(f"\n✅ Val: {val_acc*100:.4f}% | Test: {test_acc*100:.4f}%")

if __name__ == "__main__":
    train()