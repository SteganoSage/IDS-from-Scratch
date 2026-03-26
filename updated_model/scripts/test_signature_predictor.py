import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import json
import warnings
import pandas as pd
import numpy as np
from tqdm import tqdm
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

warnings.filterwarnings("ignore")

from inference.signature_predictor import SignaturePredictor


TEST_PATH     = "data/test_fusion.csv"
FEATURES_PATH = "config/features.json"
LABELS_PATH   = "config/labels.json"

SAMPLE_SIZE = 1000


def load_configs():
    with open(FEATURES_PATH) as f:
        features = json.load(f)["features"]
    with open(LABELS_PATH) as f:
        label_cfg = json.load(f)
    return features, label_cfg


def evaluate():
    print("\n=================================================")
    print(" Signature IDS Model Evaluation")
    print("=================================================\n")

    features, label_cfg = load_configs()
    label_col   = label_cfg["label_column"]
    label_names = label_cfg["label_names"]

    df = pd.read_csv(TEST_PATH)
    df = df.sample(min(SAMPLE_SIZE, len(df)), random_state=42)

    print("Sample size:", len(df))

    model = SignaturePredictor()

    y_true    = []
    y_pred    = []
    per_class = {}

    for row in tqdm(df.to_dict("records")):
        flow       = {f: row[f] for f in features if f in row}
        true_label = int(row[label_col])

        result = model.predict(flow)
        pred   = 0 if result is None else result["label_id"]

        y_true.append(true_label)
        y_pred.append(pred)

        if true_label != 0:
            name = label_names[str(true_label)]["name"]
            if name not in per_class:
                per_class[name] = {"total": 0, "detected": 0}
            per_class[name]["total"] += 1
            if pred != 0:
                per_class[name]["detected"] += 1

    # Binary metrics
    y_true_bin = [1 if y != 0 else 0 for y in y_true]
    y_pred_bin = [1 if y != 0 else 0 for y in y_pred]

    accuracy  = accuracy_score(y_true_bin, y_pred_bin)
    precision = precision_score(y_true_bin, y_pred_bin, zero_division=0)
    recall    = recall_score(y_true_bin, y_pred_bin, zero_division=0)
    f1        = f1_score(y_true_bin, y_pred_bin, zero_division=0)

    cm = confusion_matrix(y_true_bin, y_pred_bin)
    tn, fp, fn, tp = cm.ravel()
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    fpr         = fp / (fp + tn) if (fp + tn) > 0 else 0

    print("\n================ RESULTS ================\n")
    print(f"Accuracy           : {accuracy*100:.2f}%")
    print(f"Precision          : {precision*100:.2f}%")
    print(f"Recall (Attack DR) : {recall*100:.2f}%")
    print(f"F1 Score           : {f1*100:.2f}%")
    print(f"Benign Specificity : {specificity*100:.2f}%")
    print(f"False Positive Rate: {fpr*100:.2f}%")

    print("\nConfusion Matrix")
    print("----------------")
    print(f"TP: {tp}  FP: {fp}")
    print(f"FN: {fn}  TN: {tn}")

    print("\nPer Attack Detection")
    print("--------------------")
    for name, stats in per_class.items():
        rate = stats["detected"] / stats["total"] if stats["total"] > 0 else 0
        print(f"{name:<16} {stats['detected']:>4}/{stats['total']:<4} ({rate*100:.2f}%)")

    print("\n=========================================\n")


if __name__ == "__main__":
    evaluate()