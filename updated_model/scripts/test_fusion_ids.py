import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import json
import warnings
import pandas as pd
import numpy as np
from tqdm import tqdm
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score

warnings.filterwarnings("ignore")

from inference.fusion_ids import FusionIDS


TEST_PATH = "data/test_fusion.csv"
FEATURES_PATH = "config/features.json"
LABELS_PATH = "config/labels.json"

SAMPLE_SIZE = 1000


def load_configs():

    with open(FEATURES_PATH) as f:
        features = json.load(f)["features"]

    with open(LABELS_PATH) as f:
        label_cfg = json.load(f)

    return features, label_cfg


def evaluate():

    print("\n============================================================")
    print(" FusionIDS Hybrid IDS Evaluation")
    print("============================================================\n")

    features, label_cfg = load_configs()
    label_col = label_cfg["label_column"]
    label_names = label_cfg["label_names"]

    df = pd.read_csv(TEST_PATH)

    # Random sample for quick testing
    df = df.sample(SAMPLE_SIZE, random_state=42)

    print("Sample size:", len(df))

    ids = FusionIDS()

    y_true = []
    y_pred = []

    fusion_stats = {
        "Signature+Anomaly": 0,
        "SignatureOnly": 0,
        "AnomalyOnly": 0,
        "None": 0
    }

    per_class = {}

    for row in tqdm(df.to_dict("records")):

        flow = {f: row[f] for f in features}
        true_label = int(row[label_col])

        result = ids.predict(flow)
        alert = result["alert"]

        y_true.append(true_label)

        if alert is None:
            y_pred.append(0)
            fusion_stats["None"] += 1
        else:
            y_pred.append(1)
            fusion_stats[alert["fusion"]] += 1

        # Per class stats
        if true_label != 0:
            name = label_names[str(true_label)]["name"]

            if name not in per_class:
                per_class[name] = {"total": 0, "detected": 0}

            per_class[name]["total"] += 1

            if alert is not None:
                per_class[name]["detected"] += 1

    # Convert labels to binary
    y_true_bin = [1 if y != 0 else 0 for y in y_true]

    # Metrics
    accuracy = accuracy_score(y_true_bin, y_pred)
    precision = precision_score(y_true_bin, y_pred)
    recall = recall_score(y_true_bin, y_pred)
    f1 = f1_score(y_true_bin, y_pred)

    cm = confusion_matrix(y_true_bin, y_pred)
    tn, fp, fn, tp = cm.ravel()

    specificity = tn / (tn + fp)
    fpr = fp / (fp + tn)

    print("\n================ IDS METRICS =================\n")

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

    print("\nFusion Breakdown")
    print("----------------")

    total = sum(fusion_stats.values())

    for k, v in fusion_stats.items():
        pct = v / total * 100
        print(f"{k:<20} {v:>5} ({pct:.2f}%)")

    print("\nPer-Attack Detection")
    print("--------------------")

    for name, stats in per_class.items():

        rate = stats["detected"] / stats["total"]

        print(
            f"{name:<15} "
            f"{stats['detected']:>4}/{stats['total']:<4} "
            f"({rate*100:.2f}%)"
        )

    print("\n============================================================\n")


if __name__ == "__main__":
    evaluate()