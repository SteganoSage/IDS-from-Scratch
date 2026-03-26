import pandas as pd
from pathlib import Path
import json

INPUT = "data/processed/cleaned2017.csv"
OUTPUT = "data/processed/final_2017.csv"

LABELS_CFG = Path("config/labels.json")

print("Loading dataset...")
df = pd.read_csv(INPUT, low_memory=False)

print("\nOriginal distribution:")
print(df["Label"].value_counts())

# ---------------------------------------------------
# Label mapping
# ---------------------------------------------------

label_map = {

    "BENIGN":0,

    "FTP-Patator":1,
    "SSH-Patator":1,
    "BruteForce":1,

    "DoS Hulk":2,
    "DoS GoldenEye":2,
    "DoS slowloris":2,
    "DoS slowhttptest":2,
    "DoS":2,

    "PortScan":3,

    "Bot":4,

    "Web Attack - Brute Force":5,
    "Web Attack - XSS":5,
    "Web Attack - Sql Injection":5,
    "WebAttack":5,

    "Infiltration":6
}

df["Label"] = df["Label"].map(label_map)

# ---------------------------------------------------
# Verify encoding
# ---------------------------------------------------

print("\nEncoded distribution:")
print(df["Label"].value_counts())

# ---------------------------------------------------
# Save dataset
# ---------------------------------------------------

df.to_csv(OUTPUT, index=False)

print("\nSaved dataset ->", OUTPUT)

# ---------------------------------------------------
# Save labels.json
# ---------------------------------------------------

labels_cfg = {

    "label_column": "Label",

    "label_names": {

        "0": {"name":"Benign"},
        "1": {"name":"BruteForce"},
        "2": {"name":"DoS"},
        "3": {"name":"PortScan"},
        "4": {"name":"Bot"},
        "5": {"name":"WebAttack"},
        "6": {"name":"Infiltration"}

    }

}

LABELS_CFG.parent.mkdir(exist_ok=True)

with open(LABELS_CFG, "w") as f:
    json.dump(labels_cfg, f, indent=2)

print("Saved label config ->", LABELS_CFG)