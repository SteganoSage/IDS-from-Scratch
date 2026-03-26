import pandas as pd
import numpy as np
import json
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from imblearn.over_sampling import SMOTE


# --------------------------------------------------
# Paths
# --------------------------------------------------

INPUT = "data/processed/final_2017.csv"

OUTPUT_DIR = Path("data/splits")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

FEATURES_CFG = Path("config/features.json")

LABEL_COL = "Label"


# --------------------------------------------------
# Config
# --------------------------------------------------

TEST_SIZE = 0.15
VAL_SIZE = 0.15

RANDOM_SEED = 42

SMOTE_TARGET = {6: 1500}


# --------------------------------------------------
# Load dataset
# --------------------------------------------------

print("Loading dataset...")

df = pd.read_csv(INPUT, low_memory=False)

print("\nDataset shape:", df.shape)

# replace inf values
df = df.replace([np.inf, -np.inf], np.nan)

y = df[LABEL_COL]
X = df.drop(columns=[LABEL_COL])

feature_names = X.columns.tolist()

print("\nOriginal distribution:")
print(y.value_counts())


# --------------------------------------------------
# Train/Test split
# --------------------------------------------------

X_tv, X_test, y_tv, y_test = train_test_split(
    X,
    y,
    test_size=TEST_SIZE,
    stratify=y,
    random_state=RANDOM_SEED
)

# --------------------------------------------------
# Train/Val split
# --------------------------------------------------

val_size_adj = VAL_SIZE / (1 - TEST_SIZE)

X_train, X_val, y_train, y_val = train_test_split(
    X_tv,
    y_tv,
    test_size=val_size_adj,
    stratify=y_tv,
    random_state=RANDOM_SEED
)

print("\nSplit sizes")

print("Train:", len(X_train))
print("Val  :", len(X_val))
print("Test :", len(X_test))


# --------------------------------------------------
# Impute missing values (train only)
# --------------------------------------------------

print("\nFitting median imputer...")

imputer = SimpleImputer(strategy="median")

imputer.fit(X_train)

X_train = imputer.transform(X_train)
X_val = imputer.transform(X_val)
X_test = imputer.transform(X_test)

medians = dict(zip(feature_names, imputer.statistics_))


# --------------------------------------------------
# SMOTE oversample only class 6
# --------------------------------------------------

print("\nTrain before SMOTE:")
print(y_train.value_counts())

train_counts = y_train.value_counts()

smote_strategy = {}

if 6 in train_counts and train_counts[6] < SMOTE_TARGET[6]:

    smote_strategy[6] = SMOTE_TARGET[6]

if smote_strategy:

    print("\nApplying SMOTE for class 6")

    smote = SMOTE(
        sampling_strategy=smote_strategy,
        random_state=RANDOM_SEED,
        k_neighbors=min(5, train_counts[6] - 1)
    )

    X_train, y_train = smote.fit_resample(X_train, y_train)

print("\nTrain after SMOTE:")
print(pd.Series(y_train).value_counts())


# --------------------------------------------------
# Save splits
# --------------------------------------------------

def save_split(X, y, name):

    df_out = pd.DataFrame(X, columns=feature_names)

    df_out[LABEL_COL] = y

    path = OUTPUT_DIR / f"{name}.csv"

    df_out.to_csv(path, index=False)

    print(f"Saved {name}.csv -> {len(df_out)} rows")


save_split(X_train, y_train, "train")
save_split(X_val, y_val, "val")
save_split(X_test, y_test, "test")


# --------------------------------------------------
# Save split report
# --------------------------------------------------

report = {

    "train_rows": len(X_train),
    "val_rows": len(X_val),
    "test_rows": len(X_test),

    "train_distribution_after_smote":
        pd.Series(y_train).value_counts().to_dict(),

    "test_distribution":
        y_test.value_counts().to_dict()
}

with open(OUTPUT_DIR / "split_report.json", "w") as f:
    json.dump(report, f, indent=2)


# --------------------------------------------------
# Save imputer medians
# --------------------------------------------------

features_cfg = {

    "features": feature_names,
    "n_features": len(feature_names),

    "imputer_medians": medians
}

FEATURES_CFG.parent.mkdir(exist_ok=True)

with open(FEATURES_CFG, "w") as f:
    json.dump(features_cfg, f, indent=2)


print("\nSaved features.json with medians")

print("\nStep 3 completed successfully.")