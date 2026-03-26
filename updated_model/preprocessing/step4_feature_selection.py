import pandas as pd
import numpy as np
import json
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import VarianceThreshold


TRAIN_PATH = "data/splits/train.csv"
VAL_PATH   = "data/splits/val.csv"
TEST_PATH  = "data/splits/test.csv"

OUTPUT_DIR = Path("data/splits")

FEATURES_CFG = Path("config/features.json")

LABEL_COL = "Label"

CORR_THRESHOLD = 0.95

RF_IMPORTANCE_THRESHOLD = 0.001


print("Loading datasets...")

train = pd.read_csv(TRAIN_PATH)
val   = pd.read_csv(VAL_PATH)
test  = pd.read_csv(TEST_PATH)

print("Train shape:", train.shape)

y_train = train[LABEL_COL]
X_train = train.drop(columns=[LABEL_COL])

X_val = val.drop(columns=[LABEL_COL])
X_test = test.drop(columns=[LABEL_COL])


feature_names = X_train.columns.tolist()


# ------------------------------------------------
# 1. Low variance filter
# ------------------------------------------------

print("\nRemoving low variance features")

var_filter = VarianceThreshold(threshold=0.0001)

var_filter.fit(X_train)

kept_features = X_train.columns[var_filter.get_support()].tolist()

print("Remaining after variance filter:", len(kept_features))


X_train = X_train[kept_features]
X_val = X_val[kept_features]
X_test = X_test[kept_features]


# ------------------------------------------------
# 2. Correlation filter
# ------------------------------------------------

print("\nRemoving highly correlated features")

corr_matrix = X_train.corr().abs()

upper = corr_matrix.where(
    np.triu(np.ones(corr_matrix.shape), k=1).astype(bool)
)

to_drop = [
    column for column in upper.columns
    if any(upper[column] > CORR_THRESHOLD)
]

print("Correlated features removed:", len(to_drop))

X_train = X_train.drop(columns=to_drop)
X_val = X_val.drop(columns=to_drop)
X_test = X_test.drop(columns=to_drop)


# ------------------------------------------------
# 3. Random Forest importance
# ------------------------------------------------

print("\nRunning Random Forest importance")

rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    class_weight="balanced",
    n_jobs=-1,
    random_state=42
)

rf.fit(X_train, y_train)

importances = pd.Series(
    rf.feature_importances_,
    index=X_train.columns
)

selected = importances[
    importances > RF_IMPORTANCE_THRESHOLD
].index.tolist()

print("Selected features:", len(selected))


X_train = X_train[selected]
X_val = X_val[selected]
X_test = X_test[selected]


# ------------------------------------------------
# Save datasets
# ------------------------------------------------

def save_split(X, y, name):

    df = X.copy()
    df[LABEL_COL] = y

    path = OUTPUT_DIR / f"{name}_selected.csv"

    df.to_csv(path, index=False)

    print("Saved", path)


save_split(X_train, y_train, "train")
save_split(X_val, val[LABEL_COL], "val")
save_split(X_test, test[LABEL_COL], "test")


# ------------------------------------------------
# Save features.json
# ------------------------------------------------

features_cfg = {

    "features": selected,
    "n_features": len(selected),

    "selection_method": "variance + correlation + RF importance"
}

FEATURES_CFG.parent.mkdir(exist_ok=True)

with open(FEATURES_CFG, "w") as f:

    json.dump(features_cfg, f, indent=2)

print("\nSaved features.json")


print("\nFinal feature count:", len(selected))