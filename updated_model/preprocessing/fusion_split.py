import pandas as pd
from pathlib import Path

SAMPLED_PATH = "data/processed/sampled.csv"
TEST_PATH    = "data/splits/test.csv"
OUT_PATH     = "data/test_fusion.csv"

print("Loading sampled.csv...")
sampled = pd.read_csv(SAMPLED_PATH)
print("Sampled shape:", sampled.shape)

print("Loading test.csv to exclude already-seen rows...")
test = pd.read_csv(TEST_PATH)
print("Test shape:", test.shape)

label_col = "Label"
sampled[label_col] = sampled[label_col].astype(int)
test[label_col]    = test[label_col].astype(int)

# Exclude rows that are in test.csv using index tracking from step4
# Since step4 uses random_state=42 deterministically, we can exclude
# by finding exact row matches on all feature columns
feature_cols = [c for c in test.columns if c != label_col]
test_index   = set(test[feature_cols].apply(tuple, axis=1))
mask         = ~sampled[feature_cols].apply(tuple, axis=1).isin(test_index)
fresh        = sampled[mask].copy()

print(f"Fresh rows (not in test.csv): {len(fresh):,} / {len(sampled):,}")

benign  = fresh[fresh[label_col] == 0]
attacks = fresh[fresh[label_col] != 0]

print(f"Benign rows : {len(benign):,}")
print(f"Attack rows : {len(attacks):,}")

# Sample 500 benign + up to 125 per attack class
benign_sample = benign.sample(min(500, len(benign)), random_state=42)

attack_parts = []
for cls in sorted(attacks[label_col].unique()):
    rows = attacks[attacks[label_col] == cls]
    n    = min(125, len(rows))
    attack_parts.append(rows.sample(n, random_state=42))
    print(f"  Class {cls}: sampled {n}/{len(rows)}")

attack_sample = pd.concat(attack_parts)

test_df = pd.concat([benign_sample, attack_sample])
test_df = test_df.sample(frac=1, random_state=42).reset_index(drop=True)

print("\nFinal test set:", test_df.shape)
print("\nLabel distribution:")
print(test_df[label_col].value_counts().sort_index())

Path("data").mkdir(exist_ok=True)
test_df.to_csv(OUT_PATH, index=False)
print(f"\n[OK] Test dataset saved -> {OUT_PATH}")