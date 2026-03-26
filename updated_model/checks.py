import pandas as pd

df = pd.read_csv("data/splits/train.csv")

print("Unique labels:", df["Label"].unique())
print("NaN labels:", df["Label"].isna().sum())
print("Inf labels:", df["Label"].isin([float("inf"), float("-inf")]).sum())