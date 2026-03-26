"""
preprocessing/step2_clean.py
=============================
Cleans the merged combined_raw.csv in chunks (16M rows - never loads fully).

What this step does:
  1. Drop junk rows where Label == "Label" (59 duplicate header rows)
  2. Drop metadata columns that are not network flow features
  3. Replace inf / -inf with NaN (common in Flow Byts/s, Flow Pkts/s)
  4. Map raw label strings -> 7 family class IDs using config/labels.json
  5. Drop rows with unmapped / unknown labels
  6. Cast all feature columns to float32 (halves memory vs float64)
  7. Save to data/processed/cleaned.csv

Usage:
    python -m preprocessing.step2_clean

Input:
    data/processed/combined_raw.csv   (output of step1_merge.py)
    config/labels.json

Output:
    data/processed/cleaned.csv
    data/processed/clean_report.json
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
INPUT_PATH   = Path("data/processed/combined_raw.csv")
OUTPUT_PATH  = Path("data/processed/cleaned.csv")
REPORT_PATH  = Path("data/processed/clean_report.json")
LABELS_CFG   = Path("config/labels.json")

# ── Chunk size ────────────────────────────────────────────────────────────────
CHUNK_SIZE = 50_000

# ── Columns to drop — metadata, not flow features ────────────────────────────
# Dst Port  : network topology info, not behaviour
# Protocol  : low cardinality, often redundant with flow features
# Timestamp : time of capture, causes data leakage if kept
METADATA_COLS = ["Dst Port", "Protocol", "Timestamp"]


def load_label_config():
    with open(LABELS_CFG) as f:
        return json.load(f)


def clean():
    label_cfg  = load_label_config()
    label_map  = label_cfg["label_map"]
    junk_labels = label_cfg["junk_labels"]   # ["Label"]
    label_col  = label_cfg["label_column"]   # "Label"

    if not INPUT_PATH.exists():
        raise FileNotFoundError(
            f"\n❌  {INPUT_PATH} not found."
            f"\n    Run step1_merge.py first."
        )

    print(f"\n{'='*65}")
    print(f"  FusionIDS - Step 2: Clean  (chunked, {CHUNK_SIZE:,} rows/chunk)")
    print(f"  Input  : {INPUT_PATH}")
    print(f"{'='*65}\n")

    # ── Counters for report ───────────────────────────────────────────────
    total_rows_read      = 0
    total_rows_written   = 0
    dropped_junk         = 0
    dropped_unmapped     = 0
    dropped_inf_rows     = 0
    label_dist           = {}    # class_id -> count
    first_write          = True

    reader = pd.read_csv(
        INPUT_PATH,
        chunksize       = CHUNK_SIZE,
        on_bad_lines    = "skip",
        low_memory      = False,
    )

    for chunk_num, chunk in enumerate(reader):

        rows_in = len(chunk)
        total_rows_read += rows_in

        # ── 1. Strip column name whitespace ──────────────────────────────
        chunk.columns = chunk.columns.str.strip()

        # ── 2. Strip label string whitespace ─────────────────────────────
        if label_col not in chunk.columns:
            print(f"  ⚠ Chunk {chunk_num}: no '{label_col}' column — skipping")
            continue

        chunk[label_col] = chunk[label_col].astype(str).str.strip()

        # ── 3. Drop junk header rows (Label == "Label") ───────────────────
        junk_mask = chunk[label_col].isin(junk_labels)
        if junk_mask.any():
            dropped_junk += junk_mask.sum()
            chunk = chunk[~junk_mask]

        if chunk.empty:
            continue

        # ── 4. Map label strings -> family class IDs ──────────────────────
        chunk[label_col] = chunk[label_col].map(label_map)

        # Drop rows whose label wasn't in the map (NaN after map)
        unmapped_mask = chunk[label_col].isna()
        if unmapped_mask.any():
            dropped_unmapped += unmapped_mask.sum()
            chunk = chunk[~unmapped_mask]

        chunk[label_col] = chunk[label_col].astype(int)

        # ── 5. Drop metadata columns ──────────────────────────────────────
        cols_to_drop = [c for c in METADATA_COLS if c in chunk.columns]
        if cols_to_drop:
            chunk.drop(columns=cols_to_drop, inplace=True)

        # ── 6. Separate features and label ───────────────────────────────
        y = chunk[label_col].copy()
        X = chunk.drop(columns=[label_col])

        # ── 7. Force numeric, replace inf with NaN ───────────────────────
        X = X.apply(pd.to_numeric, errors="coerce")
        inf_mask = X.isin([np.inf, -np.inf])
        X.replace([np.inf, -np.inf], np.nan, inplace=True)

        # ── 8. Cast to float32 (saves ~50% memory vs float64) ────────────
        X = X.astype(np.float32)

        # ── 9. Recombine ──────────────────────────────────────────────────
        chunk_out = X.copy()
        chunk_out[label_col] = y.values

        # ── 10. Accumulate label distribution ─────────────────────────────
        for cls, cnt in chunk_out[label_col].value_counts().items():
            label_dist[int(cls)] = label_dist.get(int(cls), 0) + int(cnt)

        # ── 11. Write chunk ───────────────────────────────────────────────
        chunk_out.to_csv(
            OUTPUT_PATH,
            mode   = "w" if first_write else "a",
            header = first_write,
            index  = False,
        )
        first_write = False

        total_rows_written += len(chunk_out)

        # Progress every 20 chunks (1M rows)
        if (chunk_num + 1) % 20 == 0:
            print(f"  ... {total_rows_read:>12,} rows read  |  "
                  f"{total_rows_written:>12,} rows written", end="\r")

        del chunk, chunk_out, X, y

    # ── Final summary ─────────────────────────────────────────────────────
    print(f"\n{'='*65}")
    print(f"  Clean complete")
    print(f"  Rows read         : {total_rows_read:>12,}")
    print(f"  Rows written      : {total_rows_written:>12,}")
    print(f"  Dropped junk      : {dropped_junk:>12,}  (Label == 'Label')")
    print(f"  Dropped unmapped  : {dropped_unmapped:>12,}  (unknown labels)")
    print(f"{'='*65}")

    print(f"\n  Final class distribution (after family grouping):")
    print(f"  {'Class':<8} {'Family':<16} {'Count':>12}  {'%':>7}")
    print(f"  {'─'*50}")

    label_names = label_cfg["label_names"]
    total_out   = sum(label_dist.values())

    for cls_id in sorted(label_dist.keys()):
        count  = label_dist[cls_id]
        name   = label_names[str(cls_id)]["name"]
        pct    = count / total_out * 100
        print(f"  {cls_id:<8} {name:<16} {count:>12,}  ({pct:.2f}%)")

    print(f"\n  Total output rows : {total_out:,}")

    # ── Save report ───────────────────────────────────────────────────────
    report = {
        "input_rows":       total_rows_read,
        "output_rows":      total_rows_written,
        "dropped_junk":     dropped_junk,
        "dropped_unmapped": dropped_unmapped,
        "metadata_cols_dropped": METADATA_COLS,
        "label_distribution": {
            str(k): {
                "name":  label_names[str(k)]["name"],
                "count": v,
                "pct":   round(v / total_out * 100, 4)
            }
            for k, v in sorted(label_dist.items())
        }
    }

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[OK] Cleaned CSV   -> {OUTPUT_PATH}")
    print(f"[OK] Clean report  -> {REPORT_PATH}")
    print(f"\n✅  Step 2 complete. Run step3_features.py next.\n")


if __name__ == "__main__":
    clean()