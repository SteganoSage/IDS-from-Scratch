"""
preprocessing/step3_sample.py
==============================
Creates a representative, proportional sample from cleaned.csv
(16.2M rows) that is small enough to train on.

Strategy: Two-pass chunked sampling
  Pass 1 — scan cleaned.csv, record the FILE OFFSET (row index) of
            every row belonging to each class. Memory cost = one integer
            per row = ~130MB for 16M rows. Acceptable.

  Pass 2 — from each class's collected indices, randomly pick up to
            the cap. Then do a single targeted read of only those rows.

Sampling caps (proportional with floor):
  Class 0  Benign        400,000   (capped — originally 83% of data)
  Class 1  BruteForce    200,000
  Class 2  DoS           200,000
  Class 3  DDoS          200,000
  Class 4  Bot           150,000
  Class 5  Infiltration  100,000
  Class 6  WebAttack          87   (take ALL — only 87 rows exist)

Usage:
    python -m preprocessing.step3_sample

Input:   data/processed/cleaned.csv
Output:  data/processed/sampled.csv
         data/processed/sample_report.json
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
INPUT_PATH  = Path("data/processed/cleaned.csv")
OUTPUT_PATH = Path("data/processed/sampled2018.csv")
REPORT_PATH = Path("data/processed/sample_report.json")
LABELS_CFG  = Path("config/labels.json")

# ── Sampling caps per class (None = take all) ─────────────────────────────────
SAMPLE_CAPS = {
    0: 400_000,   # Benign
    1: 200_000,   # BruteForce
    2: 200_000,   # DoS
    3: 200_000,   # DDoS
    4: 150_000,   # Bot
    # Class 5 (Infiltration) removed — handled by Anomaly model in Fusion
    # WebAttack remapped from 6 -> 5
    5: None,      # WebAttack — only 87 rows, take all
}

CHUNK_SIZE  = 50_000
RANDOM_SEED = 42


def load_label_config():
    with open(LABELS_CFG) as f:
        return json.load(f)


def sample():
    label_cfg   = load_label_config()
    label_names = label_cfg["label_names"]
    label_col   = label_cfg["label_column"]

    if not INPUT_PATH.exists():
        raise FileNotFoundError(
            f"\n❌  {INPUT_PATH} not found."
            f"\n    Run step2_clean.py first."
        )

    print(f"\n{'='*65}")
    print(f"  FusionIDS - Step 3: Sample")
    print(f"  Input    : {INPUT_PATH}")
    print(f"  Strategy : Proportional with floor (two-pass)")
    print(f"{'='*65}")

    print(f"\n  Sampling caps:")
    print(f"  {'Class':<8} {'Family':<16} {'Cap':>12}")
    print(f"  {'─'*40}")
    for cls, cap in SAMPLE_CAPS.items():
        name    = label_names[str(cls)]["name"]
        cap_str = f"{cap:>12,}" if cap else "     ALL (87)"
        print(f"  {cls:<8} {name:<16} {cap_str}")

    # ── Pass 1: Collect row indices per class ─────────────────────────────
    # We only store the integer row index — not the row data itself
    # Memory: 16.2M integers x 8 bytes = ~130MB
    print(f"\n[INFO] Pass 1 — scanning for row indices per class...")

    class_indices = {cls: [] for cls in SAMPLE_CAPS}
    total_read    = 0

    reader = pd.read_csv(
        INPUT_PATH,
        chunksize    = CHUNK_SIZE,
        low_memory   = False,
        usecols      = [label_col],   # only read label column — much faster
    )

    for chunk_num, chunk in enumerate(reader):
        chunk_start = total_read

        for cls in SAMPLE_CAPS:
            mask = (chunk[label_col] == cls)
            # Convert local chunk indices to global row indices
            global_indices = chunk_start + np.where(mask.values)[0]
            class_indices[cls].extend(global_indices.tolist())

        total_read += len(chunk)

        if (chunk_num + 1) % 40 == 0:
            print(f"  ... {total_read:>12,} rows scanned", end="\r")

    print(f"\n  Scanned {total_read:,} rows")
    print(f"\n  Rows found per class:")
    print(f"  {'Class':<8} {'Family':<16} {'Found':>10}  {'Cap':>10}")
    print(f"  {'─'*50}")
    for cls, indices in class_indices.items():
        name    = label_names[str(cls)]["name"]
        cap     = SAMPLE_CAPS[cls]
        cap_str = f"{cap:>10,}" if cap else "  ALL"
        print(f"  {cls:<8} {name:<16} {len(indices):>10,}  {cap_str}")

    # ── Select final row indices per class ────────────────────────────────
    rng = np.random.default_rng(RANDOM_SEED)

    selected_indices = set()
    final_counts     = {}

    for cls, indices in class_indices.items():
        cap = SAMPLE_CAPS[cls]
        if cap is None or len(indices) <= cap:
            chosen = indices
        else:
            chosen = rng.choice(indices, size=cap, replace=False).tolist()

        selected_indices.update(chosen)
        final_counts[cls] = len(chosen)

    print(f"\n  Total rows selected: {len(selected_indices):,}")

    # ── Pass 2: Read only the selected rows ───────────────────────────────
    print(f"\n[INFO] Pass 2 — reading selected rows...")

    # Sort indices for sequential disk access (faster than random access)
    sorted_indices = sorted(selected_indices)
    selected_set   = set(sorted_indices)

    frames      = []
    total_read2 = 0
    rows_kept   = 0
    first_write = True

    reader2 = pd.read_csv(
        INPUT_PATH,
        chunksize  = CHUNK_SIZE,
        low_memory = False,
    )

    for chunk_num, chunk in enumerate(reader2):
        chunk_start = total_read2
        chunk_end   = chunk_start + len(chunk)

        # Find which rows in this chunk are selected
        local_mask = [
            (chunk_start + i) in selected_set
            for i in range(len(chunk))
        ]

        selected_chunk = chunk[local_mask]

        if not selected_chunk.empty:
            selected_chunk.to_csv(
                OUTPUT_PATH,
                mode   = "w" if first_write else "a",
                header = first_write,
                index  = False,
            )
            first_write = False
            rows_kept  += len(selected_chunk)

        total_read2 += len(chunk)

        if (chunk_num + 1) % 40 == 0:
            print(f"  ... {total_read2:>12,} rows scanned  |  "
                  f"{rows_kept:>10,} written", end="\r")

        del chunk, selected_chunk

    # ── Shuffle the output (rows are currently in file order) ────────────
    print(f"\n\n[INFO] Shuffling sampled data...")
    sampled = pd.read_csv(OUTPUT_PATH)
    sampled = sampled.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    sampled.to_csv(OUTPUT_PATH, index=False)

    total_sampled = len(sampled)

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'='*65}")
    print(f"  Sample complete")
    print(f"  Original rows  : {total_read:>12,}")
    print(f"  Sampled rows   : {total_sampled:>12,}")
    print(f"  Reduction      : {(1 - total_sampled/total_read)*100:.1f}%")
    print(f"{'='*65}")

    print(f"\n  Final distribution:")
    print(f"  {'Class':<8} {'Family':<16} {'Count':>10}  {'%':>7}")
    print(f"  {'─'*48}")

    actual_dist = sampled[label_col].value_counts().sort_index()
    report_dist = {}

    for cls_id, count in actual_dist.items():
        name = label_names[str(cls_id)]["name"]
        pct  = count / total_sampled * 100
        print(f"  {cls_id:<8} {name:<16} {count:>10,}  ({pct:.2f}%)")
        report_dist[str(cls_id)] = {"name": name, "count": int(count), "pct": round(pct, 4)}

    # ── Save report ───────────────────────────────────────────────────────
    report = {
        "input_rows":   total_read,
        "sampled_rows": total_sampled,
        "reduction_pct": round((1 - total_sampled / total_read) * 100, 2),
        "random_seed":  RANDOM_SEED,
        "sample_caps":  {str(k): v for k, v in SAMPLE_CAPS.items()},
        "distribution": report_dist,
    }
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[OK] Sampled CSV    -> {OUTPUT_PATH}")
    print(f"[OK] Sample report  -> {REPORT_PATH}")
    print(f"\n✅  Step 3 complete. Run step4_features.py next.\n")

    return sampled


if __name__ == "__main__":
    sample()