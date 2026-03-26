"""
preprocessing/step1_merge.py
=============================
Merges all 10 CIC-IDS 2018 daily CSV files into one combined file
using CHUNKED reading — so memory usage stays flat regardless of file size.

Without chunking:
    16.2M rows x 80 cols x float64 = ~100GB RAM -> crash

With chunking (chunksize=50,000):
    Only 50k rows in memory at any time -> ~30MB RAM peak

Known issues handled:
  - 02-20-2018.csv has 4 extra cols (Flow ID, Src IP, Src Port, Dst IP) -> dropped
  - Some files have duplicate header rows (Label == "Label") -> handled in step2
  - Files are large (up to 7.9M rows) -> chunked write, never fully loaded

Usage:
    python -m preprocessing.step1_merge
    python -m preprocessing.step1_merge --raw-dir "D:/path/to/your/csvs"

Output:
    data/processed/combined_raw.csv
    data/processed/merge_report.json
"""

import argparse
import json
import pandas as pd
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
DEFAULT_RAW_DIR = Path("data/raw")
PROCESSED_DIR   = Path("data/processed")
OUTPUT_PATH     = PROCESSED_DIR / "combined_raw.csv"
REPORT_PATH     = PROCESSED_DIR / "merge_report.json"
LABELS_CFG      = Path("config/labels.json")

# ── Chunked reading config ────────────────────────────────────────────────────
# 50k rows ~ 30MB RAM per chunk — safe on any machine
# Increase to 100_000 if you have 16GB+ RAM and want it faster
CHUNK_SIZE = 50_000

# ── Columns only in 02-20-2018.csv ───────────────────────────────────────────
EXTRA_COLS_TO_DROP = ["Flow ID", "Src IP", "Src Port", "Dst IP"]
EXPECTED_COL_COUNT = 80


def load_label_config():
    with open(LABELS_CFG) as f:
        return json.load(f)


def process_file(csv_path: Path, label_col: str, is_first_file: bool) -> dict:
    """
    Reads one CSV file in chunks, drops extra columns if present,
    and appends each chunk to the output CSV.
    Memory usage is capped at CHUNK_SIZE rows at any point.
    """
    file_report = {
        "file":          csv_path.name,
        "rows":          0,
        "chunks":        0,
        "original_cols": None,
        "final_cols":    None,
        "label_counts":  {},
        "issues":        [],
    }

    write_header  = is_first_file  # only write CSV header on very first chunk ever
    extra_dropped = []             # which extra cols we dropped from this file
    label_counts  = {}             # accumulate label counts across all chunks

    try:
        reader = pd.read_csv(
            csv_path,
            chunksize       = CHUNK_SIZE,
            on_bad_lines    = "skip",
            low_memory      = False,
            encoding        = "utf-8",
            encoding_errors = "replace",
        )

        for chunk_num, chunk in enumerate(reader):

            # Strip whitespace from column names
            chunk.columns = chunk.columns.str.strip()

            # On the first chunk — detect column layout
            if file_report["original_cols"] is None:
                file_report["original_cols"] = chunk.shape[1]

                # Check for extra columns unique to 02-20-2018.csv
                extra_found = [c for c in EXTRA_COLS_TO_DROP if c in chunk.columns]
                if extra_found:
                    extra_dropped = extra_found
                    msg = f"Dropped extra cols: {extra_found}"
                    file_report["issues"].append(msg)

                file_report["final_cols"] = chunk.shape[1] - len(extra_dropped)

                # Warn if column count is unexpected
                if file_report["final_cols"] != EXPECTED_COL_COUNT:
                    msg = (
                        f"Unexpected column count: {file_report['final_cols']} "
                        f"(expected {EXPECTED_COL_COUNT})"
                    )
                    file_report["issues"].append(msg)

            # Drop extra cols on every chunk of this file
            if extra_dropped:
                chunk.drop(columns=extra_dropped, inplace=True, errors="ignore")

            # Accumulate label distribution
            if label_col in chunk.columns:
                chunk[label_col] = chunk[label_col].astype(str).str.strip()
                for label, count in chunk[label_col].value_counts().items():
                    label_counts[label] = label_counts.get(label, 0) + count

            # Write chunk — header only on the very first write across all files
            chunk.to_csv(
                OUTPUT_PATH,
                mode   = "w" if write_header else "a",
                header = write_header,
                index  = False,
            )
            write_header = False  # never write header again

            file_report["rows"]   += len(chunk)
            file_report["chunks"] += 1

            # Progress dot every 10 chunks (500k rows)
            if (chunk_num + 1) % 10 == 0:
                print(f"    ... {file_report['rows']:>10,} rows written", end="\r")

            del chunk  # free memory immediately

    except Exception as e:
        msg = f"Error reading {csv_path.name}: {e}"
        file_report["issues"].append(msg)
        print(f"\n  ❌ {msg}")

    file_report["label_counts"] = label_counts
    return file_report


def merge(raw_dir: Path):
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    label_cfg = load_label_config()
    label_col = label_cfg["label_column"]

    csv_files = sorted(raw_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"\n❌  No CSV files found in: {raw_dir.resolve()}"
            f"\n    Pass the correct path with --raw-dir"
        )

    print(f"\n{'='*65}")
    print(f"  FusionIDS - Step 1: Merge  (chunked, {CHUNK_SIZE:,} rows/chunk)")
    print(f"  Source : {raw_dir.resolve()}")
    print(f"  Files  : {len(csv_files)}")
    print(f"{'='*65}\n")

    report     = {"files": [], "total_rows": 0, "all_issues": []}
    total_rows = 0

    for file_idx, csv_path in enumerate(csv_files):
        print(f"[{file_idx+1}/{len(csv_files)}] {csv_path.name}")

        file_report = process_file(csv_path, label_col, is_first_file=(file_idx == 0))

        total_rows += file_report["rows"]

        print(f"  -> {file_report['rows']:>10,} rows  "
              f"|  {file_report['chunks']} chunks  "
              f"|  {file_report['final_cols']} cols")

        if file_report["label_counts"]:
            print(f"  -> Labels: {list(file_report['label_counts'].keys())}")

        if file_report["issues"]:
            for issue in file_report["issues"]:
                print(f"  ⚠  {issue}")
            report["all_issues"].extend(file_report["issues"])

        report["files"].append(file_report)
        print()

    report["total_rows"] = total_rows

    # ── Aggregate label counts across all files ───────────────────────────
    all_labels = {}
    for fr in report["files"]:
        for label, count in fr["label_counts"].items():
            all_labels[label] = all_labels.get(label, 0) + count

    report["overall_label_counts"] = dict(
        sorted(all_labels.items(), key=lambda x: -x[1])
    )

    # ── Print final summary ───────────────────────────────────────────────
    print(f"{'='*65}")
    print(f"  Merge complete")
    print(f"  Total rows : {total_rows:,}")
    print(f"  Output     : {OUTPUT_PATH}")
    if report["all_issues"]:
        print(f"  Issues     : {len(report['all_issues'])} (see merge_report.json)")
    print(f"{'='*65}")

    print(f"\n  Overall label distribution:")
    print(f"  {'Label':<40} {'Count':>12}  {'%':>7}")
    print(f"  {'─'*58}")
    for label, count in report["overall_label_counts"].items():
        pct = count / total_rows * 100
        print(f"  {label:<40} {count:>10,}  ({pct:.2f}%)")

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[OK] Combined CSV  -> {OUTPUT_PATH}")
    print(f"[OK] Merge report  -> {REPORT_PATH}")
    print(f"\n✅  Step 1 complete. Run step2_clean.py next.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FusionIDS - Step 1: Merge CSVs")
    parser.add_argument(
        "--raw-dir",
        type    = str,
        default = str(DEFAULT_RAW_DIR),
        help    = "Path to folder containing CIC-IDS 2018 CSV files"
    )
    args = parser.parse_args()
    merge(Path(args.raw_dir))