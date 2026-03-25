#!/usr/bin/env python3
"""Merge the approved runtime parquet datasets into one training base."""

from __future__ import print_function

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import json
import sys


DEFAULT_INPUTS = (
    "datasets/scan_heavy_runtime_20260321.parquet",
    "datasets/collected_runtime_dataset_20260312_120629.parquet",
    "datasets/collected_runtime_dataset_20260312_121650.parquet",
    "datasets/collected_runtime_dataset_20260312_122214.parquet",
)
DEFAULT_OUTPUT = "datasets/merged_runtime_dataset.parquet"
CANONICAL_METADATA_COLUMNS = (
    "Timestamp",
    "Label",
    "Scenario",
    "Scenario ID",
    "Scenario Family",
    "Scenario Variant",
    "Traffic Class",
    "Run ID",
    "Collection ID",
    "Src IP",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Src Host",
    "Dst Host",
    "Dst Service",
    "Duration Seconds",
    "Rate Parameter",
    "Concurrency Level",
    "Capture File",
    "Label Source",
    "Note",
    "DPID",
    "In Port",
)
DEDUPE_KEY_CANDIDATES = (
    "Timestamp",
    "Src IP",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Label",
    "Scenario",
    "Run ID",
    "Collection ID",
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Merge the approved runtime parquet datasets into one training base.",
    )
    parser.add_argument(
        "--inputs",
        nargs="*",
        default=list(DEFAULT_INPUTS),
        help="Parquet files to merge. Defaults to the approved Stage 1 runtime datasets.",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help="Output merged parquet path.",
    )
    parser.add_argument(
        "--source-column",
        default="Source File",
        help="Optional metadata column that records the input parquet path.",
    )
    parser.add_argument(
        "--no-dedupe",
        action="store_true",
        help="Keep exact duplicate rows instead of dropping them.",
    )
    return parser.parse_args()


def normalize_label_value(value):
    text = str(value or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    if "benign" in lowered or "normal" in lowered or "background" in lowered:
        return "benign"
    return "malicious"


def runtime_feature_columns(columns):
    return tuple(sorted(column for column in columns if str(column).startswith("Runtime ")))


def schema_union(columns_by_file):
    ordered = []
    seen = set()

    for column_name in CANONICAL_METADATA_COLUMNS:
        ordered.append(column_name)
        seen.add(column_name)

    runtime_columns = set()
    for columns in columns_by_file.values():
        runtime_columns.update(runtime_feature_columns(columns))
    for column_name in sorted(runtime_columns):
        if column_name not in seen:
            ordered.append(column_name)
            seen.add(column_name)

    for columns in columns_by_file.values():
        for column_name in columns:
            if column_name not in seen:
                ordered.append(column_name)
                seen.add(column_name)
    return ordered


def align_frame(pandas_module, dataframe, target_columns, source_file, source_column):
    aligned = dataframe.copy()
    if "Label" in aligned.columns:
        aligned["Label"] = aligned["Label"].apply(normalize_label_value)
    if "Traffic Class" in aligned.columns:
        aligned["Traffic Class"] = aligned["Traffic Class"].replace("", pandas_module.NA)
    if "Traffic Class" not in aligned.columns and "Label" in aligned.columns:
        aligned["Traffic Class"] = aligned["Label"]
    elif "Traffic Class" in aligned.columns and "Label" in aligned.columns:
        aligned["Traffic Class"] = aligned["Traffic Class"].fillna(aligned["Label"])

    aligned[source_column] = source_file
    for column_name in target_columns:
        if column_name not in aligned.columns:
            aligned[column_name] = pandas_module.NA
    return aligned[target_columns + [source_column]]


def dedupe_rows(pandas_module, dataframe):
    subset = [column_name for column_name in DEDUPE_KEY_CANDIDATES if column_name in dataframe.columns]
    if not subset:
        return dataframe, 0, ()
    before = len(dataframe)
    deduped = dataframe.drop_duplicates(subset=subset, keep="first").reset_index(drop=True)
    removed = before - len(deduped)
    return deduped, removed, tuple(subset)


def summarize_missing_columns(columns_by_file, merged_columns):
    missing = {}
    for source_file, columns in columns_by_file.items():
        missing_columns = [column_name for column_name in merged_columns if column_name not in columns]
        missing[source_file] = missing_columns
    return missing


def main():
    args = parse_args()

    try:
        import pandas as pd
    except ImportError as exc:
        print("Missing dependency: %s" % exc, file=sys.stderr)
        return 1

    input_paths = [Path(input_path) for input_path in args.inputs]
    for input_path in input_paths:
        if not input_path.exists():
            print("Input dataset not found: %s" % input_path, file=sys.stderr)
            return 1

    frames = []
    row_counts = {}
    columns_by_file = {}
    for input_path in input_paths:
        dataframe = pd.read_parquet(str(input_path))
        row_counts[str(input_path)] = int(len(dataframe))
        columns_by_file[str(input_path)] = list(dataframe.columns)
        frames.append((input_path, dataframe))

    merged_columns = schema_union(columns_by_file)
    aligned_frames = []
    for input_path, dataframe in frames:
        aligned_frames.append(
            align_frame(
                pd,
                dataframe,
                merged_columns,
                str(input_path),
                args.source_column,
            )
        )

    merged = pd.concat(aligned_frames, ignore_index=True, sort=False)
    duplicates_removed = 0
    dedupe_subset = ()
    if not args.no_dedupe:
        merged, duplicates_removed, dedupe_subset = dedupe_rows(pd, merged)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    merged.to_parquet(str(output_path), index=False)

    label_counts = {}
    if "Label" in merged.columns:
        label_counts = (
            merged["Label"]
            .fillna("")
            .astype(str)
            .replace("", "unlabeled")
            .value_counts()
            .to_dict()
        )

    scenario_counts = {}
    if "Scenario Family" in merged.columns and merged["Scenario Family"].notna().any():
        scenario_counts = (
            merged["Scenario Family"]
            .fillna("")
            .astype(str)
            .replace("", "unspecified")
            .value_counts()
            .head(20)
            .to_dict()
        )
    elif "Scenario" in merged.columns:
        scenario_counts = (
            merged["Scenario"]
            .fillna("")
            .astype(str)
            .replace("", "unspecified")
            .value_counts()
            .head(20)
            .to_dict()
        )

    missing_notes = summarize_missing_columns(columns_by_file, merged_columns)
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": row_counts,
        "output": str(output_path),
        "merged_row_count": int(len(merged)),
        "duplicates_removed": int(duplicates_removed),
        "dedupe_subset": list(dedupe_subset),
        "label_distribution": label_counts,
        "scenario_distribution": scenario_counts,
        "missing_columns_by_input": missing_notes,
        "merged_columns": merged_columns,
    }

    print("Merged runtime dataset written to %s" % output_path)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
