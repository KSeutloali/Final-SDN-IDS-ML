#!/usr/bin/env python3
"""Convert controller-recorded JSONL rows into a parquet dataset."""

from __future__ import print_function

import argparse
import json
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Convert runtime-recorded JSONL rows into parquet.",
    )
    parser.add_argument(
        "--input",
        default="runtime/ml_dataset.jsonl",
        help="Input JSONL path from the runtime dataset recorder.",
    )
    parser.add_argument(
        "--output",
        default="datasets/runtime_lab_dataset.parquet",
        help="Output parquet path.",
    )
    return parser.parse_args()


def load_jsonl_records(input_path):
    records = []
    with input_path.open() as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            records.append(json.loads(stripped))
    return records


def main():
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print("Runtime dataset not found: %s" % input_path, file=sys.stderr)
        return 1

    try:
        import pandas as pd
    except ImportError as exc:
        print(
            "Offline ML dependencies are missing: %s\n"
            "Install requirements-ml.txt in a separate training environment." % exc,
            file=sys.stderr,
        )
        return 1

    records = load_jsonl_records(input_path)
    if not records:
        print("Runtime dataset file is empty: %s" % input_path, file=sys.stderr)
        return 1

    dataframe = pd.DataFrame.from_records(records)
    if "Timestamp" in dataframe.columns:
        dataframe["Timestamp"] = pd.to_datetime(
            dataframe["Timestamp"],
            errors="coerce",
            utc=True,
        )
    dataframe = dataframe.sort_values("Timestamp").reset_index(drop=True)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    dataframe.to_parquet(str(output_path), index=False)

    print("rows=%s" % len(dataframe))
    print("output=%s" % output_path)
    if "Label" in dataframe.columns:
        print("labels=%s" % json.dumps(dataframe["Label"].value_counts().to_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
