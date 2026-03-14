#!/usr/bin/env python3
"""Inspect parquet datasets for live-compatible SDN ML training."""

from __future__ import print_function

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from types import SimpleNamespace

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.train_random_forest import _read_parquet_schema_names, resolve_schema_columns


@dataclass(frozen=True)
class FileInspection(object):
    path: str
    row_count: int = None
    label_column: str = None
    protocol_column: str = None
    src_ip_column: str = None
    dst_ip_column: str = None
    dst_port_column: str = None
    timestamp_column: str = None
    run_id_column: str = None
    scenario_column: str = None
    scenario_id_column: str = None
    live_compatible: bool = False
    missing_live_columns: tuple = ()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Inspect parquet files or folders for live-compatible SDN ML training.",
    )
    parser.add_argument(
        "target",
        help="Path to a parquet file or a directory containing parquet files.",
    )
    parser.add_argument(
        "--dataset-profile",
        default="cicids2018",
        choices=("cicids2018", "generic"),
        help="Schema expectations to apply during inspection.",
    )
    parser.add_argument("--label-column", default=None, help="Optional explicit label column.")
    parser.add_argument("--timestamp-column", default=None, help="Optional explicit timestamp column.")
    parser.add_argument("--src-ip-column", default=None, help="Optional explicit source IP column.")
    parser.add_argument("--dst-ip-column", default=None, help="Optional explicit destination IP column.")
    parser.add_argument("--dst-port-column", default=None, help="Optional explicit destination port column.")
    parser.add_argument("--protocol-column", default=None, help="Optional explicit protocol column.")
    parser.add_argument("--run-id-column", default=None, help="Optional explicit run identifier column.")
    parser.add_argument("--scenario-column", default=None, help="Optional explicit scenario column.")
    parser.add_argument("--scenario-id-column", default=None, help="Optional explicit scenario family column.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the text summary.",
    )
    return parser.parse_args()


def _inspection_args(args):
    return SimpleNamespace(
        label_column=args.label_column,
        timestamp_column=args.timestamp_column,
        src_ip_column=args.src_ip_column,
        dst_ip_column=args.dst_ip_column,
        dst_port_column=args.dst_port_column,
        protocol_column=args.protocol_column,
        run_id_column=args.run_id_column,
        scenario_column=args.scenario_column,
        scenario_id_column=args.scenario_id_column,
        dataset_profile=args.dataset_profile,
        allow_degraded_training=True,
    )


def _iter_parquet_files(target_path):
    if target_path.suffix.lower() == ".zip":
        raise ValueError("ZIP archives must be extracted before inspection: %s" % target_path)

    if target_path.is_file():
        if target_path.suffix.lower() != ".parquet":
            raise ValueError("Target file is not a parquet file: %s" % target_path)
        return [target_path]

    if target_path.is_dir():
        return sorted(path for path in target_path.rglob("*.parquet") if path.is_file())

    raise ValueError("Target does not exist: %s" % target_path)


def _read_parquet_row_count(dataset_path):
    try:
        import pyarrow.parquet as parquet
    except ImportError:
        return None

    return int(parquet.ParquetFile(str(dataset_path)).metadata.num_rows)


def inspect_parquet_file(dataset_path, args):
    schema_names = _read_parquet_schema_names(dataset_path)
    if schema_names is None:
        raise RuntimeError(
            "Parquet schema inspection requires pyarrow. Install requirements-ml.txt first."
        )

    schema = resolve_schema_columns(schema_names, _inspection_args(args))
    return FileInspection(
        path=str(dataset_path),
        row_count=_read_parquet_row_count(dataset_path),
        label_column=schema.label_column,
        protocol_column=schema.protocol_column,
        src_ip_column=schema.src_ip_column,
        dst_ip_column=schema.dst_ip_column,
        dst_port_column=schema.dst_port_column,
        timestamp_column=schema.timestamp_column,
        run_id_column=schema.run_id_column,
        scenario_column=schema.scenario_column,
        scenario_id_column=schema.scenario_id_column,
        live_compatible=schema.live_compatible,
        missing_live_columns=tuple(schema.missing_live_columns),
    )


def inspect_target(target_path, args):
    parquet_files = _iter_parquet_files(target_path)
    if not parquet_files:
        raise ValueError("No parquet files found under: %s" % target_path)

    inspections = [inspect_parquet_file(parquet_path, args) for parquet_path in parquet_files]
    compatible_count = sum(1 for item in inspections if item.live_compatible)
    incompatible_count = len(inspections) - compatible_count
    return {
        "target": str(target_path),
        "dataset_profile": args.dataset_profile,
        "file_count": len(inspections),
        "compatible_count": compatible_count,
        "incompatible_count": incompatible_count,
        "all_live_compatible": incompatible_count == 0,
        "files": [
            {
                "path": item.path,
                "row_count": item.row_count,
                "label_column": item.label_column,
                "protocol_column": item.protocol_column,
                "src_ip_column": item.src_ip_column,
                "dst_ip_column": item.dst_ip_column,
                "dst_port_column": item.dst_port_column,
                "timestamp_column": item.timestamp_column,
                "run_id_column": item.run_id_column,
                "scenario_column": item.scenario_column,
                "scenario_id_column": item.scenario_id_column,
                "live_compatible": item.live_compatible,
                "missing_live_columns": list(item.missing_live_columns),
            }
            for item in inspections
        ],
    }


def _format_columns(file_result):
    return ", ".join(
        [
            "label=%s" % (file_result["label_column"] or "-"),
            "protocol=%s" % (file_result["protocol_column"] or "-"),
            "src_ip=%s" % (file_result["src_ip_column"] or "-"),
            "dst_ip=%s" % (file_result["dst_ip_column"] or "-"),
            "dst_port=%s" % (file_result["dst_port_column"] or "-"),
            "timestamp=%s" % (file_result["timestamp_column"] or "-"),
            "run_id=%s" % (file_result.get("run_id_column") or "-"),
            "scenario=%s" % (file_result.get("scenario_column") or "-"),
            "scenario_id=%s" % (file_result.get("scenario_id_column") or "-"),
        ]
    )


def _format_text_report(result):
    lines = [
        "Target: %s" % result["target"],
        "Dataset profile: %s" % result["dataset_profile"],
        "Parquet files: %s" % result["file_count"],
        "Live-compatible files: %s" % result["compatible_count"],
        "Incompatible files: %s" % result["incompatible_count"],
    ]

    overall_status = "YES" if result["all_live_compatible"] else "NO"
    lines.append("Suitable for live SDN ML training: %s" % overall_status)

    for file_result in result["files"]:
        status = "OK" if file_result["live_compatible"] else "MISSING_FIELDS"
        lines.append("")
        lines.append("[%s] %s" % (status, file_result["path"]))
        if file_result["row_count"] is not None:
            lines.append("  rows: %s" % file_result["row_count"])
        lines.append("  columns: %s" % _format_columns(file_result))
        if file_result["missing_live_columns"]:
            lines.append(
                "  missing live fields: %s" % ", ".join(file_result["missing_live_columns"])
            )

    return "\n".join(lines)


def main():
    args = parse_args()
    target_path = Path(args.target)

    try:
        result = inspect_target(target_path, args)
    except (RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(_format_text_report(result))

    return 0 if result["all_live_compatible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
