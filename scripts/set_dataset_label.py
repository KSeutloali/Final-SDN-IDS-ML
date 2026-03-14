#!/usr/bin/env python3
"""Set or clear the active label used by the runtime dataset recorder."""

from __future__ import print_function

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config.settings import load_config


def parse_args():
    parser = argparse.ArgumentParser(description="Set the active runtime dataset label.")
    parser.add_argument("label", nargs="?", help="Label to apply, for example benign or malicious.")
    parser.add_argument("--scenario", default="", help="Optional scenario name.")
    parser.add_argument("--scenario-id", default="", help="Optional stable scenario family identifier.")
    parser.add_argument("--run-id", default="", help="Optional unique run identifier.")
    parser.add_argument("--collection-id", default="", help="Optional collector session identifier.")
    parser.add_argument("--note", default="", help="Optional note stored with recorded rows.")
    parser.add_argument(
        "--label-file",
        default=None,
        help="Optional explicit label file path.",
    )
    parser.add_argument("--clear", action="store_true", help="Remove the active label file.")
    return parser.parse_args()


def main():
    args = parse_args()
    config = load_config()
    label_path = Path(args.label_file or config.ml.dataset_label_path)
    label_path.parent.mkdir(parents=True, exist_ok=True)

    if args.clear:
        if label_path.exists():
            label_path.unlink()
        print("dataset_label=cleared path=%s" % label_path)
        return 0

    if not args.label:
        print("A label is required unless --clear is used.", file=sys.stderr)
        return 1

    payload = {
        "label": args.label,
        "scenario": args.scenario,
        "scenario_id": args.scenario_id,
        "run_id": args.run_id,
        "collection_id": args.collection_id,
        "note": args.note,
        "source": "manual",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    label_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print("dataset_label=%s path=%s" % (args.label, label_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
