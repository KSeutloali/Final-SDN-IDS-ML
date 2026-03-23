#!/usr/bin/env python3
"""Convert an sklearn-backed IDS model bundle into a portable runtime bundle."""

from __future__ import print_function

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.model_loader import load_model, save_model_bundle
from ml.runtime_forest import RuntimeRandomForestModel, export_random_forest_model


def parse_args():
    parser = argparse.ArgumentParser(
        description="Export a trained sklearn Random Forest into a portable runtime bundle."
    )
    parser.add_argument("--input", required=True, help="Path to the existing model bundle.")
    parser.add_argument("--output", required=True, help="Path to the exported runtime bundle.")
    return parser.parse_args()


def main():
    args = parse_args()
    bundle = load_model(args.input)
    if not bundle.is_available:
        print("Unable to load model bundle: %s" % bundle.load_error, file=sys.stderr)
        return 1

    model = bundle.model
    if isinstance(model, RuntimeRandomForestModel):
        runtime_model = model
    else:
        if not hasattr(model, "estimators_"):
            print(
                "Input model is not a fitted Random Forest and cannot be exported.",
                file=sys.stderr,
            )
            return 1
        runtime_model = export_random_forest_model(model)

    metadata = dict(bundle.metadata or {})
    metadata["runtime_model_type"] = "portable_random_forest"
    metadata["tree_count"] = len(runtime_model.trees)
    metadata["exported_from"] = str(Path(args.input))

    save_model_bundle(
        args.output,
        {
            "model": runtime_model,
            "feature_names": list(bundle.feature_names),
            "positive_labels": list(bundle.positive_labels),
            "metadata": metadata,
        },
    )
    print("Exported portable runtime model to %s" % args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
