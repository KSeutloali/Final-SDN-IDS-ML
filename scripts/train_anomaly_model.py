#!/usr/bin/env python3
"""Offline anomaly-model training utility for runtime-compatible SDN features."""

from __future__ import print_function

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import statistics
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml.anomaly import export_isolation_forest_model
from ml.feature_extractor import RUNTIME_FEATURE_NAMES
from ml.model_loader import save_model_bundle
from scripts.train_random_forest import (
    build_runtime_training_frame,
    load_combined_dataset,
    resolve_schema_columns,
    resolve_input_datasets,
)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Train an offline anomaly IDS model.")
    parser.add_argument(
        "--dataset",
        default=None,
        help="Path to a parquet dataset. Preserved for backward compatibility.",
    )
    parser.add_argument(
        "--merged-runtime-data",
        default=None,
        help="Primary merged runtime parquet dataset to train from.",
    )
    parser.add_argument(
        "--additional-runtime-dir",
        default=None,
        help="Optional directory of additional runtime parquet files to append before training.",
    )
    parser.add_argument(
        "--model-out",
        default="models/isolation_forest_runtime.joblib",
        help="Output path for the serialized anomaly model bundle.",
    )
    parser.add_argument(
        "--metrics-out",
        default=None,
        help="Optional JSON metrics output path.",
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=10,
        help="Host aggregation window used to approximate controller runtime features.",
    )
    parser.add_argument("--label-column", default=None, help="Optional explicit label column.")
    parser.add_argument("--timestamp-column", default=None, help="Optional explicit timestamp column.")
    parser.add_argument("--src-ip-column", default=None, help="Optional explicit source IP column.")
    parser.add_argument("--dst-ip-column", default=None, help="Optional explicit destination IP column.")
    parser.add_argument("--dst-port-column", default=None, help="Optional explicit destination port column.")
    parser.add_argument("--protocol-column", default=None, help="Optional explicit protocol column.")
    parser.add_argument("--run-id-column", default=None, help="Optional explicit run identifier column.")
    parser.add_argument("--scenario-column", default=None, help="Optional explicit scenario column.")
    parser.add_argument("--scenario-family-column", default=None, help="Optional explicit scenario-family column.")
    parser.add_argument("--scenario-id-column", default=None, help="Optional explicit scenario ID column.")
    parser.add_argument(
        "--dataset-profile",
        default="cicids2018",
        choices=("cicids2018", "generic"),
        help="Schema expectations to apply during validation. CICIDS2018 is preferred.",
    )
    parser.add_argument(
        "--allow-degraded-training",
        action="store_true",
        help="Allow exploratory training even when the schema is not fully live-compatible.",
    )
    parser.add_argument(
        "--benign-label",
        default="benign",
        help="Resolved label to treat as benign for anomaly-model training.",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.25,
        help="Hold-out fraction for benign evaluation rows.",
    )
    parser.add_argument("--random-state", type=int, default=42, help="Random seed.")
    parser.add_argument(
        "--minimum-benign-rows",
        type=int,
        default=10,
        help="Minimum benign rows required before fitting the anomaly model.",
    )
    parser.add_argument(
        "--max-benign-training-rows",
        type=int,
        default=0,
        help="Optional cap for benign training rows. Use 0 to keep all benign training rows.",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        help="Isolation Forest tree count.",
    )
    parser.add_argument(
        "--max-samples",
        default="auto",
        help="Isolation Forest max_samples value.",
    )
    parser.add_argument(
        "--contamination",
        default="auto",
        help="Isolation Forest contamination value.",
    )
    return parser.parse_args(argv)


def parse_contamination(value):
    text = str(value).strip().lower()
    if text in ("", "auto"):
        return "auto"
    return float(value)


def parse_max_samples(value):
    text = str(value).strip().lower()
    if text == "auto":
        return "auto"
    try:
        numeric_value = int(value)
        return numeric_value
    except (TypeError, ValueError):
        return float(value)


def select_benign_training_rows(
    feature_frame,
    label_series,
    benign_label,
    test_size,
    random_state,
    train_test_split_fn,
    minimum_benign_rows=10,
    max_benign_training_rows=0,
):
    benign_mask = label_series.astype(str) == str(benign_label)
    benign_rows = feature_frame[benign_mask].reset_index(drop=True)
    if len(benign_rows) < int(minimum_benign_rows):
        raise ValueError(
            "Need at least %s benign rows for anomaly training; found %s."
            % (minimum_benign_rows, len(benign_rows))
        )
    if len(benign_rows) < 2:
        raise ValueError("Need at least two benign rows for anomaly training.")

    train_rows, holdout_rows = train_test_split_fn(
        benign_rows,
        test_size=test_size,
        random_state=random_state,
    )
    if int(max_benign_training_rows or 0) > 0 and len(train_rows) > int(max_benign_training_rows):
        train_rows = train_rows.sample(
            n=int(max_benign_training_rows),
            random_state=random_state,
        )
    return train_rows.reset_index(drop=True), holdout_rows.reset_index(drop=True)


def _score_summary(values):
    if not values:
        return {
            "count": 0,
            "min": 0.0,
            "p50": 0.0,
            "p90": 0.0,
            "p95": 0.0,
            "max": 0.0,
            "mean": 0.0,
        }

    ordered = sorted(float(value) for value in values)

    def percentile(percent):
        if len(ordered) == 1:
            return ordered[0]
        index = int(round((len(ordered) - 1) * float(percent)))
        index = max(0, min(index, len(ordered) - 1))
        return ordered[index]

    return {
        "count": int(len(ordered)),
        "min": float(ordered[0]),
        "p50": float(percentile(0.50)),
        "p90": float(percentile(0.90)),
        "p95": float(percentile(0.95)),
        "max": float(ordered[-1]),
        "mean": float(statistics.mean(ordered)),
    }


def evaluate_anomaly_model(
    model,
    feature_frame,
    label_series,
    family_series=None,
    benign_label="benign",
):
    rows = feature_frame.values.tolist()
    predictions = model.predict(rows)
    anomaly_scores = model.anomaly_scores(rows)
    anomaly_flags = [int(prediction) == -1 for prediction in predictions]
    benign_label = str(benign_label)
    labels = label_series.astype(str).tolist()
    benign_scores = [
        float(score)
        for label, score in zip(labels, anomaly_scores)
        if label == benign_label
    ]
    malicious_scores = [
        float(score)
        for label, score in zip(labels, anomaly_scores)
        if label != benign_label
    ]

    benign_total = sum(1 for label in labels if label == benign_label)
    benign_false_positives = sum(
        1
        for label, flag in zip(labels, anomaly_flags)
        if label == benign_label and flag
    )
    malicious_total = sum(1 for label in labels if label != benign_label)
    malicious_detected = sum(
        1
        for label, flag in zip(labels, anomaly_flags)
        if label != benign_label and flag
    )

    metrics = {
        "rows_evaluated": int(len(labels)),
        "benign_rows": int(benign_total),
        "malicious_rows": int(malicious_total),
        "benign_false_positive_rate": (
            float(benign_false_positives) / float(benign_total)
            if benign_total
            else 0.0
        ),
        "anomaly_detection_rate": (
            float(malicious_detected) / float(malicious_total)
            if malicious_total
            else 0.0
        ),
        "average_anomaly_score": (
            float(sum(anomaly_scores)) / float(len(anomaly_scores))
            if anomaly_scores
            else 0.0
        ),
        "benign_score_summary": _score_summary(benign_scores),
        "malicious_score_summary": _score_summary(malicious_scores),
    }

    if family_series is not None:
        family_metrics = {}
        for family_name in sorted(set(family_series.astype(str).tolist())):
            if not family_name or family_name == benign_label:
                continue
            family_mask = family_series.astype(str) == family_name
            family_total = int(family_mask.sum())
            if family_total <= 0:
                continue
            family_detected = sum(
                1
                for flag, include_row in zip(anomaly_flags, family_mask.tolist())
                if include_row and flag
            )
            family_metrics[family_name] = {
                "rows": family_total,
                "detection_rate": float(family_detected) / float(family_total),
            }
        if family_metrics:
            metrics["per_family_detection"] = family_metrics

    return metrics


def _build_family_labels(pandas_module, dataframe, args):
    family_args = argparse.Namespace(**dict(vars(args), label_mode="family"))
    try:
        _, family_labels, _, _ = build_runtime_training_frame(
            pandas_module,
            dataframe,
            family_args,
        )
        return family_labels, None
    except ValueError as exc:
        return None, str(exc)


def summarize_benign_diversity(dataframe, schema, benign_label):
    label_series = dataframe[schema.label_column].fillna("").astype(str).str.strip().str.lower()
    benign_mask = label_series == str(benign_label).strip().lower()

    summary = {
        "benign_source_rows": int(benign_mask.sum()),
        "benign_family_count": 0,
        "benign_family_distribution": {},
        "benign_scenario_count": 0,
        "benign_scenario_distribution": {},
    }

    if schema.scenario_family_column:
        family_values = (
            dataframe.loc[benign_mask, schema.scenario_family_column]
            .fillna("")
            .astype(str)
            .str.strip()
        )
        family_counts = Counter(value for value in family_values.tolist() if value)
        summary["benign_family_count"] = int(len(family_counts))
        summary["benign_family_distribution"] = dict(sorted(family_counts.items()))

    scenario_column = schema.scenario_id_column or schema.scenario_column
    if scenario_column:
        scenario_values = (
            dataframe.loc[benign_mask, scenario_column]
            .fillna("")
            .astype(str)
            .str.strip()
        )
        scenario_counts = Counter(value for value in scenario_values.tolist() if value)
        summary["benign_scenario_count"] = int(len(scenario_counts))
        summary["benign_scenario_distribution"] = dict(sorted(scenario_counts.items()))

    return summary


def main():
    args = parse_args()

    try:
        import pandas as pd
        from sklearn.ensemble import IsolationForest
        from sklearn.model_selection import train_test_split
    except ImportError as exc:
        print(
            "Offline anomaly dependencies are missing: %s\n"
            "Install requirements-ml.txt in a separate training environment." % exc,
            file=sys.stderr,
        )
        return 1

    dataset_argument = args.merged_runtime_data or args.dataset or "datasets/merged_runtime_dataset.parquet"
    dataset_path = Path(dataset_argument)
    if not dataset_path.exists():
        print("Dataset not found: %s" % dataset_path, file=sys.stderr)
        return 1

    try:
        dataset_paths = resolve_input_datasets(dataset_path, args.additional_runtime_dir)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    dataframe, input_row_counts = load_combined_dataset(pd, dataset_paths)
    training_args = argparse.Namespace(**dict(vars(args), label_mode="binary"))
    try:
        schema = resolve_schema_columns(dataframe.columns, training_args)
        feature_frame, label_series, _, metadata = build_runtime_training_frame(
            pd,
            dataframe,
            training_args,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if feature_frame.empty:
        print("No usable rows were extracted from the dataset.", file=sys.stderr)
        return 1

    try:
        benign_train, benign_holdout = select_benign_training_rows(
            feature_frame,
            label_series,
            args.benign_label,
            args.test_size,
            args.random_state,
            train_test_split,
            minimum_benign_rows=args.minimum_benign_rows,
            max_benign_training_rows=args.max_benign_training_rows,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    contamination = parse_contamination(args.contamination)
    max_samples = parse_max_samples(args.max_samples)
    detector = IsolationForest(
        n_estimators=args.n_estimators,
        contamination=contamination,
        max_samples=max_samples,
        random_state=args.random_state,
    )
    detector.fit(benign_train)

    runtime_model = export_isolation_forest_model(detector)

    benign_mask = label_series.astype(str) == str(args.benign_label)
    malicious_eval = feature_frame[~benign_mask].reset_index(drop=True)
    eval_feature_frame = pd.concat(
        [benign_holdout.reset_index(drop=True), malicious_eval],
        ignore_index=True,
        sort=False,
    )
    eval_labels = pd.Series(
        [args.benign_label] * len(benign_holdout)
        + label_series[~benign_mask].astype(str).tolist(),
        dtype="object",
    )

    family_labels, family_warning = _build_family_labels(pd, dataframe, args)
    eval_family_labels = None
    if family_labels is not None:
        eval_family_labels = pd.Series(
            [args.benign_label] * len(benign_holdout)
            + family_labels[~benign_mask].astype(str).tolist(),
            dtype="object",
        )

    metrics_payload = evaluate_anomaly_model(
        runtime_model,
        eval_feature_frame[list(RUNTIME_FEATURE_NAMES)],
        eval_labels,
        family_series=eval_family_labels,
        benign_label=args.benign_label,
    )
    diversity_summary = summarize_benign_diversity(
        dataframe,
        schema,
        args.benign_label,
    )
    metrics_payload.update(
        {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "dataset_paths": [str(path) for path in dataset_paths],
            "input_row_counts": input_row_counts,
            "combined_rows": int(len(dataframe)),
            "runtime_training_rows": int(len(feature_frame)),
            "training_benign_rows": int(len(benign_train)),
            "holdout_benign_rows": int(len(benign_holdout)),
            "features_used": list(RUNTIME_FEATURE_NAMES),
            "contamination": contamination,
            "max_samples": max_samples,
            "n_estimators": args.n_estimators,
            "random_state": args.random_state,
            "max_benign_training_rows": int(args.max_benign_training_rows or 0),
            "schema_notes": metadata,
            "benign_diversity": diversity_summary,
        }
    )
    if family_warning:
        metrics_payload["family_metrics_warning"] = family_warning

    bundle = {
        "model": runtime_model,
        "feature_names": list(RUNTIME_FEATURE_NAMES),
        "positive_labels": ["anomalous"],
        "metadata": {
            "model_name": "isolation_forest",
            "model_version": "1",
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "dataset_path": str(dataset_path),
            "dataset_paths": [str(path) for path in dataset_paths],
            "input_row_counts": input_row_counts,
            "combined_rows": int(len(dataframe)),
            "training_rows": int(len(benign_train)),
            "evaluation_rows": int(len(eval_feature_frame)),
            "runtime_model_type": "portable_isolation_forest",
            "tree_count": int(len(runtime_model.trees)),
            "contamination": contamination,
            "max_samples": max_samples,
            "n_estimators": args.n_estimators,
            "anomaly_threshold": float(runtime_model.anomaly_threshold),
            "benign_label": args.benign_label,
            "max_benign_training_rows": int(args.max_benign_training_rows or 0),
            "metrics": metrics_payload,
            "benign_diversity": diversity_summary,
            "schema_notes": metadata,
        },
    }
    save_model_bundle(args.model_out, bundle)

    if args.metrics_out:
        metrics_path = Path(args.metrics_out)
        metrics_path.parent.mkdir(parents=True, exist_ok=True)
        metrics_path.write_text(json.dumps(metrics_payload, indent=2, sort_keys=True))

    print("Saved anomaly model bundle to %s" % args.model_out)
    if args.metrics_out:
        print("Saved anomaly metrics to %s" % args.metrics_out)
    print("Benign false positive rate: %.6f" % metrics_payload["benign_false_positive_rate"])
    print("Anomaly detection rate: %.6f" % metrics_payload["anomaly_detection_rate"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
