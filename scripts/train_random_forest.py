#!/usr/bin/env python3
"""Offline Random Forest training utility for the optional ML IDS module.

This script is intentionally offline-only. The live controller only performs:
1. rolling-window feature extraction
2. model loading
3. inference

The CIC parquet schema can vary slightly across collections. The helpers below
therefore:
- normalize column names
- search for a set of candidate column names
- approximate runtime features when exact matches do not exist

The trained model only uses features that can be approximated from live
controller telemetry.
"""

from __future__ import print_function

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml.feature_engineering import (
    baseline_ratio,
    burstiness,
    entropy,
    inter_arrival_stats,
    new_value_ratio,
    standard_deviation,
    trend_delta,
)
from ml.feature_extractor import RUNTIME_FEATURE_NAMES
from ml.model_loader import save_model_bundle
from ml.runtime_forest import export_random_forest_model


BENIGN_LABEL_KEYWORDS = ("benign", "normal", "background")
LIVE_COMPATIBLE_SCHEMA_FIELDS = (
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "timestamp",
)
EXTENDED_RUNTIME_FEATURE_NAMES = (
    "inter_arrival_mean_short",
    "inter_arrival_std_short",
    "inter_arrival_mean_medium",
    "inter_arrival_std_medium",
    "burstiness_short",
    "destination_ip_entropy_short",
    "destination_port_entropy_short",
    "protocol_entropy_short",
    "packet_size_std_short",
    "new_destination_ip_ratio_short",
    "new_destination_port_ratio_short",
    "host_packet_rate_baseline_ratio",
    "host_unique_dest_ip_baseline_ratio",
    "host_unique_dest_port_baseline_ratio",
    "host_unanswered_syn_ratio_baseline_ratio",
    "packet_rate_trend",
    "unique_destination_port_trend",
    "unanswered_syn_ratio_trend",
)


def summarize_feature_importances(feature_names, importance_values, top_k=6):
    """Return stable, lightweight feature-importance metadata for runtime bundles."""

    resolved_names = list(feature_names or ())
    resolved_values = list(importance_values or ())
    if not resolved_names or not resolved_values:
        return {
            "feature_importance_available": False,
            "global_feature_importance": [],
            "top_global_features": [],
            "feature_importance_source": "random_forest_global_importance",
        }

    paired_entries = []
    for feature_name, importance in zip(resolved_names, resolved_values):
        paired_entries.append(
            {
                "feature": str(feature_name),
                "importance": round(float(importance), 8),
            }
        )
    paired_entries.sort(
        key=lambda item: (-float(item["importance"]), str(item["feature"]))
    )
    return {
        "feature_importance_available": any(
            float(item["importance"]) > 0.0 for item in paired_entries
        ),
        "global_feature_importance": paired_entries,
        "top_global_features": paired_entries[: max(0, int(top_k or 0))],
        "feature_importance_source": "random_forest_global_importance",
    }


@dataclass(frozen=True)
class ResolvedSchema(object):
    """Resolved parquet schema columns used for runtime-compatible training."""

    label_column: str
    src_ip_column: str = None
    dst_ip_column: str = None
    timestamp_column: str = None
    dst_port_column: str = None
    protocol_column: str = None
    run_id_column: str = None
    scenario_column: str = None
    scenario_family_column: str = None
    scenario_id_column: str = None
    collection_id_column: str = None
    packet_count_column: str = None
    backward_packet_count_column: str = None
    byte_count_column: str = None
    backward_byte_count_column: str = None
    flow_duration_column: str = None
    syn_flag_column: str = None
    rst_flag_column: str = None
    live_compatible: bool = False
    missing_live_columns: tuple = ()


def _normalize_column_name(value):
    characters = []
    for character in str(value).strip().lower():
        if character.isalnum():
            characters.append(character)
        else:
            characters.append("_")
    normalized = "".join(characters)
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    return normalized.strip("_")


def _column_lookup(dataframe):
    lookup = {}
    for column_name in dataframe.columns:
        lookup[_normalize_column_name(column_name)] = column_name
    return lookup


def _resolve_column(lookup, candidates, explicit_name=None):
    if explicit_name:
        explicit_normalized = _normalize_column_name(explicit_name)
        return lookup.get(explicit_normalized, explicit_name)

    for candidate in candidates:
        actual_name = lookup.get(_normalize_column_name(candidate))
        if actual_name is not None:
            return actual_name
    return None


def _numeric_series(pandas_module, dataframe, column_name, default_value=0.0):
    if column_name is None:
        return pandas_module.Series(default_value, index=dataframe.index, dtype="float64")
    return pandas_module.to_numeric(dataframe[column_name], errors="coerce").fillna(default_value)


def _text_series(pandas_module, dataframe, column_name, default_value=""):
    if column_name is None:
        return pandas_module.Series(default_value, index=dataframe.index, dtype="object")
    return dataframe[column_name].fillna(default_value).astype(str)


def _protocol_indicator(pandas_module, protocol_series, numeric_code, text_name):
    lower_series = protocol_series.astype(str).str.strip().str.lower()
    numeric_series = pandas_module.to_numeric(protocol_series, errors="coerce")
    return ((lower_series == text_name) | (numeric_series == numeric_code)).astype("int64")


def _normalized_protocol_series(pandas_module, protocol_series):
    lower_series = protocol_series.astype(str).str.strip().str.lower()
    normalized = lower_series.copy()
    numeric_series = pandas_module.to_numeric(protocol_series, errors="coerce")
    normalized = normalized.where(~numeric_series.eq(6), "tcp")
    normalized = normalized.where(~numeric_series.eq(17), "udp")
    normalized = normalized.where(~numeric_series.eq(1), "icmp")
    normalized = normalized.where(normalized != "", "unknown")
    return normalized


def _binary_label_series(label_series):
    labels = label_series.fillna("unknown").astype(str).str.strip()
    lower_labels = labels.str.lower()
    benign_mask = lower_labels.apply(
        lambda value: any(keyword in value for keyword in BENIGN_LABEL_KEYWORDS)
    )
    return benign_mask.map({True: "benign", False: "malicious"})


def _clean_label_value(value):
    text = str(value).strip()
    return "" if text.lower() in ("", "none", "nan", "null") else text


def _is_benign_label(value):
    return any(keyword in str(value).strip().lower() for keyword in BENIGN_LABEL_KEYWORDS)


def _aggregate_group_label(values, label_mode):
    labels = [_clean_label_value(value) for value in values]
    non_benign = sorted({label for label in labels if label and label != "benign"})
    if label_mode == "binary":
        return "malicious" if non_benign else "benign"
    if not non_benign:
        return "benign"
    if len(non_benign) == 1:
        return non_benign[0]
    raise ValueError(
        "Grouped splitting requires each group/window to map to one non-benign %s label. "
        "Observed labels: %s"
        % (label_mode, ", ".join(non_benign))
    )


def build_training_labels(
    raw_labels,
    label_mode="binary",
    scenario_family_values=None,
    scenario_id_values=None,
    scenario_values=None,
):
    """Resolve training target labels for binary and multi-class modes."""

    label_mode = str(label_mode or "binary").strip().lower()
    cleaned_labels = [_clean_label_value(value) for value in raw_labels]

    if label_mode == "binary":
        resolved_labels = [
            "benign" if _is_benign_label(value) else "malicious"
            for value in cleaned_labels
        ]
        return resolved_labels, ["malicious"]

    if label_mode == "family":
        if scenario_family_values is None:
            raise ValueError("Label mode 'family' requires scenario-family metadata.")
        family_values = [_clean_label_value(value) for value in scenario_family_values]
        resolved_labels = []
        for raw_label, family_value in zip(cleaned_labels, family_values):
            if _is_benign_label(raw_label):
                resolved_labels.append("benign")
                continue
            if not family_value:
                raise ValueError(
                    "Label mode 'family' requires scenario-family values for all non-benign rows."
                )
            resolved_labels.append(family_value)
        positive_labels = sorted({value for value in resolved_labels if value != "benign"})
        return resolved_labels, positive_labels

    if label_mode == "scenario":
        if scenario_id_values is None and scenario_values is None:
            raise ValueError(
                "Label mode 'scenario' requires scenario ID or scenario name metadata."
            )
        scenario_id_values = (
            [_clean_label_value(value) for value in scenario_id_values]
            if scenario_id_values is not None
            else [""] * len(cleaned_labels)
        )
        scenario_values = (
            [_clean_label_value(value) for value in scenario_values]
            if scenario_values is not None
            else [""] * len(cleaned_labels)
        )
        resolved_labels = []
        for raw_label, scenario_id_value, scenario_value in zip(
            cleaned_labels,
            scenario_id_values,
            scenario_values,
        ):
            if _is_benign_label(raw_label):
                resolved_labels.append("benign")
                continue
            scenario_label = scenario_id_value or scenario_value
            if not scenario_label:
                raise ValueError(
                    "Label mode 'scenario' requires scenario ID or scenario name values for all non-benign rows."
                )
            resolved_labels.append(scenario_label)
        positive_labels = sorted({value for value in resolved_labels if value != "benign"})
        return resolved_labels, positive_labels

    raise ValueError("Unsupported label mode: %s" % label_mode)


def _summarize_feature_sources(source_map):
    return dict((key, value) for key, value in sorted(source_map.items()))


def resolve_schema_columns(column_names, args):
    """Resolve parquet columns and validate live-runtime compatibility.

    The SDN controller computes host-window features such as unique destination
    ports, unique destination IPs, protocol rates, and failed-connection rates.
    Training on parquet data that lacks those identifiers creates a misleading
    model: offline metrics may look acceptable, but live controller inference
    cannot match that feature space. The trainer therefore refuses such schemas
    by default.
    """

    lookup = {}
    for column_name in column_names:
        lookup[_normalize_column_name(column_name)] = column_name

    label_column = _resolve_column(
        lookup,
        ("label", "class", "classlabel", "attack_label", "traffic_label"),
        explicit_name=args.label_column,
    )
    if label_column is None:
        raise ValueError(
            "Could not find a label column. Pass --label-column if the parquet schema differs."
        )

    resolved = ResolvedSchema(
        label_column=label_column,
        src_ip_column=_resolve_column(
            lookup,
            ("src_ip", "source_ip", "source_ipv4_address"),
            explicit_name=args.src_ip_column,
        ),
        dst_ip_column=_resolve_column(
            lookup,
            ("dst_ip", "destination_ip", "destination_ipv4_address"),
            explicit_name=args.dst_ip_column,
        ),
        timestamp_column=_resolve_column(
            lookup,
            ("timestamp", "flow_start", "flow_start_time", "start_time"),
            explicit_name=args.timestamp_column,
        ),
        dst_port_column=_resolve_column(
            lookup,
            ("dst_port", "destination_port", "port", "dstport"),
            explicit_name=args.dst_port_column,
        ),
        protocol_column=_resolve_column(
            lookup,
            ("protocol", "protocol_name", "proto", "ip_protocol"),
            explicit_name=args.protocol_column,
        ),
        run_id_column=_resolve_column(
            lookup,
            ("run_id", "scenario_run_id", "runid"),
            explicit_name=args.run_id_column,
        ),
        scenario_column=_resolve_column(
            lookup,
            ("scenario", "scenario_name"),
            explicit_name=args.scenario_column,
        ),
        scenario_family_column=_resolve_column(
            lookup,
            ("scenario_family", "attack_family", "family"),
            explicit_name=getattr(args, "scenario_family_column", None),
        ),
        scenario_id_column=_resolve_column(
            lookup,
            ("scenario_id", "scenario_family", "scenario_type"),
            explicit_name=args.scenario_id_column,
        ),
        collection_id_column=_resolve_column(
            lookup,
            ("collection_id", "collector_session_id"),
        ),
        packet_count_column=_resolve_column(
            lookup,
            (
                "total_packets",
                "tot_pkts",
                "pkt_count",
                "flow_packets_s",
                "flow_packets",
                "tot_fwd_pkts",
                "total_fwd_packets",
            ),
        ),
        backward_packet_count_column=_resolve_column(
            lookup,
            ("tot_bwd_pkts", "total_backward_packets", "bwd_pkt_count"),
        ),
        byte_count_column=_resolve_column(
            lookup,
            (
                "total_bytes",
                "flow_bytes_s",
                "totlen_fwd_pkts",
                "tot_len_fwd_pkts",
                "fwd_packets_length_total",
                "bytes",
                "flow_bytes",
            ),
        ),
        backward_byte_count_column=_resolve_column(
            lookup,
            (
                "totlen_bwd_pkts",
                "tot_len_bwd_pkts",
                "bwd_packets_length_total",
                "total_backward_bytes",
            ),
        ),
        flow_duration_column=_resolve_column(
            lookup,
            ("flow_duration", "duration", "flow_duration_ms", "flow_duration_s"),
        ),
        syn_flag_column=_resolve_column(
            lookup,
            ("syn_flag_cnt", "syn_flag_count", "syn_count"),
        ),
        rst_flag_column=_resolve_column(
            lookup,
            ("rst_flag_cnt", "rst_flag_count", "rst_count"),
        ),
    )

    missing_live_columns = tuple(
        field_name
        for field_name in LIVE_COMPATIBLE_SCHEMA_FIELDS
        if getattr(resolved, "%s_column" % field_name) is None
    )
    resolved = ResolvedSchema(
        **dict(resolved.__dict__, live_compatible=not missing_live_columns, missing_live_columns=missing_live_columns)
    )

    if missing_live_columns and not args.allow_degraded_training:
        raise ValueError(
            "Dataset schema is not suitable for live-compatible SDN ML training. "
            "Missing required columns for %s: %s. "
            "Preferred dataset: CICIDS2018-style flow parquet with columns such as "
            "'Src IP', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', and 'Label'. "
            "Use --allow-degraded-training only for exploratory offline experiments."
            % (args.dataset_profile, ", ".join(missing_live_columns))
        )

    return resolved


def _resolve_group_column(schema):
    for field_name in (
        "run_id_column",
        "scenario_column",
        "scenario_id_column",
        "collection_id_column",
    ):
        column_name = getattr(schema, field_name)
        if column_name:
            return column_name
    return None


def _timestamp_to_epoch_seconds(timestamp_value):
    if hasattr(timestamp_value, "timestamp"):
        return float(timestamp_value.timestamp())
    return float(timestamp_value)


def build_extended_runtime_feature_frame(
    pandas_module,
    grouped_frame,
    aggregated_frame,
    groupby_keys,
    window_seconds,
):
    """Build richer live-aligned engineered features from grouped runtime windows.

    These features are currently computed for alignment and future retraining
    without changing the default model vector, which remains RUNTIME_FEATURE_NAMES.
    """

    if (
        grouped_frame is None
        or grouped_frame.empty
        or aggregated_frame is None
        or aggregated_frame.empty
    ):
        return pandas_module.DataFrame(
            columns=list(groupby_keys) + list(EXTENDED_RUNTIME_FEATURE_NAMES)
        )

    window_seconds = float(window_seconds)
    medium_window_seconds = max(30.0, window_seconds)
    long_window_seconds = max(120.0, medium_window_seconds)
    history_key_names = [name for name in groupby_keys if name != "window_start"]

    per_window_records = {}
    ordered_grouped_frame = grouped_frame.sort_values(list(groupby_keys) + ["timestamp"])
    for group_key, group in ordered_grouped_frame.groupby(groupby_keys, sort=False):
        if not isinstance(group_key, tuple):
            group_key = (group_key,)
        timestamps = [
            _timestamp_to_epoch_seconds(value)
            for value in group["timestamp"].tolist()
        ]
        destination_ips = [
            value for value in group["dst_ip"].astype(str).tolist() if value
        ]
        destination_ports = [
            int(value)
            for value in group["dst_port"].tolist()
            if int(value) >= 0
        ]
        protocol_values = group["protocol_name"].astype(str).tolist()
        packet_sizes = (
            group["byte_count"] / group["packet_count"].clip(lower=1.0)
        ).astype("float64").tolist()
        inter_arrival_mean_short, inter_arrival_std_short = inter_arrival_stats(
            timestamps
        )
        per_window_records[group_key] = {
            "timestamps": timestamps,
            "destination_ip_set": set(destination_ips),
            "destination_port_set": set(destination_ports),
            "packet_count": float(group["packet_count"].sum()),
            "syn_counts": float(group["syn_counts"].sum()),
            "unanswered_syn_count": 0.0,
            "inter_arrival_mean_short": inter_arrival_mean_short,
            "inter_arrival_std_short": inter_arrival_std_short,
            "burstiness_short": burstiness(
                inter_arrival_mean_short,
                inter_arrival_std_short,
            ),
            "destination_ip_entropy_short": entropy(destination_ips),
            "destination_port_entropy_short": entropy(destination_ports),
            "protocol_entropy_short": entropy(protocol_values),
            "packet_size_std_short": standard_deviation(packet_sizes),
        }

    extension_rows = []
    alpha = 0.25
    ordered_aggregated = aggregated_frame.sort_values(list(groupby_keys)).reset_index(drop=True)
    host_groups = (
        ordered_aggregated.groupby(history_key_names, sort=False)
        if history_key_names
        else [((), ordered_aggregated)]
    )

    for host_group_key, host_frame in host_groups:
        history = []
        baseline = {}
        if history_key_names and not isinstance(host_group_key, tuple):
            host_group_key = (host_group_key,)
        elif not history_key_names:
            host_group_key = ()

        for _, row in host_frame.iterrows():
            current_group_key = tuple(row[name] for name in groupby_keys)
            current_window = per_window_records.get(current_group_key, {})
            window_start_seconds = _timestamp_to_epoch_seconds(row["window_start"])
            window_end_seconds = window_start_seconds + window_seconds

            medium_cutoff = window_end_seconds - medium_window_seconds
            long_cutoff = window_end_seconds - long_window_seconds
            medium_history = [
                summary for summary in history if summary["window_end_seconds"] >= medium_cutoff
            ]
            long_history = [
                summary for summary in history if summary["window_end_seconds"] >= long_cutoff
            ]
            medium_summaries = list(medium_history)
            current_summary = {
                "window_end_seconds": window_end_seconds,
                "timestamps": list(current_window.get("timestamps", [])),
                "destination_ip_set": set(current_window.get("destination_ip_set", set())),
                "destination_port_set": set(current_window.get("destination_port_set", set())),
                "packet_count": float(row["packet_count"]),
                "syn_counts": float(row["syn_counts"]),
                "unanswered_syn_count": float(row["unanswered_syn_count"]),
            }
            medium_summaries.append(current_summary)

            medium_timestamps = []
            medium_destination_ports = set()
            medium_syn_count = 0.0
            medium_unanswered_syn_count = 0.0
            medium_packet_count = 0.0
            for summary in medium_summaries:
                medium_timestamps.extend(summary["timestamps"])
                medium_destination_ports.update(summary["destination_port_set"])
                medium_syn_count += float(summary["syn_counts"])
                medium_unanswered_syn_count += float(summary["unanswered_syn_count"])
                medium_packet_count += float(summary["packet_count"])

            medium_timestamps = sorted(medium_timestamps)
            medium_observation_window_seconds = (
                max(
                    1.0,
                    min(
                        medium_window_seconds,
                        window_end_seconds - medium_timestamps[0] + 0.001,
                    ),
                )
                if medium_timestamps
                else 1.0
            )
            inter_arrival_mean_medium, inter_arrival_std_medium = inter_arrival_stats(
                medium_timestamps
            )
            medium_packet_rate = medium_packet_count / medium_observation_window_seconds
            medium_unique_destination_port_rate = (
                float(len(medium_destination_ports)) / medium_observation_window_seconds
                if medium_destination_ports
                else 0.0
            )
            medium_unanswered_syn_ratio = (
                min(1.0, medium_unanswered_syn_count / medium_syn_count)
                if medium_syn_count
                else 0.0
            )

            historical_destination_ips = set()
            historical_destination_ports = set()
            for summary in long_history:
                historical_destination_ips.update(summary["destination_ip_set"])
                historical_destination_ports.update(summary["destination_port_set"])

            host_packet_rate_baseline_ratio = baseline_ratio(
                row["packet_rate"],
                baseline.get("packet_rate"),
            )
            host_unique_dest_ip_baseline_ratio = baseline_ratio(
                row["unique_destination_ips"],
                baseline.get("unique_destination_ips"),
            )
            host_unique_dest_port_baseline_ratio = baseline_ratio(
                row["unique_destination_ports"],
                baseline.get("unique_destination_ports"),
            )
            host_unanswered_syn_ratio_baseline_ratio = baseline_ratio(
                row["unanswered_syn_ratio"],
                baseline.get("unanswered_syn_ratio"),
            )

            extension_row = dict((name, row[name]) for name in groupby_keys)
            extension_row.update(
                {
                    "inter_arrival_mean_short": float(
                        current_window.get("inter_arrival_mean_short", 0.0)
                    ),
                    "inter_arrival_std_short": float(
                        current_window.get("inter_arrival_std_short", 0.0)
                    ),
                    "inter_arrival_mean_medium": float(inter_arrival_mean_medium),
                    "inter_arrival_std_medium": float(inter_arrival_std_medium),
                    "burstiness_short": float(current_window.get("burstiness_short", 0.0)),
                    "destination_ip_entropy_short": float(
                        current_window.get("destination_ip_entropy_short", 0.0)
                    ),
                    "destination_port_entropy_short": float(
                        current_window.get("destination_port_entropy_short", 0.0)
                    ),
                    "protocol_entropy_short": float(
                        current_window.get("protocol_entropy_short", 0.0)
                    ),
                    "packet_size_std_short": float(
                        current_window.get("packet_size_std_short", 0.0)
                    ),
                    "new_destination_ip_ratio_short": float(
                        new_value_ratio(
                            current_window.get("destination_ip_set", set()),
                            historical_destination_ips,
                        )
                    ),
                    "new_destination_port_ratio_short": float(
                        new_value_ratio(
                            current_window.get("destination_port_set", set()),
                            historical_destination_ports,
                        )
                    ),
                    "host_packet_rate_baseline_ratio": float(
                        host_packet_rate_baseline_ratio
                    ),
                    "host_unique_dest_ip_baseline_ratio": float(
                        host_unique_dest_ip_baseline_ratio
                    ),
                    "host_unique_dest_port_baseline_ratio": float(
                        host_unique_dest_port_baseline_ratio
                    ),
                    "host_unanswered_syn_ratio_baseline_ratio": float(
                        host_unanswered_syn_ratio_baseline_ratio
                    ),
                    "packet_rate_trend": float(
                        trend_delta(row["packet_rate"], medium_packet_rate)
                    ),
                    "unique_destination_port_trend": float(
                        trend_delta(
                            row["unique_destination_ports"] / window_seconds,
                            medium_unique_destination_port_rate,
                        )
                    ),
                    "unanswered_syn_ratio_trend": float(
                        trend_delta(
                            row["unanswered_syn_ratio"],
                            medium_unanswered_syn_ratio,
                        )
                    ),
                }
            )
            extension_rows.append(extension_row)

            for baseline_name in (
                "packet_rate",
                "unique_destination_ips",
                "unique_destination_ports",
                "unanswered_syn_ratio",
            ):
                current_value = float(row[baseline_name])
                previous_value = baseline.get(baseline_name)
                if previous_value is None:
                    baseline[baseline_name] = current_value
                else:
                    baseline[baseline_name] = (
                        (1.0 - alpha) * float(previous_value)
                    ) + (alpha * current_value)
            history.append(current_summary)

    if not extension_rows:
        return pandas_module.DataFrame(
            columns=list(groupby_keys) + list(EXTENDED_RUNTIME_FEATURE_NAMES)
        )
    return pandas_module.DataFrame(extension_rows)


def build_runtime_training_frame(pandas_module, dataframe, args):
    """Map CIC parquet columns into runtime-observable host-window features."""

    schema = resolve_schema_columns(dataframe.columns, args)

    label_column = schema.label_column
    src_ip_column = schema.src_ip_column
    dst_ip_column = schema.dst_ip_column
    timestamp_column = schema.timestamp_column
    dst_port_column = schema.dst_port_column
    protocol_column = schema.protocol_column
    group_column = _resolve_group_column(schema)
    scenario_column = schema.scenario_column
    scenario_family_column = schema.scenario_family_column
    scenario_id_column = schema.scenario_id_column
    packet_count_column = schema.packet_count_column
    backward_packet_count_column = schema.backward_packet_count_column
    byte_count_column = schema.byte_count_column
    backward_byte_count_column = schema.backward_byte_count_column
    flow_duration_column = schema.flow_duration_column
    syn_flag_column = schema.syn_flag_column
    rst_flag_column = schema.rst_flag_column

    raw_label_series = _text_series(pandas_module, dataframe, label_column)
    scenario_family_series = (
        _text_series(pandas_module, dataframe, scenario_family_column, "")
        if scenario_family_column
        else None
    )
    scenario_id_series = (
        _text_series(pandas_module, dataframe, scenario_id_column, "")
        if scenario_id_column
        else None
    )
    scenario_series = (
        _text_series(pandas_module, dataframe, scenario_column, "")
        if scenario_column
        else None
    )
    resolved_labels, positive_labels = build_training_labels(
        raw_label_series.tolist(),
        label_mode=args.label_mode,
        scenario_family_values=(
            scenario_family_series.tolist() if scenario_family_series is not None else None
        ),
        scenario_id_values=(
            scenario_id_series.tolist() if scenario_id_series is not None else None
        ),
        scenario_values=(scenario_series.tolist() if scenario_series is not None else None),
    )
    labels = pandas_module.Series(resolved_labels, index=dataframe.index, dtype="object")

    packet_count = _numeric_series(pandas_module, dataframe, packet_count_column, 1.0)
    if backward_packet_count_column is not None:
        packet_count = packet_count + _numeric_series(
            pandas_module,
            dataframe,
            backward_packet_count_column,
            0.0,
        )
    packet_count = packet_count.clip(lower=1.0)

    byte_count = _numeric_series(pandas_module, dataframe, byte_count_column, 0.0)
    if backward_byte_count_column is not None:
        byte_count = byte_count + _numeric_series(
            pandas_module,
            dataframe,
            backward_byte_count_column,
            0.0,
        )

    duration_series = _numeric_series(pandas_module, dataframe, flow_duration_column, float(args.window_seconds))
    duration_series = duration_series.clip(lower=1.0)
    if flow_duration_column and "ms" in _normalize_column_name(flow_duration_column):
        duration_series = duration_series / 1000.0
    elif flow_duration_column and "duration" in _normalize_column_name(flow_duration_column):
        duration_series = duration_series
    else:
        duration_series = duration_series

    protocol_series = _text_series(pandas_module, dataframe, protocol_column, "")
    normalized_protocol_series = _normalized_protocol_series(
        pandas_module,
        protocol_series,
    )
    tcp_indicator = _protocol_indicator(pandas_module, protocol_series, 6, "tcp")
    udp_indicator = _protocol_indicator(pandas_module, protocol_series, 17, "udp")
    icmp_indicator = _protocol_indicator(pandas_module, protocol_series, 1, "icmp")
    syn_counts = _numeric_series(pandas_module, dataframe, syn_flag_column, 0.0)
    rst_counts = _numeric_series(pandas_module, dataframe, rst_flag_column, 0.0)

    source_map = {
        "label": label_column,
        "src_ip": src_ip_column,
        "dst_ip": dst_ip_column,
        "timestamp": timestamp_column,
        "dst_port": dst_port_column,
        "protocol": protocol_column,
        "group": group_column,
        "scenario": scenario_column,
        "scenario_family": scenario_family_column,
        "scenario_id": scenario_id_column,
        "packet_count": packet_count_column,
        "byte_count": byte_count_column,
        "flow_duration": flow_duration_column,
        "syn_flags": syn_flag_column,
        "rst_flags": rst_flag_column,
    }

    grouped_frame = None
    grouped_by_window = bool(src_ip_column and timestamp_column)
    if grouped_by_window:
        timestamp_series = pandas_module.to_datetime(
            dataframe[timestamp_column],
            errors="coerce",
            utc=True,
        )
        grouped_frame = pandas_module.DataFrame(
            {
                "src_ip": _text_series(pandas_module, dataframe, src_ip_column, "unknown"),
                "dst_ip": _text_series(pandas_module, dataframe, dst_ip_column, ""),
                "dst_port": _numeric_series(pandas_module, dataframe, dst_port_column, -1).astype("int64"),
                "timestamp": timestamp_series,
                "protocol_name": normalized_protocol_series,
                "label": labels,
                "packet_count": packet_count,
                "byte_count": byte_count,
                "duration_seconds": duration_series,
                "tcp_indicator": tcp_indicator,
                "udp_indicator": udp_indicator,
                "icmp_indicator": icmp_indicator,
                "syn_counts": syn_counts,
                "rst_counts": rst_counts,
                "connection_attempts": 1.0,
                "group_id": _text_series(pandas_module, dataframe, group_column, "") if group_column else "",
            }
        ).dropna(subset=["timestamp"])
        grouped_frame["window_start"] = grouped_frame["timestamp"].dt.floor("%ss" % args.window_seconds)

    groups = None
    if grouped_by_window and grouped_frame is not None and not grouped_frame.empty:
        groupby_keys = ["src_ip", "window_start"]
        if group_column:
            groupby_keys.insert(0, "group_id")

        pair_keys = list(groupby_keys) + ["dst_ip"]
        pair_aggregated = grouped_frame.groupby(pair_keys, as_index=False).agg(
            syn_counts=("syn_counts", "sum"),
            rst_counts=("rst_counts", "sum"),
            tcp_packets=("tcp_indicator", "sum"),
        )
        reverse_responses = pair_aggregated[list(pair_keys) + ["tcp_packets"]].rename(
            columns={
                "src_ip": "dst_ip",
                "dst_ip": "src_ip",
                "tcp_packets": "reverse_tcp_packets",
            }
        )
        pair_aggregated = pair_aggregated.merge(
            reverse_responses,
            on=pair_keys,
            how="left",
        )
        pair_aggregated["reverse_tcp_packets"] = pair_aggregated["reverse_tcp_packets"].fillna(0.0)
        pair_aggregated["unanswered_syn_count"] = (
            pair_aggregated["syn_counts"]
            - pair_aggregated["rst_counts"]
            - pair_aggregated["reverse_tcp_packets"]
        ).clip(lower=0.0)
        unanswered_counts = (
            pair_aggregated.groupby(groupby_keys, as_index=False)["unanswered_syn_count"].sum()
        )

        aggregated = grouped_frame.groupby(groupby_keys, as_index=False).agg(
            packet_count=("packet_count", "sum"),
            byte_count=("byte_count", "sum"),
            unique_destination_ports=("dst_port", lambda series: int(series[series >= 0].nunique())),
            unique_destination_ips=("dst_ip", lambda series: int(series[series != ""].nunique())),
            connection_attempts=("connection_attempts", "sum"),
            syn_counts=("syn_counts", "sum"),
            icmp_packets=("icmp_indicator", "sum"),
            udp_packets=("udp_indicator", "sum"),
            tcp_packets=("tcp_indicator", "sum"),
            failed_connections=("rst_counts", "sum"),
            label=("label", lambda series: _aggregate_group_label(series.tolist(), args.label_mode)),
        )
        aggregated = aggregated.merge(
            unanswered_counts,
            on=groupby_keys,
            how="left",
        )
        aggregated["unanswered_syn_count"] = aggregated["unanswered_syn_count"].fillna(0.0)
        observation_window = float(args.window_seconds)
        feature_frame = pandas_module.DataFrame(
            {
                "packet_count": aggregated["packet_count"].astype("float64"),
                "byte_count": aggregated["byte_count"].astype("float64"),
                "unique_destination_ports": aggregated["unique_destination_ports"].astype("float64"),
                "unique_destination_ips": aggregated["unique_destination_ips"].astype("float64"),
                "destination_port_fanout_ratio": (
                    aggregated["unique_destination_ports"]
                    / aggregated["connection_attempts"].clip(lower=1.0)
                ),
                "connection_rate": aggregated["connection_attempts"] / observation_window,
                "syn_rate": aggregated["syn_counts"] / observation_window,
                "icmp_rate": aggregated["icmp_packets"] / observation_window,
                "udp_rate": aggregated["udp_packets"] / observation_window,
                "tcp_rate": aggregated["tcp_packets"] / observation_window,
                "average_packet_size": aggregated["byte_count"] / aggregated["packet_count"].clip(lower=1.0),
                "observation_window_seconds": observation_window,
                "packet_rate": aggregated["packet_count"] / observation_window,
                "bytes_per_second": aggregated["byte_count"] / observation_window,
                "failed_connection_rate": aggregated["failed_connections"] / observation_window,
                "unanswered_syn_rate": aggregated["unanswered_syn_count"] / observation_window,
                "unanswered_syn_ratio": (
                    aggregated["unanswered_syn_count"]
                    / aggregated["syn_counts"].clip(lower=1.0)
                ).clip(upper=1.0),
            }
        )
        aggregated_for_extensions = aggregated.copy()
        aggregated_for_extensions["packet_rate"] = feature_frame["packet_rate"].astype("float64")
        aggregated_for_extensions["unique_destination_ips"] = feature_frame[
            "unique_destination_ips"
        ].astype("float64")
        aggregated_for_extensions["unique_destination_ports"] = feature_frame[
            "unique_destination_ports"
        ].astype("float64")
        aggregated_for_extensions["unanswered_syn_ratio"] = feature_frame[
            "unanswered_syn_ratio"
        ].astype("float64")
        extended_feature_frame = build_extended_runtime_feature_frame(
            pandas_module,
            grouped_frame,
            aggregated_for_extensions,
            groupby_keys,
            observation_window,
        )
        if not extended_feature_frame.empty:
            extension_only_frame = (
                extended_feature_frame.set_index(groupby_keys)
                .loc[
                    aggregated[groupby_keys]
                    .set_index(groupby_keys)
                    .index
                ]
                .reset_index(drop=True)
            )
            feature_frame = pandas_module.concat(
                [feature_frame.reset_index(drop=True), extension_only_frame],
                axis=1,
            )
        labels = aggregated["label"].astype(str)
        if group_column:
            groups = aggregated["group_id"].astype(str)
    else:
        feature_frame = pandas_module.DataFrame(
            {
                "packet_count": packet_count.astype("float64"),
                "byte_count": byte_count.astype("float64"),
                "unique_destination_ports": (
                    _numeric_series(pandas_module, dataframe, dst_port_column, -1).ge(0)
                ).astype("float64"),
                "unique_destination_ips": (
                    _text_series(pandas_module, dataframe, dst_ip_column, "").ne("")
                ).astype("float64"),
                "destination_port_fanout_ratio": 1.0,
                "connection_rate": 1.0 / duration_series,
                "syn_rate": syn_counts / duration_series,
                "icmp_rate": icmp_indicator / duration_series,
                "udp_rate": udp_indicator / duration_series,
                "tcp_rate": tcp_indicator / duration_series,
                "average_packet_size": byte_count / packet_count.clip(lower=1.0),
                "observation_window_seconds": duration_series,
                "packet_rate": packet_count / duration_series,
                "bytes_per_second": byte_count / duration_series,
                "failed_connection_rate": rst_counts / duration_series,
                "unanswered_syn_rate": (syn_counts - rst_counts).clip(lower=0.0) / duration_series,
                "unanswered_syn_ratio": (
                    (syn_counts - rst_counts).clip(lower=0.0)
                    / syn_counts.clip(lower=1.0)
                ).clip(upper=1.0),
            }
        )
        if group_column:
            groups = _text_series(pandas_module, dataframe, group_column, "")

    feature_frame = feature_frame.fillna(0.0)
    feature_frame = feature_frame[list(RUNTIME_FEATURE_NAMES)]
    metadata = {
        "source_columns": _summarize_feature_sources(source_map),
        "grouped_by_host_window": grouped_by_window and grouped_frame is not None and not grouped_frame.empty,
        "group_split_column": group_column,
        "group_split_ready": bool(group_column),
        "live_compatible_schema": schema.live_compatible,
        "missing_live_columns": list(schema.missing_live_columns),
        "dataset_profile": args.dataset_profile,
        "label_mode": args.label_mode,
        "positive_labels": list(positive_labels),
        "window_seconds": args.window_seconds,
        "runtime_feature_names": list(RUNTIME_FEATURE_NAMES),
        "extended_runtime_feature_names": list(EXTENDED_RUNTIME_FEATURE_NAMES),
    }
    return feature_frame, labels, groups, metadata


def split_training_frame(
    pandas_module,
    feature_frame,
    label_series,
    groups,
    args,
    train_test_split_fn,
):
    """Split samples using whole-run grouping when available."""

    if args.split_mode == "random":
        features_train, features_test, labels_train, labels_test = train_test_split_fn(
            feature_frame,
            label_series,
            test_size=args.test_size,
            random_state=args.random_state,
            stratify=label_series,
        )
        return features_train, features_test, labels_train, labels_test, {
            "split_mode": "random",
            "group_count": 0,
        }

    if groups is None:
        if args.split_mode == "grouped":
            raise ValueError(
                "Grouped splitting requires a run/scenario identifier such as "
                "'Run ID' or 'Scenario'."
            )
        features_train, features_test, labels_train, labels_test = train_test_split_fn(
            feature_frame,
            label_series,
            test_size=args.test_size,
            random_state=args.random_state,
            stratify=label_series,
        )
        return features_train, features_test, labels_train, labels_test, {
            "split_mode": "random_fallback",
            "group_count": 0,
        }

    group_frame = pandas_module.DataFrame(
        {
            "group": groups.astype(str),
            "label": label_series.astype(str),
        }
    )
    group_frame = (
        group_frame.groupby("group", as_index=False)
        .agg(label=("label", lambda series: _aggregate_group_label(series.tolist(), args.label_mode)))
    )
    group_count = int(len(group_frame))
    if group_count < 2 or group_frame["label"].nunique() < 2:
        raise ValueError("Need at least two labeled groups for grouped splitting.")

    label_counts = group_frame["label"].value_counts()
    if int(label_counts.min()) < 2:
        raise ValueError(
            "Need at least two groups per class for grouped splitting. "
            "Current group counts: %s" % label_counts.to_dict()
        )

    effective_test_size = args.test_size
    if isinstance(effective_test_size, float):
        minimum_fraction = float(group_frame["label"].nunique()) / float(group_count)
        if effective_test_size < minimum_fraction:
            effective_test_size = minimum_fraction

    train_groups, test_groups = train_test_split_fn(
        group_frame["group"],
        test_size=effective_test_size,
        random_state=args.random_state,
        stratify=group_frame["label"],
    )
    train_group_set = set(train_groups.astype(str))
    train_mask = groups.astype(str).isin(train_group_set)

    features_train = feature_frame[train_mask].reset_index(drop=True)
    features_test = feature_frame[~train_mask].reset_index(drop=True)
    labels_train = label_series[train_mask].reset_index(drop=True)
    labels_test = label_series[~train_mask].reset_index(drop=True)
    return features_train, features_test, labels_train, labels_test, {
        "split_mode": "grouped",
        "group_count": group_count,
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Train an offline Random Forest IDS model.")
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
        default="models/random_forest_ids.joblib",
        help="Output path for the serialized model bundle.",
    )
    parser.add_argument(
        "--metrics-out",
        default=None,
        help="Optional JSON metrics output path.",
    )
    parser.add_argument(
        "--feature-manifest-out",
        default=None,
        help="Optional JSON feature manifest output path.",
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
    parser.add_argument(
        "--scenario-family-column",
        default=None,
        help="Optional explicit scenario-family column.",
    )
    parser.add_argument("--scenario-id-column", default=None, help="Optional explicit scenario ID column.")
    parser.add_argument(
        "--label-mode",
        default="binary",
        choices=("binary", "family", "scenario"),
        help="Training label mode. Binary preserves current benign/malicious behavior.",
    )
    parser.add_argument(
        "--dataset-profile",
        default="cicids2018",
        choices=("cicids2018", "generic"),
        help="Schema expectations to apply during validation. CICIDS2018 is preferred.",
    )
    parser.add_argument(
        "--allow-degraded-training",
        action="store_true",
        help=(
            "Allow exploratory training even when the parquet schema cannot support "
            "live-compatible SDN features. Not recommended for runtime models."
        ),
    )
    parser.add_argument("--test-size", type=float, default=0.25, help="Hold-out evaluation split.")
    parser.add_argument(
        "--split-mode",
        default="grouped",
        choices=("grouped", "auto", "random"),
        help="Use grouped hold-out by run/scenario when possible.",
    )
    parser.add_argument("--random-state", type=int, default=42, help="Random seed.")
    parser.add_argument("--n-estimators", type=int, default=200, help="Random Forest tree count.")
    parser.add_argument("--max-depth", type=int, default=18, help="Random Forest max depth.")
    parser.add_argument(
        "--min-samples-split",
        type=int,
        default=2,
        help="Random Forest min_samples_split value.",
    )
    parser.add_argument(
        "--min-samples-leaf",
        type=int,
        default=1,
        help="Random Forest min_samples_leaf value.",
    )
    parser.add_argument(
        "--class-weight",
        default="balanced_subsample",
        help="Random Forest class_weight value. Use 'none' to disable.",
    )
    return parser.parse_args()


def _read_parquet_schema_names(dataset_path):
    try:
        import pyarrow.parquet as parquet
    except ImportError:
        return None

    return list(parquet.read_schema(str(dataset_path)).names)


def resolve_input_datasets(base_dataset_path, additional_runtime_dir):
    dataset_paths = [Path(base_dataset_path)]
    if additional_runtime_dir:
        directory = Path(additional_runtime_dir)
        if not directory.exists():
            raise ValueError("Additional runtime directory not found: %s" % directory)
        if not directory.is_dir():
            raise ValueError("Additional runtime path is not a directory: %s" % directory)
        for candidate in sorted(directory.glob("*.parquet")):
            if candidate not in dataset_paths:
                dataset_paths.append(candidate)
    return dataset_paths


def load_combined_dataset(pandas_module, dataset_paths):
    frames = []
    row_counts = {}
    for dataset_path in dataset_paths:
        dataframe = pandas_module.read_parquet(str(dataset_path))
        dataframe = dataframe.copy()
        if "Source Dataset" not in dataframe.columns:
            dataframe["Source Dataset"] = str(dataset_path)
        row_counts[str(dataset_path)] = int(len(dataframe))
        frames.append(dataframe)
    combined = pandas_module.concat(frames, ignore_index=True, sort=False)
    return combined, row_counts


def parse_class_weight(value):
    if value is None:
        return "balanced_subsample"
    text = str(value).strip().lower()
    if text in ("", "none", "null"):
        return None
    if text in ("balanced", "balanced_subsample"):
        return text
    return value


def main():
    args = parse_args()

    try:
        import pandas as pd
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import classification_report, confusion_matrix
        from sklearn.model_selection import train_test_split
    except ImportError as exc:
        print(
            "Offline ML dependencies are missing: %s\n"
            "Install requirements-ml.txt in a separate training environment." % exc,
            file=sys.stderr,
        )
        return 1

    dataset_argument = args.merged_runtime_data or args.dataset or "datasets/cicids2018.parquet"
    dataset_path = Path(dataset_argument)
    if not dataset_path.exists():
        print("Dataset not found: %s" % dataset_path, file=sys.stderr)
        return 1

    try:
        dataset_paths = resolve_input_datasets(dataset_path, args.additional_runtime_dir)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    for candidate in dataset_paths:
        if not candidate.exists():
            print("Dataset not found: %s" % candidate, file=sys.stderr)
            return 1

    schema_names = _read_parquet_schema_names(dataset_path)
    if schema_names is not None:
        try:
            resolve_schema_columns(schema_names, args)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    dataframe, input_row_counts = load_combined_dataset(pd, dataset_paths)
    feature_frame, label_series, groups, metadata = build_runtime_training_frame(pd, dataframe, args)
    if feature_frame.empty:
        print("No usable rows were extracted from the dataset.", file=sys.stderr)
        return 1

    if not metadata.get("live_compatible_schema", False):
        print(
            "WARNING: degraded training mode enabled. Missing live-compatible columns: %s"
            % ", ".join(metadata.get("missing_live_columns") or ()),
            file=sys.stderr,
        )

    if label_series.nunique() < 2:
        print("Need at least two label classes after preprocessing.", file=sys.stderr)
        return 1

    normalized_class_balance = label_series.value_counts().to_dict()

    split_mode = args.split_mode
    if split_mode == "auto":
        split_mode = "grouped" if groups is not None else "random"
    split_args = argparse.Namespace(**dict(vars(args), split_mode=split_mode))
    try:
        (
            features_train,
            features_test,
            labels_train,
            labels_test,
            split_metadata,
        ) = split_training_frame(
            pd,
            feature_frame,
            label_series,
            groups,
            split_args,
            train_test_split,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    classifier = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        min_samples_split=args.min_samples_split,
        min_samples_leaf=args.min_samples_leaf,
        random_state=args.random_state,
        n_jobs=-1,
        class_weight=parse_class_weight(args.class_weight),
    )
    classifier.fit(features_train, labels_train)

    predictions = classifier.predict(features_test)
    class_names = [str(value) for value in getattr(classifier, "classes_", [])]
    report = classification_report(
        labels_test,
        predictions,
        output_dict=True,
        zero_division=0,
    )
    per_class_metrics = dict(
        (class_name, report.get(class_name, {}))
        for class_name in class_names
    )
    confusion = confusion_matrix(
        labels_test,
        predictions,
        labels=class_names,
    ).tolist()

    runtime_model = export_random_forest_model(classifier)
    positive_labels = list(metadata.get("positive_labels") or ["malicious"])
    train_class_distribution = labels_train.value_counts().to_dict()
    test_class_distribution = labels_test.value_counts().to_dict()
    feature_importance_summary = summarize_feature_importances(
        RUNTIME_FEATURE_NAMES,
        getattr(classifier, "feature_importances_", ()),
        top_k=6,
    )

    bundle = {
        "model": runtime_model,
        "feature_names": list(RUNTIME_FEATURE_NAMES),
        "positive_labels": positive_labels,
        "metadata": {
            "model_name": "random_forest",
            "model_version": "1",
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "dataset_path": str(dataset_path),
            "dataset_paths": [str(path) for path in dataset_paths],
            "input_row_counts": input_row_counts,
            "combined_rows": int(len(dataframe)),
            "training_rows": int(len(features_train)),
            "test_rows": int(len(features_test)),
            "window_seconds": args.window_seconds,
            "runtime_model_type": "portable_random_forest",
            "tree_count": int(len(runtime_model.trees)),
            "split_mode": split_metadata.get("split_mode"),
            "group_count": split_metadata.get("group_count"),
            "label_mode": args.label_mode,
            "class_balance": normalized_class_balance,
            "train_class_distribution": train_class_distribution,
            "test_class_distribution": test_class_distribution,
            "classes": class_names,
            "per_class_metrics": per_class_metrics,
            "confusion_matrix_labels": class_names,
            "confusion_matrix": confusion,
            "positive_labels": positive_labels,
            "class_weight": parse_class_weight(args.class_weight),
            "min_samples_split": args.min_samples_split,
            "min_samples_leaf": args.min_samples_leaf,
            "feature_importance_summary": feature_importance_summary,
            "explainability": {
                "explanation_version": "1",
                "feature_importance_available": feature_importance_summary[
                    "feature_importance_available"
                ],
                "feature_importance_source": feature_importance_summary[
                    "feature_importance_source"
                ],
                "top_global_features": feature_importance_summary["top_global_features"],
                "global_feature_importance": feature_importance_summary[
                    "global_feature_importance"
                ],
            },
            "report": report,
            "schema_notes": metadata,
        },
    }
    save_model_bundle(args.model_out, bundle)

    metrics_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_paths": [str(path) for path in dataset_paths],
        "input_row_counts": input_row_counts,
        "combined_rows": int(len(dataframe)),
        "runtime_training_rows": int(len(feature_frame)),
        "class_balance": normalized_class_balance,
        "train_class_distribution": train_class_distribution,
        "test_class_distribution": test_class_distribution,
        "label_mode": args.label_mode,
        "classes": class_names,
        "positive_labels": positive_labels,
        "features_used": list(RUNTIME_FEATURE_NAMES),
        "split_mode": split_metadata.get("split_mode"),
        "group_count": split_metadata.get("group_count"),
        "train_rows": int(len(features_train)),
        "test_rows": int(len(features_test)),
        "random_state": args.random_state,
        "n_estimators": args.n_estimators,
        "max_depth": args.max_depth,
        "min_samples_split": args.min_samples_split,
        "min_samples_leaf": args.min_samples_leaf,
        "class_weight": parse_class_weight(args.class_weight),
        "feature_importance_summary": feature_importance_summary,
        "report": report,
        "per_class_metrics": per_class_metrics,
        "confusion_matrix_labels": class_names,
        "confusion_matrix": confusion,
        "schema_notes": metadata,
    }
    if args.metrics_out:
        metrics_path = Path(args.metrics_out)
        metrics_path.parent.mkdir(parents=True, exist_ok=True)
        metrics_path.write_text(json.dumps(metrics_payload, indent=2, sort_keys=True))

    feature_manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_paths": [str(path) for path in dataset_paths],
        "label_mode": args.label_mode,
        "runtime_feature_names": list(RUNTIME_FEATURE_NAMES),
        "runtime_feature_count": len(RUNTIME_FEATURE_NAMES),
        "feature_importance_summary": feature_importance_summary,
        "schema_notes": metadata,
    }
    if args.feature_manifest_out:
        feature_manifest_path = Path(args.feature_manifest_out)
        feature_manifest_path.parent.mkdir(parents=True, exist_ok=True)
        feature_manifest_path.write_text(json.dumps(feature_manifest, indent=2, sort_keys=True))

    print("Saved model bundle to %s" % args.model_out)
    if args.metrics_out:
        print("Saved metrics to %s" % args.metrics_out)
    if args.feature_manifest_out:
        print("Saved feature manifest to %s" % args.feature_manifest_out)
    print("Input datasets:")
    for path in dataset_paths:
        print("- %s (%s rows)" % (path, input_row_counts.get(str(path), 0)))
    print("Class balance: %s" % json.dumps(normalized_class_balance, sort_keys=True))
    print("Label mode: %s" % args.label_mode)
    print("Features used: %s" % ", ".join(RUNTIME_FEATURE_NAMES))
    print("Training rows: %s" % len(features_train))
    print("Test rows: %s" % len(features_test))
    print("Split mode: %s" % split_metadata.get("split_mode"))
    print("Group count: %s" % split_metadata.get("group_count"))
    print("Classification report:")
    print(json.dumps(report, indent=2, sort_keys=True))
    print("Column mapping:")
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
