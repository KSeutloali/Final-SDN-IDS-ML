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
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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


def _binary_label_series(label_series):
    labels = label_series.fillna("unknown").astype(str).str.strip()
    lower_labels = labels.str.lower()
    benign_mask = lower_labels.apply(
        lambda value: any(keyword in value for keyword in BENIGN_LABEL_KEYWORDS)
    )
    return benign_mask.map({True: "benign", False: "malicious"})


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
    packet_count_column = schema.packet_count_column
    backward_packet_count_column = schema.backward_packet_count_column
    byte_count_column = schema.byte_count_column
    backward_byte_count_column = schema.backward_byte_count_column
    flow_duration_column = schema.flow_duration_column
    syn_flag_column = schema.syn_flag_column
    rst_flag_column = schema.rst_flag_column

    labels = _binary_label_series(_text_series(pandas_module, dataframe, label_column))

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
        malicious_mask = (grouped_frame["label"] == "malicious").astype("int64")
        grouped_frame["malicious_mask"] = malicious_mask

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
            malicious_mask=("malicious_mask", "max"),
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
        labels = aggregated["malicious_mask"].map({1: "malicious", 0: "benign"})
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
        "window_seconds": args.window_seconds,
        "runtime_feature_names": list(RUNTIME_FEATURE_NAMES),
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
        .agg(label=("label", lambda series: "malicious" if "malicious" in set(series) else series.iloc[0]))
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
        default="datasets/cicids2018.parquet",
        help="Path to the parquet dataset. CICIDS2018-style flow parquet is preferred.",
    )
    parser.add_argument(
        "--model-out",
        default="models/random_forest_ids.joblib",
        help="Output path for the serialized model bundle.",
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
    parser.add_argument("--scenario-id-column", default=None, help="Optional explicit scenario family column.")
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
    return parser.parse_args()


def _read_parquet_schema_names(dataset_path):
    try:
        import pyarrow.parquet as parquet
    except ImportError:
        return None

    return list(parquet.read_schema(str(dataset_path)).names)


def main():
    args = parse_args()

    try:
        import pandas as pd
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import classification_report
        from sklearn.model_selection import train_test_split
    except ImportError as exc:
        print(
            "Offline ML dependencies are missing: %s\n"
            "Install requirements-ml.txt in a separate training environment." % exc,
            file=sys.stderr,
        )
        return 1

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print("Dataset not found: %s" % dataset_path, file=sys.stderr)
        return 1

    schema_names = _read_parquet_schema_names(dataset_path)
    if schema_names is not None:
        try:
            resolve_schema_columns(schema_names, args)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    dataframe = pd.read_parquet(str(dataset_path))
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
        random_state=args.random_state,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )
    classifier.fit(features_train, labels_train)

    predictions = classifier.predict(features_test)
    report = classification_report(
        labels_test,
        predictions,
        output_dict=True,
        zero_division=0,
    )

    runtime_model = export_random_forest_model(classifier)

    bundle = {
        "model": runtime_model,
        "feature_names": list(RUNTIME_FEATURE_NAMES),
        "positive_labels": ["malicious"],
        "metadata": {
            "model_name": "random_forest",
            "model_version": "1",
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "dataset_path": str(dataset_path),
            "training_rows": int(len(features_train)),
            "test_rows": int(len(features_test)),
            "window_seconds": args.window_seconds,
            "runtime_model_type": "portable_random_forest",
            "tree_count": int(len(runtime_model.trees)),
            "split_mode": split_metadata.get("split_mode"),
            "group_count": split_metadata.get("group_count"),
            "report": report,
            "schema_notes": metadata,
        },
    }
    save_model_bundle(args.model_out, bundle)

    print("Saved model bundle to %s" % args.model_out)
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
