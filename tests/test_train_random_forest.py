"""Tests for offline ML training schema validation."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from types import SimpleNamespace

from ml.feature_extractor import LiveFeatureExtractor
from scripts.train_random_forest import (
    _aggregate_group_label,
    build_extended_runtime_feature_frame,
    build_training_labels,
    parse_class_weight,
    resolve_input_datasets,
    resolve_schema_columns,
    summarize_feature_importances,
)

try:
    import pandas as pd
except ImportError:  # pragma: no cover - test environment should provide pandas
    pd = None


class TrainRandomForestSchemaTests(unittest.TestCase):
    def _args(self, **overrides):
        defaults = {
            "label_column": None,
            "timestamp_column": None,
            "src_ip_column": None,
            "dst_ip_column": None,
            "dst_port_column": None,
            "protocol_column": None,
            "run_id_column": None,
            "scenario_column": None,
            "scenario_family_column": None,
            "scenario_id_column": None,
            "label_mode": "binary",
            "dataset_profile": "cicids2018",
            "allow_degraded_training": False,
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_resolve_schema_columns_accepts_cicids2018_style_columns(self):
        schema = resolve_schema_columns(
            [
                "Src IP",
                "Dst IP",
                "Dst Port",
                "Protocol",
                "Timestamp",
                "Flow Duration",
                "Flow Bytes/s",
                "Flow Packets/s",
                "SYN Flag Count",
                "Label",
            ],
            self._args(),
        )

        self.assertTrue(schema.live_compatible)
        self.assertEqual(schema.src_ip_column, "Src IP")
        self.assertEqual(schema.dst_ip_column, "Dst IP")
        self.assertEqual(schema.dst_port_column, "Dst Port")
        self.assertEqual(schema.protocol_column, "Protocol")
        self.assertEqual(schema.timestamp_column, "Timestamp")
        self.assertEqual(schema.label_column, "Label")

    def test_resolve_schema_columns_detects_grouping_columns(self):
        schema = resolve_schema_columns(
            [
                "Src IP",
                "Dst IP",
                "Dst Port",
                "Protocol",
                "Timestamp",
                "Run ID",
                "Scenario Family",
                "Scenario",
                "Label",
            ],
            self._args(),
        )

        self.assertEqual(schema.run_id_column, "Run ID")
        self.assertEqual(schema.scenario_family_column, "Scenario Family")
        self.assertEqual(schema.scenario_column, "Scenario")

    def test_resolve_schema_columns_rejects_flow_summary_only_schema_by_default(self):
        with self.assertRaises(ValueError) as context:
            resolve_schema_columns(
                [
                    "Flow Duration",
                    "Flow Bytes/s",
                    "Flow Packets/s",
                    "SYN Flag Count",
                    "Label",
                ],
                self._args(),
            )

        self.assertIn("Missing required columns", str(context.exception))
        self.assertIn("CICIDS2018-style", str(context.exception))

    def test_resolve_schema_columns_can_allow_degraded_training(self):
        schema = resolve_schema_columns(
            [
                "Flow Duration",
                "Flow Bytes/s",
                "Flow Packets/s",
                "SYN Flag Count",
                "Label",
            ],
            self._args(allow_degraded_training=True),
        )

        self.assertFalse(schema.live_compatible)
        self.assertEqual(
            schema.missing_live_columns,
            ("src_ip", "dst_ip", "dst_port", "protocol", "timestamp"),
        )

    def test_resolve_input_datasets_includes_additional_runtime_files(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            base = directory / "base.parquet"
            extra_dir = directory / "extra"
            extra_dir.mkdir()
            extra_a = extra_dir / "a.parquet"
            extra_b = extra_dir / "b.parquet"
            for path in (base, extra_a, extra_b):
                path.write_text("placeholder")

            dataset_paths = resolve_input_datasets(base, extra_dir)
            self.assertEqual(dataset_paths, [base, extra_a, extra_b])

    def test_parse_class_weight_supports_none(self):
        self.assertEqual(parse_class_weight("balanced"), "balanced")
        self.assertEqual(parse_class_weight("balanced_subsample"), "balanced_subsample")
        self.assertIsNone(parse_class_weight("none"))

    def test_summarize_feature_importances_returns_sorted_metadata(self):
        summary = summarize_feature_importances(
            ("packet_rate", "unique_destination_ports", "unanswered_syn_ratio"),
            (0.20, 0.65, 0.15),
            top_k=2,
        )

        self.assertTrue(summary["feature_importance_available"])
        self.assertEqual(
            summary["top_global_features"],
            [
                {"feature": "unique_destination_ports", "importance": 0.65},
                {"feature": "packet_rate", "importance": 0.2},
            ],
        )
        self.assertEqual(
            summary["global_feature_importance"][2],
            {"feature": "unanswered_syn_ratio", "importance": 0.15},
        )

    def test_summarize_feature_importances_handles_missing_values(self):
        summary = summarize_feature_importances((), (), top_k=3)

        self.assertFalse(summary["feature_importance_available"])
        self.assertEqual(summary["global_feature_importance"], [])
        self.assertEqual(summary["top_global_features"], [])

    def test_build_training_labels_binary_mode_preserves_existing_behavior(self):
        labels, positive_labels = build_training_labels(
            ["Benign", "port_scan", "background"],
            label_mode="binary",
        )

        self.assertEqual(labels, ["benign", "malicious", "benign"])
        self.assertEqual(positive_labels, ["malicious"])

    def test_build_training_labels_family_mode_uses_scenario_family(self):
        labels, positive_labels = build_training_labels(
            ["port_scan", "Benign", "syn_flood"],
            label_mode="family",
            scenario_family_values=["tcp_port_scan", "", "syn_flood_open_port"],
        )

        self.assertEqual(
            labels,
            ["tcp_port_scan", "benign", "syn_flood_open_port"],
        )
        self.assertEqual(
            positive_labels,
            ["syn_flood_open_port", "tcp_port_scan"],
        )

    def test_build_training_labels_scenario_mode_uses_id_then_name(self):
        labels, positive_labels = build_training_labels(
            ["scan", "scan", "Benign"],
            label_mode="scenario",
            scenario_id_values=["tcp_scan_01", "", ""],
            scenario_values=["tcp scan 01", "wide scan demo", ""],
        )

        self.assertEqual(labels, ["tcp_scan_01", "wide scan demo", "benign"])
        self.assertEqual(positive_labels, ["tcp_scan_01", "wide scan demo"])

    def test_build_training_labels_errors_when_required_metadata_is_missing(self):
        with self.assertRaises(ValueError) as family_context:
            build_training_labels(
                ["scan"],
                label_mode="family",
                scenario_family_values=[""],
            )
        self.assertIn("scenario-family values", str(family_context.exception))

        with self.assertRaises(ValueError) as scenario_context:
            build_training_labels(
                ["scan"],
                label_mode="scenario",
                scenario_id_values=[""],
                scenario_values=[""],
            )
        self.assertIn("scenario ID or scenario name values", str(scenario_context.exception))

    def test_aggregate_group_label_preserves_binary_and_multiclass_rules(self):
        self.assertEqual(
            _aggregate_group_label(["benign", "malicious"], "binary"),
            "malicious",
        )
        self.assertEqual(
            _aggregate_group_label(["benign", "tcp_port_scan"], "family"),
            "tcp_port_scan",
        )
        with self.assertRaises(ValueError):
            _aggregate_group_label(["tcp_port_scan", "icmp_sweep"], "family")

    @unittest.skipIf(pd is None, "pandas is required for offline training tests")
    def test_extended_runtime_feature_frame_aligns_with_live_short_window_features(self):
        extractor = LiveFeatureExtractor(
            SimpleNamespace(
                feature_window_seconds=10,
                unanswered_syn_timeout_seconds=1.0,
            )
        )

        packets = [
            SimpleNamespace(
                timestamp=1.0,
                src_ip="10.0.0.3",
                dst_ip="10.0.0.2",
                src_port=40001,
                dst_port=80,
                transport_protocol="tcp",
                packet_length=100,
                is_ipv4=True,
                tcp_syn_only=True,
                tcp_rst=False,
            ),
            SimpleNamespace(
                timestamp=2.0,
                src_ip="10.0.0.3",
                dst_ip="10.0.0.4",
                src_port=40002,
                dst_port=53,
                transport_protocol="udp",
                packet_length=140,
                is_ipv4=True,
                tcp_syn_only=False,
                tcp_rst=False,
            ),
            SimpleNamespace(
                timestamp=4.0,
                src_ip="10.0.0.3",
                dst_ip="10.0.0.5",
                src_port=None,
                dst_port=None,
                transport_protocol="icmp",
                packet_length=180,
                is_ipv4=True,
                tcp_syn_only=False,
                tcp_rst=False,
            ),
        ]
        snapshot = None
        for packet in packets:
            snapshot = extractor.observe(packet)

        grouped_frame = pd.DataFrame(
            {
                "group_id": ["run-1", "run-1", "run-1"],
                "src_ip": ["10.0.0.3", "10.0.0.3", "10.0.0.3"],
                "window_start": pd.to_datetime(
                    ["1970-01-01T00:00:00Z"] * 3,
                    utc=True,
                ),
                "timestamp": pd.to_datetime(
                    [
                        "1970-01-01T00:00:01Z",
                        "1970-01-01T00:00:02Z",
                        "1970-01-01T00:00:04Z",
                    ],
                    utc=True,
                ),
                "protocol_name": ["tcp", "udp", "icmp"],
                "dst_ip": ["10.0.0.2", "10.0.0.4", "10.0.0.5"],
                "dst_port": [80, 53, -1],
                "packet_count": [1.0, 1.0, 1.0],
                "byte_count": [100.0, 140.0, 180.0],
                "syn_counts": [1.0, 0.0, 0.0],
            }
        )
        aggregated_frame = pd.DataFrame(
            {
                "group_id": ["run-1"],
                "src_ip": ["10.0.0.3"],
                "window_start": pd.to_datetime(["1970-01-01T00:00:00Z"], utc=True),
                "packet_count": [3.0],
                "syn_counts": [1.0],
                "unanswered_syn_count": [0.0],
                "packet_rate": [0.3],
                "unique_destination_ips": [3.0],
                "unique_destination_ports": [2.0],
                "unanswered_syn_ratio": [0.0],
            }
        )

        extension_frame = build_extended_runtime_feature_frame(
            pd,
            grouped_frame,
            aggregated_frame,
            ["group_id", "src_ip", "window_start"],
            10,
        )
        offline_row = extension_frame.iloc[0]

        self.assertAlmostEqual(
            offline_row["inter_arrival_mean_short"],
            snapshot.feature_values["inter_arrival_mean_short"],
        )
        self.assertAlmostEqual(
            offline_row["inter_arrival_std_short"],
            snapshot.feature_values["inter_arrival_std_short"],
        )
        self.assertAlmostEqual(
            offline_row["burstiness_short"],
            snapshot.feature_values["burstiness_short"],
        )
        self.assertAlmostEqual(
            offline_row["destination_ip_entropy_short"],
            snapshot.feature_values["destination_ip_entropy_short"],
        )
        self.assertAlmostEqual(
            offline_row["destination_port_entropy_short"],
            snapshot.feature_values["destination_port_entropy_short"],
        )
        self.assertAlmostEqual(
            offline_row["protocol_entropy_short"],
            snapshot.feature_values["protocol_entropy_short"],
        )
        self.assertAlmostEqual(
            offline_row["packet_size_std_short"],
            snapshot.feature_values["packet_size_std_short"],
        )


if __name__ == "__main__":
    unittest.main()
