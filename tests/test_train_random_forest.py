"""Tests for offline ML training schema validation."""

import unittest
from types import SimpleNamespace

from scripts.train_random_forest import resolve_schema_columns


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
            "scenario_id_column": None,
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
                "Scenario",
                "Label",
            ],
            self._args(),
        )

        self.assertEqual(schema.run_id_column, "Run ID")
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


if __name__ == "__main__":
    unittest.main()
