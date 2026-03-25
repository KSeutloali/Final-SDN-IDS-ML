"""Tests for runtime dataset merging helpers."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from merge_runtime_datasets import dedupe_rows, normalize_label_value, schema_union


class MergeRuntimeDatasetsTests(unittest.TestCase):
    def test_normalize_label_value_maps_runtime_labels(self):
        self.assertEqual(normalize_label_value("BENIGN"), "benign")
        self.assertEqual(normalize_label_value("normal_traffic"), "benign")
        self.assertEqual(normalize_label_value("PortScan"), "malicious")

    def test_schema_union_prefers_canonical_columns_then_runtime_columns(self):
        merged_columns = schema_union(
            {
                "a.parquet": ["Label", "Runtime packet_count", "Scenario"],
                "b.parquet": ["Runtime syn_rate", "Custom Field"],
            }
        )
        self.assertIn("Label", merged_columns)
        self.assertIn("Scenario", merged_columns)
        self.assertIn("Runtime packet_count", merged_columns)
        self.assertIn("Runtime syn_rate", merged_columns)
        self.assertIn("Custom Field", merged_columns)

    def test_dedupe_rows_uses_runtime_identity_columns_when_available(self):
        try:
            import pandas as pd
        except ImportError:
            raise unittest.SkipTest("pandas is not available")

        dataframe = pd.DataFrame(
            [
                {
                    "Timestamp": "2026-03-25T00:00:00Z",
                    "Src IP": "10.0.0.1",
                    "Dst IP": "10.0.0.2",
                    "Dst Port": 80,
                    "Protocol": "tcp",
                    "Label": "benign",
                    "Scenario": "example",
                    "Run ID": "run-1",
                    "Collection ID": "collect-1",
                },
                {
                    "Timestamp": "2026-03-25T00:00:00Z",
                    "Src IP": "10.0.0.1",
                    "Dst IP": "10.0.0.2",
                    "Dst Port": 80,
                    "Protocol": "tcp",
                    "Label": "benign",
                    "Scenario": "example",
                    "Run ID": "run-1",
                    "Collection ID": "collect-1",
                },
            ]
        )

        deduped, removed, subset = dedupe_rows(pd, dataframe)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(removed, 1)
        self.assertIn("Run ID", subset)


if __name__ == "__main__":
    unittest.main()
