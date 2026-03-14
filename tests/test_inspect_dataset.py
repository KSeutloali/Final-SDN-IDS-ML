"""Tests for parquet dataset inspection utility."""

import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts.inspect_dataset import inspect_target


class InspectDatasetTests(unittest.TestCase):
    def _args(self, **overrides):
        defaults = {
            "dataset_profile": "cicids2018",
            "label_column": None,
            "timestamp_column": None,
            "src_ip_column": None,
            "dst_ip_column": None,
            "dst_port_column": None,
            "protocol_column": None,
            "run_id_column": None,
            "scenario_column": None,
            "scenario_id_column": None,
            "json": False,
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_inspect_target_reports_mixed_compatibility(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            compatible = directory / "compatible.parquet"
            incompatible = directory / "incompatible.parquet"
            compatible.touch()
            incompatible.touch()

            schemas = {
                str(compatible): [
                    "Src IP",
                    "Dst IP",
                    "Dst Port",
                    "Protocol",
                    "Timestamp",
                    "Label",
                ],
                str(incompatible): [
                    "Flow Duration",
                    "Flow Bytes/s",
                    "Flow Packets/s",
                    "Label",
                ],
            }
            row_counts = {
                str(compatible): 100,
                str(incompatible): 200,
            }

            with mock.patch(
                "scripts.inspect_dataset._read_parquet_schema_names",
                side_effect=lambda path: schemas[str(path)],
            ), mock.patch(
                "scripts.inspect_dataset._read_parquet_row_count",
                side_effect=lambda path: row_counts[str(path)],
            ):
                result = inspect_target(directory, self._args())

        self.assertEqual(result["file_count"], 2)
        self.assertEqual(result["compatible_count"], 1)
        self.assertEqual(result["incompatible_count"], 1)
        self.assertFalse(result["all_live_compatible"])

        file_results = {Path(item["path"]).name: item for item in result["files"]}
        self.assertTrue(file_results["compatible.parquet"]["live_compatible"])
        self.assertEqual(file_results["compatible.parquet"]["row_count"], 100)
        self.assertFalse(file_results["incompatible.parquet"]["live_compatible"])
        self.assertEqual(
            file_results["incompatible.parquet"]["missing_live_columns"],
            ["src_ip", "dst_ip", "dst_port", "protocol", "timestamp"],
        )

    def test_inspect_target_rejects_zip_archives(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            archive_path = Path(temporary_directory) / "dataset.zip"
            archive_path.touch()

            with self.assertRaises(ValueError) as context:
                inspect_target(archive_path, self._args())

        self.assertIn("ZIP archives must be extracted", str(context.exception))


if __name__ == "__main__":
    unittest.main()
