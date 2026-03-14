"""Tests for runtime dataset recording."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from ml.dataset_recorder import RuntimeDatasetRecorder


class RuntimeDatasetRecorderTests(unittest.TestCase):
    def _ml_config(self, output_path, label_path, **overrides):
        defaults = {
            "dataset_recording_enabled": True,
            "dataset_recording_path": str(output_path),
            "dataset_label_path": str(label_path),
            "dataset_label_refresh_seconds": 0.0,
            "dataset_record_unlabeled": False,
            "feature_window_seconds": 10,
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def _packet(self, **overrides):
        defaults = {
            "is_ipv4": True,
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.2",
            "src_port": 42424,
            "dst_port": 80,
            "transport_protocol": "tcp",
            "packet_length": 128,
            "timestamp": 1000.0,
            "tcp_syn_only": True,
            "tcp_rst": False,
            "dpid": "0000000000000001",
            "in_port": 2,
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_record_writes_live_compatible_row(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            output_path = directory / "ml_dataset.jsonl"
            label_path = directory / "dataset_label.json"
            label_path.write_text(
                json.dumps(
                    {
                        "label": "malicious",
                        "scenario": "port_scan",
                        "scenario_id": "port_scan_tcp",
                        "run_id": "run-001",
                        "collection_id": "collect-001",
                        "note": "unit-test",
                        "source": "manual",
                    }
                )
            )

            recorder = RuntimeDatasetRecorder(self._ml_config(output_path, label_path))
            recorded = recorder.record(self._packet())

            self.assertTrue(recorded)
            rows = [json.loads(line) for line in output_path.read_text().splitlines() if line.strip()]
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["Src IP"], "10.0.0.3")
            self.assertEqual(row["Dst IP"], "10.0.0.2")
            self.assertEqual(row["Dst Port"], 80)
            self.assertEqual(row["Protocol"], "tcp")
            self.assertEqual(row["Label"], "malicious")
            self.assertEqual(row["Scenario"], "port_scan")
            self.assertEqual(row["Scenario ID"], "port_scan_tcp")
            self.assertEqual(row["Run ID"], "run-001")
            self.assertEqual(row["Collection ID"], "collect-001")
            self.assertEqual(row["Total Packets"], 1)
            self.assertEqual(row["Total Bytes"], 128)
            self.assertEqual(row["SYN Flag Count"], 1)
            self.assertEqual(row["RST Flag Count"], 0)

    def test_record_skips_unlabeled_rows_by_default(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            output_path = directory / "ml_dataset.jsonl"
            label_path = directory / "dataset_label.json"

            recorder = RuntimeDatasetRecorder(self._ml_config(output_path, label_path))
            recorded = recorder.record(self._packet())

            self.assertFalse(recorded)
            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
