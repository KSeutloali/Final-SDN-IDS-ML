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
            "dataset_recording_mode": "packet",
            "dataset_snapshot_stride": 10,
            "dataset_record_debug_context": False,
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
                        "scenario_family": "tcp_port_scan",
                        "scenario_variant": "h3_to_h2_ports_1_20_t4",
                        "traffic_class": "malicious",
                        "run_id": "run-001",
                        "collection_id": "collect-001",
                        "src_host": "h3",
                        "dst_host": "h2",
                        "dst_service": "10.0.0.2:1-23/tcp",
                        "duration_seconds": "8",
                        "rate_parameter": "timing=T4,retries=0",
                        "concurrency_level": "1",
                        "capture_file": "captures/output/example.pcap",
                        "expected_detection_target": "classifier",
                        "threshold_evasive": True,
                        "known_family": True,
                        "blended_with_benign": False,
                        "note": "unit-test",
                        "source": "manual",
                    }
                )
            )

            recorder = RuntimeDatasetRecorder(self._ml_config(output_path, label_path))
            recorded = recorder.record(
                self._packet(),
                threshold_context={
                    "threshold_triggered": True,
                    "threshold_reason": "tcp_scan_threshold_exceeded",
                    "threshold_rule_family": "recon",
                    "threshold_severity": "high",
                    "threshold_recent_event_count": 2,
                    "unanswered_syn_count": 3,
                    "scan_unique_destination_hosts": 1,
                    "scan_unique_destination_ports": 4,
                    "recon_visible_traffic": True,
                    "forwarding_visibility": "tcp_syn_probe",
                },
            )

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
            self.assertEqual(row["Scenario Family"], "tcp_port_scan")
            self.assertEqual(row["Scenario Variant"], "h3_to_h2_ports_1_20_t4")
            self.assertEqual(row["Traffic Class"], "malicious")
            self.assertEqual(row["Run ID"], "run-001")
            self.assertEqual(row["Collection ID"], "collect-001")
            self.assertEqual(row["Src Host"], "h3")
            self.assertEqual(row["Dst Host"], "h2")
            self.assertEqual(row["Dst Service"], "10.0.0.2:1-23/tcp")
            self.assertEqual(row["Duration Seconds"], "8")
            self.assertEqual(row["Rate Parameter"], "timing=T4,retries=0")
            self.assertEqual(row["Concurrency Level"], "1")
            self.assertEqual(row["Capture File"], "captures/output/example.pcap")
            self.assertEqual(row["Expected Detection Target"], "classifier")
            self.assertTrue(row["Threshold Evasive"])
            self.assertTrue(row["Known Family"])
            self.assertFalse(row["Blended With Benign"])
            self.assertEqual(row["Total Packets"], 1)
            self.assertEqual(row["Total Bytes"], 128)
            self.assertEqual(row["SYN Flag Count"], 1)
            self.assertEqual(row["RST Flag Count"], 0)
            self.assertEqual(row["Recording Mode"], "packet")
            self.assertEqual(row["Observation Index"], 1)
            self.assertEqual(row["Snapshot Sample Count"], 1)
            self.assertIn("Runtime unanswered_syn_rate", row)
            self.assertIn("Runtime unanswered_syn_ratio", row)
            self.assertIn("Runtime destination_port_fanout_ratio", row)
            self.assertIn("Runtime inter_arrival_mean_short", row)
            self.assertIn("Runtime destination_ip_entropy_short", row)
            self.assertIn("Runtime host_packet_rate_baseline_ratio", row)
            self.assertTrue(row["Threshold Triggered"])
            self.assertEqual(row["Threshold Rule Family"], "recon")
            self.assertEqual(row["Threshold Unanswered SYN Count"], 3)
            self.assertTrue(row["Recon Visible Traffic"])
            self.assertEqual(row["Forwarding Visibility"], "tcp_syn_probe")

    def test_record_skips_unlabeled_rows_by_default(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            output_path = directory / "ml_dataset.jsonl"
            label_path = directory / "dataset_label.json"

            recorder = RuntimeDatasetRecorder(self._ml_config(output_path, label_path))
            recorded = recorder.record(self._packet())

            self.assertFalse(recorded)
            self.assertFalse(output_path.exists())

    def test_snapshot_recording_emits_one_row_at_configured_stride(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            output_path = directory / "ml_dataset.jsonl"
            label_path = directory / "dataset_label.json"
            label_path.write_text(
                json.dumps(
                    {
                        "label": "benign",
                        "scenario": "http_browse",
                        "scenario_id": "benign_http_01",
                        "scenario_family": "benign_http_repeated",
                        "expected_detection_target": "",
                        "threshold_evasive": False,
                        "known_family": False,
                        "blended_with_benign": False,
                        "source": "manual",
                    }
                )
            )

            recorder = RuntimeDatasetRecorder(
                self._ml_config(
                    output_path,
                    label_path,
                    dataset_recording_mode="snapshot",
                    dataset_snapshot_stride=2,
                )
            )

            first_recorded = recorder.record(
                self._packet(timestamp=1000.0, dst_port=80, src_port=42424)
            )
            second_recorded = recorder.record(
                self._packet(timestamp=1001.0, dst_port=81, src_port=42425)
            )

            self.assertFalse(first_recorded)
            self.assertTrue(second_recorded)
            rows = [json.loads(line) for line in output_path.read_text().splitlines() if line.strip()]
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["Label"], "benign")
            self.assertEqual(row["Scenario Family"], "benign_http_repeated")
            self.assertEqual(row["Recording Mode"], "snapshot")
            self.assertEqual(row["Observation Index"], 2)
            self.assertEqual(row["Snapshot Stride"], 2)
            self.assertEqual(row["Snapshot Sample Count"], 2)
            self.assertFalse(row["Threshold Evasive"])
            self.assertFalse(row["Known Family"])
            self.assertFalse(row["Blended With Benign"])
            self.assertGreaterEqual(row["Total Packets"], 2)
            self.assertIn("Runtime packet_count", row)

    def test_snapshot_recording_can_include_optional_debug_context_fields(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            output_path = directory / "ml_dataset.jsonl"
            label_path = directory / "dataset_label.json"
            label_path.write_text(json.dumps({"label": "benign", "source": "manual"}))

            recorder = RuntimeDatasetRecorder(
                self._ml_config(
                    output_path,
                    label_path,
                    dataset_recording_mode="snapshot",
                    dataset_snapshot_stride=1,
                    dataset_record_debug_context=True,
                )
            )

            recorded = recorder.record(self._packet(timestamp=1000.0, dst_port=80, src_port=43000))

            self.assertTrue(recorded)
            row = json.loads(output_path.read_text().splitlines()[0])
            self.assertIn("Context Short Window Samples", row)
            self.assertIn("Context Long Window Samples", row)
            self.assertIn("Context Pending Connection Attempts", row)
            self.assertIn("Context Unanswered Window Samples", row)
            self.assertEqual(row["Context Short Window Samples"], 1)


if __name__ == "__main__":
    unittest.main()
