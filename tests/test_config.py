"""Basic tests for firewall controller configuration loading."""

import os
import unittest
from unittest.mock import patch

from config.settings import load_config


class ConfigLoadingTests(unittest.TestCase):
    def test_default_config(self):
        with patch.dict(os.environ, {}, clear=True):
            config = load_config()
            self.assertEqual(config.controller.openflow_port, 6633)
            self.assertTrue(config.firewall.allow_arp)
            self.assertTrue(config.firewall.permit_icmp)
            self.assertEqual(config.firewall.restricted_tcp_ports, (23,))
            self.assertTrue(config.ids.enabled)
            self.assertTrue(config.ids.inspect_tcp_udp_packets)
            self.assertEqual(config.ids.unique_destination_ports_threshold, 12)
            self.assertTrue(config.mitigation.enabled)
            self.assertTrue(config.mitigation.quarantine_enabled)
            self.assertFalse(config.mitigation.auto_unblock_enabled)
            self.assertTrue(config.mitigation.manual_unblock_enabled)
            self.assertTrue(config.capture.enabled)
            self.assertTrue(config.capture.continuous_enabled)
            self.assertEqual(config.capture.tool, "tcpdump")
            self.assertEqual(
                config.capture.interfaces,
                ("h1-eth0", "h3-eth0", "h2-eth0", "s2-eth3"),
            )
            self.assertEqual(config.capture.output_directory, "captures/output")
            self.assertEqual(config.capture.ring_file_seconds, 30)
            self.assertEqual(config.capture.ring_file_count, 12)
            self.assertEqual(config.capture.snapshot_files_per_interface, 2)
            self.assertEqual(config.capture.snapshot_cooldown_seconds, 10)
            self.assertFalse(config.ml.enabled)
            self.assertEqual(config.ml.mode, "threshold_only")
            self.assertEqual(config.ml.mode_state_path, "runtime/ids_mode_state.json")
            self.assertEqual(config.ml.hybrid_policy, "alert_only")
            self.assertEqual(
                config.ml.model_path,
                "models/random_forest_ids.joblib",
            )
            self.assertEqual(
                config.ml.dataset_path,
                "datasets/cicids2018.parquet",
            )
            self.assertFalse(config.ml.dataset_recording_enabled)
            self.assertEqual(config.ml.dataset_recording_path, "runtime/ml_dataset.jsonl")
            self.assertEqual(config.ml.dataset_label_path, "runtime/dataset_label.json")
            self.assertFalse(config.ml.dataset_record_unlabeled)
            self.assertFalse(config.ml.dataset_disable_mitigation)
            self.assertAlmostEqual(config.ml.unanswered_syn_timeout_seconds, 1.5)
            self.assertEqual(config.ml.hybrid_correlation_window_seconds, 10)
            self.assertFalse(config.logging.log_allowed_traffic)
            self.assertEqual(config.dashboard.port, 8080)
            self.assertEqual(config.dashboard.base_path, "/sdn-security")
            self.assertEqual(config.dashboard.poll_interval_seconds, 1.0)
            self.assertEqual(config.dashboard.persist_interval_seconds, 0.25)

    def test_environment_overrides(self):
        with patch.dict(
            os.environ,
            {
                "SDN_FIREWALL_BLOCKED_SOURCE_IPS": "10.0.0.3,10.0.0.4",
                "SDN_FIREWALL_RESTRICTED_TCP_PORTS": "23,445",
                "SDN_FIREWALL_DYNAMIC_BLOCK_SECONDS": "120",
                "SDN_FLOW_PACKET_BLOCK_SECONDS": "15",
                "SDN_IDS_PACKET_RATE_THRESHOLD": "400",
                "SDN_IDS_INSPECT_TCP_UDP_PACKETS": "false",
                "SDN_IDS_UNIQUE_DESTINATION_HOSTS_THRESHOLD": "10",
                "SDN_MITIGATION_ENABLED": "false",
                "SDN_QUARANTINE_ENABLED": "false",
                "SDN_MANUAL_UNBLOCK_ENABLED": "false",
                "SDN_CAPTURE_ENABLED": "false",
                "SDN_CAPTURE_CONTINUOUS_ENABLED": "false",
                "SDN_CAPTURE_TOOL": "tshark",
                "SDN_CAPTURE_INTERFACES": "h1-eth0,s1-eth3",
                "SDN_CAPTURE_OUTPUT_DIRECTORY": "runtime/captures",
                "SDN_CAPTURE_RING_FILE_SECONDS": "15",
                "SDN_CAPTURE_RING_FILE_COUNT": "8",
                "SDN_CAPTURE_SNAPSHOT_FILES_PER_INTERFACE": "3",
                "SDN_CAPTURE_SNAPSHOT_COOLDOWN_SECONDS": "4",
                "SDN_ML_ENABLED": "true",
                "SDN_IDS_MODE": "ml",
                "SDN_ML_HYBRID_POLICY": "high_confidence_block",
                "SDN_IDS_MODE_STATE_PATH": "runtime/custom-ids-mode.json",
                "SDN_ML_MODEL_PATH": "models/demo.joblib",
                "SDN_ML_DATASET_PATH": "datasets/custom.parquet",
                "SDN_ML_DATASET_RECORDING_ENABLED": "true",
                "SDN_ML_DATASET_RECORDING_PATH": "runtime/custom.jsonl",
                "SDN_ML_DATASET_LABEL_PATH": "runtime/custom-label.json",
                "SDN_ML_DATASET_RECORD_UNLABELED": "true",
                "SDN_ML_DATASET_DISABLE_MITIGATION": "true",
                "SDN_ML_UNANSWERED_SYN_TIMEOUT_SECONDS": "0.9",
                "SDN_ML_CONFIDENCE_THRESHOLD": "0.66",
                "SDN_ML_HYBRID_CORRELATION_WINDOW_SECONDS": "15",
                "SDN_ML_POSITIVE_LABELS": "malicious,attack,scan",
                "SDN_LOG_ALLOWED_TRAFFIC": "true",
                "SDN_DASHBOARD_PORT": "18080",
                "SDN_DASHBOARD_BASE_PATH": "/monitor",
                "SDN_DASHBOARD_POLL_INTERVAL_SECONDS": "0.8",
                "SDN_DASHBOARD_PERSIST_INTERVAL_SECONDS": "0.2",
            },
            clear=True,
        ):
            config = load_config()
            self.assertEqual(
                config.firewall.blocked_source_ips,
                ("10.0.0.3", "10.0.0.4"),
            )
            self.assertEqual(config.firewall.restricted_tcp_ports, (23, 445))
            self.assertEqual(config.firewall.dynamic_block_duration_seconds, 120)
            self.assertEqual(config.flow_timeouts.packet_block_seconds, 15)
            self.assertEqual(config.ids.packet_rate_threshold, 400)
            self.assertFalse(config.ids.inspect_tcp_udp_packets)
            self.assertEqual(config.ids.unique_destination_hosts_threshold, 10)
            self.assertFalse(config.mitigation.enabled)
            self.assertFalse(config.mitigation.quarantine_enabled)
            self.assertFalse(config.mitigation.manual_unblock_enabled)
            self.assertFalse(config.capture.enabled)
            self.assertFalse(config.capture.continuous_enabled)
            self.assertEqual(config.capture.tool, "tshark")
            self.assertEqual(config.capture.interfaces, ("h1-eth0", "s1-eth3"))
            self.assertEqual(config.capture.output_directory, "runtime/captures")
            self.assertEqual(config.capture.ring_file_seconds, 15)
            self.assertEqual(config.capture.ring_file_count, 8)
            self.assertEqual(config.capture.snapshot_files_per_interface, 3)
            self.assertEqual(config.capture.snapshot_cooldown_seconds, 4)
            self.assertTrue(config.ml.enabled)
            self.assertEqual(config.ml.mode, "ml_only")
            self.assertEqual(config.ml.mode_state_path, "runtime/custom-ids-mode.json")
            self.assertEqual(config.ml.hybrid_policy, "high_confidence_block")
            self.assertEqual(config.ml.model_path, "models/demo.joblib")
            self.assertEqual(config.ml.dataset_path, "datasets/custom.parquet")
            self.assertTrue(config.ml.dataset_recording_enabled)
            self.assertEqual(config.ml.dataset_recording_path, "runtime/custom.jsonl")
            self.assertEqual(config.ml.dataset_label_path, "runtime/custom-label.json")
            self.assertTrue(config.ml.dataset_record_unlabeled)
            self.assertTrue(config.ml.dataset_disable_mitigation)
            self.assertAlmostEqual(config.ml.unanswered_syn_timeout_seconds, 0.9)
            self.assertAlmostEqual(config.ml.confidence_threshold, 0.66)
            self.assertEqual(config.ml.hybrid_correlation_window_seconds, 15)
            self.assertEqual(
                config.ml.positive_labels,
                ("malicious", "attack", "scan"),
            )
            self.assertTrue(config.logging.log_allowed_traffic)
            self.assertEqual(config.dashboard.port, 18080)
            self.assertEqual(config.dashboard.base_path, "/monitor")
            self.assertAlmostEqual(config.dashboard.poll_interval_seconds, 0.8)
            self.assertAlmostEqual(config.dashboard.persist_interval_seconds, 0.2)


if __name__ == "__main__":
    unittest.main()
