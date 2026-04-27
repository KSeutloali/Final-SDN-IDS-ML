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
            self.assertTrue(config.ids.keep_tcp_syn_packets_visible)
            self.assertTrue(config.ids.keep_udp_probe_packets_visible)
            self.assertTrue(config.ids.keep_icmp_echo_requests_visible)
            self.assertEqual(config.ids.udp_fastpath_ports, ())
            self.assertEqual(config.ids.packet_rate_threshold, 250)
            self.assertEqual(config.ids.syn_rate_threshold, 100)
            self.assertEqual(config.ids.unique_destination_ports_threshold, 6)
            self.assertEqual(config.ids.unique_destination_hosts_threshold, 4)
            self.assertEqual(config.ids.tcp_scan_unique_destination_ports_threshold, 4)
            self.assertEqual(config.ids.udp_scan_unique_destination_ports_threshold, 3)
            self.assertEqual(config.ids.icmp_sweep_unique_destination_hosts_threshold, 4)
            self.assertEqual(config.ids.combined_recon_unique_destination_hosts_threshold, 3)
            self.assertEqual(config.ids.combined_recon_unique_destination_ports_threshold, 3)
            self.assertEqual(config.ids.combined_recon_probe_threshold, 4)
            self.assertEqual(config.ids.failed_connection_threshold, 8)
            self.assertEqual(config.ids.unanswered_syn_window_seconds, 10)
            self.assertEqual(config.ids.unanswered_syn_threshold, 4)
            self.assertAlmostEqual(config.ids.unanswered_syn_timeout_seconds, 1.5)
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
            self.assertEqual(config.ml.hybrid_policy, "layered_consensus")
            self.assertEqual(
                config.ml.model_path,
                "models/random_forest_runtime_final.joblib",
            )
            self.assertEqual(config.ml.anomaly_model_path, "")
            self.assertEqual(config.ml.inference_mode, "classifier_only")
            self.assertEqual(
                config.ml.dataset_path,
                "datasets/cicids2018.parquet",
            )
            self.assertFalse(config.ml.dataset_recording_enabled)
            self.assertEqual(config.ml.dataset_recording_path, "runtime/ml_dataset.jsonl")
            self.assertEqual(config.ml.dataset_recording_mode, "packet")
            self.assertEqual(config.ml.dataset_snapshot_stride, 10)
            self.assertFalse(config.ml.dataset_record_debug_context)
            self.assertEqual(config.ml.dataset_label_path, "runtime/dataset_label.json")
            self.assertFalse(config.ml.dataset_record_unlabeled)
            self.assertFalse(config.ml.dataset_disable_mitigation)
            self.assertEqual(config.ml.feature_window_seconds, 3)
            self.assertEqual(config.ml.minimum_packets_before_inference, 6)
            self.assertEqual(config.ml.inference_packet_stride, 2)
            self.assertAlmostEqual(config.ml.inference_cooldown_seconds, 0.5)
            self.assertAlmostEqual(config.ml.confidence_threshold, 0.65)
            self.assertAlmostEqual(config.ml.mitigation_threshold, 0.80)
            self.assertAlmostEqual(config.ml.alert_only_threshold, 0.55)
            self.assertAlmostEqual(config.ml.anomaly_score_threshold, 0.60)
            self.assertAlmostEqual(config.ml.hybrid_classifier_block_threshold, 0.80)
            self.assertAlmostEqual(config.ml.hybrid_anomaly_support_threshold, 0.60)
            self.assertEqual(config.ml.hybrid_block_repeat_count, 2)
            self.assertEqual(config.ml.hybrid_threshold_near_miss_repeat_count, 2)
            self.assertTrue(config.ml.hybrid_known_family_block_enabled)
            self.assertEqual(config.ml.hybrid_block_eligible_families, ())
            self.assertAlmostEqual(config.ml.hybrid_anomaly_trend_threshold, 0.05)
            self.assertFalse(config.ml.hybrid_anomaly_only_block_enabled)
            self.assertAlmostEqual(config.ml.hybrid_anomaly_only_block_threshold, 0.75)
            self.assertAlmostEqual(config.ml.unanswered_syn_timeout_seconds, 1.5)
            self.assertEqual(config.ml.hybrid_correlation_window_seconds, 10)
            self.assertEqual(config.ml.ml_only_escalation_count, 3)
            self.assertEqual(config.ml.anomaly_only_escalation_count, 3)
            self.assertFalse(config.ml.ml_only_escalation_enabled)
            self.assertTrue(config.ml.capture_on_ml_only_alert)
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
                "SDN_IDS_KEEP_TCP_SYN_PACKETS_VISIBLE": "false",
                "SDN_IDS_KEEP_UDP_PROBE_PACKETS_VISIBLE": "false",
                "SDN_IDS_KEEP_ICMP_ECHO_REQUESTS_VISIBLE": "false",
                "SDN_IDS_UDP_FASTPATH_PORTS": "53,123",
                "SDN_IDS_UNIQUE_DESTINATION_HOSTS_THRESHOLD": "10",
                "SDN_IDS_TCP_SCAN_UNIQUE_DESTINATION_PORTS_THRESHOLD": "5",
                "SDN_IDS_TCP_SCAN_PROBE_THRESHOLD": "6",
                "SDN_IDS_UDP_SCAN_UNIQUE_DESTINATION_PORTS_THRESHOLD": "4",
                "SDN_IDS_UDP_SCAN_PROBE_THRESHOLD": "5",
                "SDN_IDS_ICMP_SWEEP_UNIQUE_DESTINATION_HOSTS_THRESHOLD": "6",
                "SDN_IDS_ICMP_SWEEP_PROBE_THRESHOLD": "7",
                "SDN_IDS_COMBINED_RECON_UNIQUE_DESTINATION_HOSTS_THRESHOLD": "4",
                "SDN_IDS_COMBINED_RECON_UNIQUE_DESTINATION_PORTS_THRESHOLD": "5",
                "SDN_IDS_COMBINED_RECON_PROBE_THRESHOLD": "8",
                "SDN_IDS_UNANSWERED_SYN_WINDOW_SECONDS": "12",
                "SDN_IDS_UNANSWERED_SYN_THRESHOLD": "6",
                "SDN_IDS_UNANSWERED_SYN_TIMEOUT_SECONDS": "2.5",
                "SDN_MITIGATION_ENABLED": "false",
                "SDN_QUARANTINE_ENABLED": "false",
                "SDN_AUTO_UNBLOCK_ENABLED": "true",
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
                "SDN_ML_ANOMALY_MODEL_PATH": "models/anomaly.joblib",
                "SDN_ML_INFERENCE_MODE": "combined",
                "SDN_ML_DATASET_PATH": "datasets/custom.parquet",
                "SDN_ML_DATASET_RECORDING_ENABLED": "true",
                "SDN_ML_DATASET_RECORDING_PATH": "runtime/custom.jsonl",
                "SDN_ML_DATASET_RECORDING_MODE": "snapshot",
                "SDN_ML_DATASET_SNAPSHOT_STRIDE": "12",
                "SDN_ML_DATASET_RECORD_DEBUG_CONTEXT": "true",
                "SDN_ML_DATASET_LABEL_PATH": "runtime/custom-label.json",
                "SDN_ML_DATASET_RECORD_UNLABELED": "true",
                "SDN_ML_DATASET_DISABLE_MITIGATION": "true",
                "SDN_ML_UNANSWERED_SYN_TIMEOUT_SECONDS": "0.9",
                "SDN_ML_CONFIDENCE_THRESHOLD": "0.66",
                "SDN_ML_ALERT_ONLY_THRESHOLD": "0.58",
                "SDN_ML_ANOMALY_SCORE_THRESHOLD": "0.72",
                "SDN_ML_HYBRID_CLASSIFIER_BLOCK_THRESHOLD": "0.87",
                "SDN_ML_HYBRID_ANOMALY_SUPPORT_THRESHOLD": "0.69",
                "SDN_ML_HYBRID_BLOCK_REPEAT_COUNT": "4",
                "SDN_ML_HYBRID_THRESHOLD_NEAR_MISS_REPEAT_COUNT": "5",
                "SDN_ML_HYBRID_KNOWN_FAMILY_BLOCK_ENABLED": "false",
                "SDN_ML_HYBRID_BLOCK_ELIGIBLE_FAMILIES": "tcp_scan,syn_flood",
                "SDN_ML_HYBRID_ANOMALY_TREND_THRESHOLD": "0.11",
                "SDN_ML_HYBRID_ANOMALY_ONLY_BLOCK_ENABLED": "true",
                "SDN_ML_HYBRID_ANOMALY_ONLY_BLOCK_THRESHOLD": "0.93",
                "SDN_ML_HYBRID_CORRELATION_WINDOW_SECONDS": "15",
                "SDN_ML_ONLY_ESCALATION_COUNT": "4",
                "SDN_ML_ANOMALY_ONLY_ESCALATION_COUNT": "5",
                "SDN_ML_ONLY_ESCALATION_ENABLED": "true",
                "SDN_ML_CAPTURE_ON_ML_ONLY_ALERT": "false",
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
            self.assertFalse(config.ids.keep_tcp_syn_packets_visible)
            self.assertFalse(config.ids.keep_udp_probe_packets_visible)
            self.assertFalse(config.ids.keep_icmp_echo_requests_visible)
            self.assertEqual(config.ids.udp_fastpath_ports, (53, 123))
            self.assertEqual(config.ids.unique_destination_hosts_threshold, 10)
            self.assertEqual(config.ids.tcp_scan_unique_destination_ports_threshold, 5)
            self.assertEqual(config.ids.tcp_scan_probe_threshold, 6)
            self.assertEqual(config.ids.udp_scan_unique_destination_ports_threshold, 4)
            self.assertEqual(config.ids.udp_scan_probe_threshold, 5)
            self.assertEqual(config.ids.icmp_sweep_unique_destination_hosts_threshold, 6)
            self.assertEqual(config.ids.icmp_sweep_probe_threshold, 7)
            self.assertEqual(config.ids.combined_recon_unique_destination_hosts_threshold, 4)
            self.assertEqual(config.ids.combined_recon_unique_destination_ports_threshold, 5)
            self.assertEqual(config.ids.combined_recon_probe_threshold, 8)
            self.assertEqual(config.ids.unanswered_syn_window_seconds, 12)
            self.assertEqual(config.ids.unanswered_syn_threshold, 6)
            self.assertAlmostEqual(config.ids.unanswered_syn_timeout_seconds, 2.5)
            self.assertFalse(config.mitigation.enabled)
            self.assertFalse(config.mitigation.quarantine_enabled)
            self.assertTrue(config.mitigation.auto_unblock_enabled)
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
            self.assertEqual(config.ml.anomaly_model_path, "models/anomaly.joblib")
            self.assertEqual(config.ml.inference_mode, "combined")
            self.assertEqual(config.ml.dataset_path, "datasets/custom.parquet")
            self.assertTrue(config.ml.dataset_recording_enabled)
            self.assertEqual(config.ml.dataset_recording_path, "runtime/custom.jsonl")
            self.assertEqual(config.ml.dataset_recording_mode, "snapshot")
            self.assertEqual(config.ml.dataset_snapshot_stride, 12)
            self.assertTrue(config.ml.dataset_record_debug_context)
            self.assertEqual(config.ml.dataset_label_path, "runtime/custom-label.json")
            self.assertTrue(config.ml.dataset_record_unlabeled)
            self.assertTrue(config.ml.dataset_disable_mitigation)
            self.assertAlmostEqual(config.ml.unanswered_syn_timeout_seconds, 0.9)
            self.assertAlmostEqual(config.ml.confidence_threshold, 0.66)
            self.assertAlmostEqual(config.ml.alert_only_threshold, 0.58)
            self.assertAlmostEqual(config.ml.anomaly_score_threshold, 0.72)
            self.assertAlmostEqual(config.ml.hybrid_classifier_block_threshold, 0.87)
            self.assertAlmostEqual(config.ml.hybrid_anomaly_support_threshold, 0.69)
            self.assertEqual(config.ml.hybrid_block_repeat_count, 4)
            self.assertEqual(config.ml.hybrid_threshold_near_miss_repeat_count, 5)
            self.assertFalse(config.ml.hybrid_known_family_block_enabled)
            self.assertEqual(
                config.ml.hybrid_block_eligible_families,
                ("tcp_scan", "syn_flood"),
            )
            self.assertAlmostEqual(config.ml.hybrid_anomaly_trend_threshold, 0.11)
            self.assertTrue(config.ml.hybrid_anomaly_only_block_enabled)
            self.assertAlmostEqual(config.ml.hybrid_anomaly_only_block_threshold, 0.93)
            self.assertEqual(config.ml.hybrid_correlation_window_seconds, 15)
            self.assertEqual(config.ml.ml_only_escalation_count, 4)
            self.assertEqual(config.ml.anomaly_only_escalation_count, 5)
            self.assertTrue(config.ml.ml_only_escalation_enabled)
            self.assertFalse(config.ml.capture_on_ml_only_alert)
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
