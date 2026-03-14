"""Tests for experiment result extraction."""

import unittest

from experiments.common import EvaluationMode, EvaluationScenario
from experiments.extract_results import aggregate_results, extract_run_result


class ExperimentExtractionTests(unittest.TestCase):
    def setUp(self):
        self.mode = EvaluationMode(
            name="dynamic_enforcement",
            title="Dynamic",
            description="Threshold IDS with mitigation.",
            env={"SDN_IDS_ENABLED": "true"},
            mitigation_enabled=True,
        )
        self.scenario = EvaluationScenario(
            name="port_scan",
            title="Port Scan",
            label="malicious",
            host="h3",
            command="scan",
            description="scan",
            source_ip="10.0.0.3",
            allow_nonzero=False,
        )

    def test_extract_run_result_captures_detection_and_mitigation(self):
        controller_log = "\n".join(
            [
                "sdn-security-controller  | 2026-03-13 10:00:01,100 | WARNING | sdn_security | event=security action=ids_alert src_ip=10.0.0.3 alert_type=port_scan_detected reason=scan",
                "sdn-security-controller  | 2026-03-13 10:00:01,350 | WARNING | sdn_security | event=security action=temporary_block_added src_ip=10.0.0.3 reason=ids_port_scan_detected",
                "sdn-security-controller  | 2026-03-13 10:00:01,500 | WARNING | sdn_security | event=traffic action=block src_ip=10.0.0.3 reason=temporary_source_block",
            ]
        )
        before_payload = {
            "summary": {
                "total_packets": 10,
                "total_bytes": 1000,
                "alerts_total": 0,
                "blocks_total": 0,
                "flow_installs_total": 5,
                "flow_removals_total": 1,
                "controller_events_total": 2,
            }
        }
        after_payload = {
            "summary": {
                "total_packets": 60,
                "total_bytes": 4000,
                "alerts_total": 1,
                "blocks_total": 1,
                "flow_installs_total": 10,
                "flow_removals_total": 2,
                "controller_events_total": 4,
                "active_blocks": 1,
                "active_security_flows_total": 2,
                "active_flows_total": 8,
            }
        }
        capture_metadata = {
            "session_name": "port-scan-20260313-100000",
            "file_count": 4,
            "total_size_bytes": 2048,
        }

        result = extract_run_result(
            mode=self.mode,
            scenario=self.scenario,
            repeat_index=1,
            start_epoch=1773396001.0,
            end_epoch=1773396006.0,
            before_payload=before_payload,
            after_payload=after_payload,
            controller_log_text=controller_log,
            command_stdout="",
            command_returncode=0,
            capture_metadata=capture_metadata,
        )

        self.assertTrue(result["attack_detected"])
        self.assertTrue(result["mitigation_observed"])
        self.assertEqual(result["threshold_alert_count"], 1)
        self.assertEqual(result["packet_drop_count_observed"], 1)
        self.assertEqual(result["packets_processed_delta"], 50)
        self.assertEqual(result["flow_installs_delta"], 5)
        self.assertEqual(result["capture_file_count"], 4)
        self.assertEqual(result["false_negative_estimate"], 0)

    def test_aggregate_results_groups_by_mode_and_scenario(self):
        rows = [
            {
                "mode": "dynamic_enforcement",
                "scenario": "port_scan",
                "attack_detection_time_seconds": 0.2,
                "mitigation_time_seconds": 0.4,
                "packets_processed_delta": 100,
                "packet_drop_count_observed": 10,
                "flow_installs_delta": 5,
                "flow_removals_delta": 1,
                "controller_events_delta": 2,
                "bytes_per_second_observed": 300.0,
                "ping_avg_rtt_ms": None,
                "false_positive_estimate": 0,
                "false_negative_estimate": 0,
                "attack_detected": True,
                "mitigation_observed": True,
            },
            {
                "mode": "dynamic_enforcement",
                "scenario": "port_scan",
                "attack_detection_time_seconds": 0.4,
                "mitigation_time_seconds": 0.6,
                "packets_processed_delta": 200,
                "packet_drop_count_observed": 20,
                "flow_installs_delta": 7,
                "flow_removals_delta": 2,
                "controller_events_delta": 3,
                "bytes_per_second_observed": 600.0,
                "ping_avg_rtt_ms": None,
                "false_positive_estimate": 0,
                "false_negative_estimate": 0,
                "attack_detected": True,
                "mitigation_observed": True,
            },
        ]

        summary = aggregate_results(rows)
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["mode"], "dynamic_enforcement")
        self.assertEqual(summary[0]["scenario"], "port_scan")
        self.assertEqual(summary[0]["runs"], 2)
        self.assertAlmostEqual(summary[0]["attack_detection_time_mean_seconds"], 0.3)
        self.assertAlmostEqual(summary[0]["mitigation_time_mean_seconds"], 0.5)
        self.assertAlmostEqual(summary[0]["attack_detection_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
