"""Tests for experiment result extraction."""

import unittest

from experiments.common import EvaluationMode, EvaluationScenario, default_modes
from experiments.extract_results import (
    aggregate_results,
    build_family_summary,
    build_intent_summary,
    build_mode_comparison,
    build_scenario_comparison,
    extract_run_result,
)


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
            scenario_family="tcp_port_scan",
            expected_detection_target="threshold",
            known_family=True,
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
        self.assertEqual(result["scenario_family"], "tcp_port_scan")
        self.assertEqual(result["expected_detection_target"], "threshold")

    def test_aggregate_results_groups_by_mode_and_scenario(self):
        rows = [
            {
                "mode": "dynamic_enforcement",
                "mode_title": "Dynamic",
                "scenario": "port_scan",
                "scenario_title": "Port Scan",
                "scenario_family": "tcp_port_scan",
                "expected_detection_target": "threshold",
                "threshold_evasive": False,
                "known_family": True,
                "blended_with_benign": False,
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
                "hybrid_agreement_count": 0,
                "hybrid_consensus_count": 0,
                "threshold_plus_ml_count": 0,
                "anomaly_only_correlation_count": 0,
                "effective_runtime_mode": "threshold",
                "effective_inference_mode": "",
                "scenario_label": "malicious",
            },
            {
                "mode": "dynamic_enforcement",
                "mode_title": "Dynamic",
                "scenario": "port_scan",
                "scenario_title": "Port Scan",
                "scenario_family": "tcp_port_scan",
                "expected_detection_target": "threshold",
                "threshold_evasive": False,
                "known_family": True,
                "blended_with_benign": False,
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
                "hybrid_agreement_count": 0,
                "hybrid_consensus_count": 0,
                "threshold_plus_ml_count": 0,
                "anomaly_only_correlation_count": 0,
                "effective_runtime_mode": "threshold",
                "effective_inference_mode": "",
                "scenario_label": "malicious",
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
        self.assertEqual(summary[0]["effective_runtime_modes"], "threshold")

    def test_extract_run_result_captures_layered_hybrid_statuses(self):
        controller_log = "\n".join(
            [
                "sdn-security-controller  | 2026-03-13 10:00:01,100 | WARNING | sdn_security | event=ml action=hybrid_correlation src_ip=10.0.0.3 status=threshold_plus_ml reason=threshold_and_ml_agree",
                "sdn-security-controller  | 2026-03-13 10:00:01,200 | WARNING | sdn_security | event=ml action=hybrid_correlation src_ip=10.0.0.3 status=known_class_match reason=classifier_family_match",
                "sdn-security-controller  | 2026-03-13 10:00:01,300 | WARNING | sdn_security | event=ml action=hybrid_correlation src_ip=10.0.0.3 status=anomaly_only reason=anomaly_score_high",
            ]
        )
        after_payload = {
            "summary": {},
            "ml_status": {
                "configured_mode_api": "hybrid",
                "selected_mode_api": "hybrid",
                "effective_mode_api": "hybrid",
                "inference_mode": "combined",
                "effective_inference_mode": "combined",
                "model_available": True,
                "anomaly_model_available": True,
            },
        }

        result = extract_run_result(
            mode=self.mode,
            scenario=self.scenario,
            repeat_index=1,
            start_epoch=1773396001.0,
            end_epoch=1773396006.0,
            before_payload={"summary": {}},
            after_payload=after_payload,
            controller_log_text=controller_log,
            command_stdout="",
            command_returncode=0,
            capture_metadata={},
        )

        self.assertTrue(result["attack_detected"])
        self.assertEqual(result["hybrid_agreement_count"], 0)
        self.assertEqual(result["hybrid_consensus_count"], 2)
        self.assertEqual(result["threshold_plus_ml_count"], 1)
        self.assertEqual(result["known_class_match_count"], 1)
        self.assertEqual(result["anomaly_only_correlation_count"], 1)
        self.assertEqual(result["effective_runtime_mode"], "hybrid")
        self.assertEqual(result["effective_inference_mode"], "combined")
        self.assertTrue(result["supervised_model_available"])
        self.assertTrue(result["anomaly_model_available"])

    def test_extract_run_result_captures_prediction_and_quarantine_metadata(self):
        controller_log = "\n".join(
            [
                "sdn-security-controller  | 2026-03-13 10:00:01,100 | WARNING | sdn_security | event=ml action=ml_alert src_ip=10.0.0.3 decision=hybrid_ml_block reason=threshold_suspicion_elevated_by_strong_ml_evidence label=malicious confidence=0.91 suspicion_score=0.91 correlation_status=threshold_enriched_by_ml predicted_family=tcp_scan classifier_confidence=0.91 anomaly_score=0.63 threshold_reason=tcp_scan_threshold_exceeded repeated_window_count=2 block_decision_path=threshold_suspicion_elevated_by_ml final_block_reason=threshold_suspicion_elevated_by_strong_ml_evidence",
                "sdn-security-controller  | 2026-03-13 10:00:01,200 | WARNING | sdn_security | event=security action=host_quarantined src_ip=10.0.0.3 detector=ml reason=ml_random_forest_detected status=created",
            ]
        )
        after_payload = {
            "summary": {},
            "ml_status": {
                "configured_mode_api": "hybrid",
                "selected_mode_api": "hybrid",
                "effective_mode_api": "hybrid",
                "inference_mode": "combined",
                "effective_inference_mode": "combined",
                "model_available": True,
                "anomaly_model_available": True,
            },
            "recent_ml_predictions": [
                {
                    "src_ip": "10.0.0.3",
                    "label": "malicious",
                    "reason": "classifier_and_anomaly_agree",
                    "confidence": 0.91,
                    "anomaly_score": 0.63,
                    "is_anomalous": True,
                    "predicted_family": "",
                    "explanation_summary": "Classifier and anomaly detector both flagged the host.",
                    "timestamp": "2026-03-13T10:00:01.100000+00:00",
                }
            ],
        }

        result = extract_run_result(
            mode=self.mode,
            scenario=self.scenario,
            repeat_index=1,
            start_epoch=1773396001.0,
            end_epoch=1773396006.0,
            before_payload={"summary": {}},
            after_payload=after_payload,
            controller_log_text=controller_log,
            command_stdout="",
            command_returncode=0,
            capture_metadata={},
        )

        self.assertEqual(result["latest_ml_alert_decision"], "hybrid_ml_block")
        self.assertEqual(
            result["latest_ml_alert_reason"],
            "threshold_suspicion_elevated_by_strong_ml_evidence",
        )
        self.assertEqual(result["mitigation_src_ip"], "10.0.0.3")
        self.assertEqual(result["mitigation_detector"], "ml")
        self.assertEqual(result["prediction_label"], "malicious")
        self.assertEqual(result["prediction_reason"], "classifier_and_anomaly_agree")
        self.assertEqual(result["prediction_confidence"], 0.91)
        self.assertEqual(result["prediction_anomaly_score"], 0.63)
        self.assertTrue(result["prediction_is_anomalous"])
        self.assertEqual(
            result["latest_ml_alert_correlation_status"],
            "threshold_enriched_by_ml",
        )
        self.assertEqual(result["latest_ml_alert_predicted_family"], "tcp_scan")
        self.assertEqual(result["latest_ml_alert_classifier_confidence"], 0.91)
        self.assertEqual(result["latest_ml_alert_anomaly_score"], 0.63)
        self.assertEqual(
            result["latest_ml_alert_threshold_reason"],
            "tcp_scan_threshold_exceeded",
        )
        self.assertEqual(result["latest_ml_alert_repeated_window_count"], 2)
        self.assertEqual(
            result["latest_ml_alert_block_decision_path"],
            "threshold_suspicion_elevated_by_ml",
        )
        self.assertEqual(
            result["latest_ml_alert_final_block_reason"],
            "threshold_suspicion_elevated_by_strong_ml_evidence",
        )

    def test_non_hybrid_correlation_counters_do_not_count_as_detection_without_alerts(self):
        controller_log = (
            "sdn-security-controller  | 2026-03-13 10:00:01,100 | WARNING | sdn_security | "
            "event=ml action=hybrid_correlation src_ip=10.0.0.3 status=ml_only reason=classifier_prediction_supported"
        )
        after_payload = {
            "summary": {},
            "ml_status": {
                "configured_mode_api": "ml",
                "selected_mode_api": "ml",
                "effective_mode_api": "ml",
                "inference_mode": "classifier_only",
                "effective_inference_mode": "classifier_only",
                "model_available": True,
                "anomaly_model_available": False,
            },
        }

        result = extract_run_result(
            mode=EvaluationMode(
                name="classifier_only",
                title="Classifier Only",
                description="Classifier only.",
                env={},
                mitigation_enabled=False,
            ),
            scenario=self.scenario,
            repeat_index=1,
            start_epoch=1773396001.0,
            end_epoch=1773396006.0,
            before_payload={"summary": {}},
            after_payload=after_payload,
            controller_log_text=controller_log,
            command_stdout="",
            command_returncode=0,
            capture_metadata={},
        )

        self.assertFalse(result["attack_detected"])
        self.assertEqual(result["ml_only_correlation_count"], 1)
        self.assertEqual(result["effective_runtime_mode"], "ml")

    def test_default_modes_include_layered_comparison_modes(self):
        modes = default_modes(
            "models/classifier.joblib",
            "models/anomaly.joblib",
        )

        self.assertIn("threshold_only", modes)
        self.assertIn("classifier_only", modes)
        self.assertIn("anomaly_only", modes)
        self.assertIn("hybrid", modes)
        self.assertEqual(modes["classifier_only"].env["SDN_ML_INFERENCE_MODE"], "classifier_only")
        self.assertEqual(modes["anomaly_only"].env["SDN_ML_INFERENCE_MODE"], "anomaly_only")
        self.assertEqual(modes["hybrid"].env["SDN_IDS_MODE"], "hybrid")
        self.assertEqual(modes["hybrid"].env["SDN_ML_HYBRID_POLICY"], "layered_consensus")
        self.assertEqual(
            modes["hybrid"].env["SDN_ML_ANOMALY_MODEL_PATH"],
            "models/anomaly.joblib",
        )

    def test_mode_family_and_intent_summaries_use_available_rows_only(self):
        rows = [
            {
                "mode": "threshold_only",
                "mode_title": "Threshold IDS Only",
                "scenario": "stealth_scan",
                "scenario_title": "Stealth Scan",
                "scenario_label": "malicious",
                "scenario_family": "tcp_port_scan_stealth",
                "expected_detection_target": "classifier",
                "threshold_evasive": True,
                "known_family": True,
                "blended_with_benign": False,
                "attack_detected": False,
                "mitigation_observed": False,
                "hybrid_agreement_count": 0,
                "hybrid_consensus_count": 0,
                "threshold_plus_ml_count": 0,
                "threshold_enriched_by_ml_count": 0,
                "known_class_match_count": 0,
                "threshold_only_correlation_count": 0,
                "ml_only_correlation_count": 0,
                "anomaly_only_correlation_count": 0,
                "effective_runtime_mode": "threshold",
                "effective_inference_mode": "",
            },
            {
                "mode": "hybrid",
                "mode_title": "Layered Hybrid IDS",
                "scenario": "stealth_scan",
                "scenario_title": "Stealth Scan",
                "scenario_label": "malicious",
                "scenario_family": "tcp_port_scan_stealth",
                "expected_detection_target": "classifier",
                "threshold_evasive": True,
                "known_family": True,
                "blended_with_benign": False,
                "attack_detected": True,
                "mitigation_observed": False,
                "hybrid_agreement_count": 1,
                "hybrid_consensus_count": 1,
                "threshold_plus_ml_count": 1,
                "threshold_enriched_by_ml_count": 0,
                "known_class_match_count": 0,
                "threshold_only_correlation_count": 0,
                "ml_only_correlation_count": 0,
                "anomaly_only_correlation_count": 0,
                "effective_runtime_mode": "hybrid",
                "effective_inference_mode": "combined",
            },
            {
                "mode": "hybrid",
                "mode_title": "Layered Hybrid IDS",
                "scenario": "benign",
                "scenario_title": "Benign",
                "scenario_label": "benign",
                "scenario_family": "benign_background",
                "expected_detection_target": "",
                "threshold_evasive": False,
                "known_family": False,
                "blended_with_benign": False,
                "attack_detected": False,
                "mitigation_observed": False,
                "hybrid_agreement_count": 0,
                "hybrid_consensus_count": 0,
                "threshold_plus_ml_count": 0,
                "threshold_enriched_by_ml_count": 0,
                "known_class_match_count": 0,
                "threshold_only_correlation_count": 0,
                "ml_only_correlation_count": 0,
                "anomaly_only_correlation_count": 0,
                "effective_runtime_mode": "hybrid",
                "effective_inference_mode": "combined",
            },
        ]

        mode_summary = build_mode_comparison(rows)
        family_summary = build_family_summary(rows)
        intent_summary = build_intent_summary(rows)

        self.assertEqual(len(mode_summary), 2)
        hybrid_row = next(row for row in mode_summary if row["mode"] == "hybrid")
        self.assertAlmostEqual(hybrid_row["precision"], 1.0)
        self.assertAlmostEqual(hybrid_row["recall"], 1.0)
        self.assertAlmostEqual(hybrid_row["threshold_plus_ml_frequency"], 0.5)
        self.assertAlmostEqual(hybrid_row["threshold_evasive_detection_rate"], 1.0)
        threshold_row = next(row for row in mode_summary if row["mode"] == "threshold_only")
        self.assertAlmostEqual(threshold_row["classifier_target_detection_rate"], 0.0)

        self.assertEqual(len(family_summary), 3)
        stealth_hybrid_family = next(
            row
            for row in family_summary
            if row["mode"] == "hybrid" and row["scenario_family"] == "tcp_port_scan_stealth"
        )
        self.assertAlmostEqual(stealth_hybrid_family["attack_detection_rate"], 1.0)

        self.assertEqual(len(intent_summary), 4)
        threshold_evasive_hybrid = next(
            row
            for row in intent_summary
            if row["mode"] == "hybrid" and row["intent_name"] == "threshold_evasive"
        )
        self.assertAlmostEqual(threshold_evasive_hybrid["attack_detection_rate"], 1.0)

    def test_build_scenario_comparison_consolidates_layered_slots(self):
        rows = [
            {
                "mode": "threshold_only",
                "mode_title": "Threshold IDS Only",
                "scenario": "stealth_scan_h1",
                "scenario_family": "tcp_port_scan_stealth",
                "expected_detection_target": "classifier",
                "attack_detected": True,
                "mitigation_observed": False,
                "threshold_alert_count": 1,
                "ml_alert_count": 0,
                "hybrid_consensus_count": 0,
                "threshold_plus_ml_count": 0,
                "threshold_enriched_by_ml_count": 0,
                "anomaly_only_correlation_count": 0,
                "mitigation_src_ip": "",
                "mitigation_detector": "",
            },
            {
                "mode": "classifier_only",
                "mode_title": "Classifier Only",
                "scenario": "stealth_scan_h1",
                "scenario_family": "tcp_port_scan_stealth",
                "expected_detection_target": "classifier",
                "attack_detected": True,
                "mitigation_observed": False,
                "threshold_alert_count": 0,
                "ml_alert_count": 1,
                "hybrid_consensus_count": 0,
                "threshold_plus_ml_count": 0,
                "threshold_enriched_by_ml_count": 0,
                "anomaly_only_correlation_count": 0,
                "mitigation_src_ip": "",
                "mitigation_detector": "",
            },
            {
                "mode": "anomaly_only",
                "mode_title": "Anomaly Only",
                "scenario": "stealth_scan_h1",
                "scenario_family": "tcp_port_scan_stealth",
                "expected_detection_target": "classifier",
                "attack_detected": True,
                "mitigation_observed": False,
                "threshold_alert_count": 0,
                "ml_alert_count": 1,
                "hybrid_consensus_count": 0,
                "threshold_plus_ml_count": 0,
                "threshold_enriched_by_ml_count": 0,
                "anomaly_only_correlation_count": 1,
                "mitigation_src_ip": "",
                "mitigation_detector": "",
            },
            {
                "mode": "hybrid_blocking",
                "mode_title": "Hybrid Blocking",
                "scenario": "stealth_scan_h1",
                "scenario_family": "tcp_port_scan_stealth",
                "expected_detection_target": "classifier",
                "attack_detected": True,
                "mitigation_observed": True,
                "threshold_alert_count": 0,
                "ml_alert_count": 1,
                "hybrid_consensus_count": 0,
                "threshold_plus_ml_count": 0,
                "threshold_enriched_by_ml_count": 0,
                "known_class_match_count": 0,
                "ml_only_correlation_count": 0,
                "anomaly_only_correlation_count": 0,
                "mitigation_src_ip": "10.0.0.1",
                "mitigation_detector": "ml",
                "latest_ml_alert_decision": "hybrid_ml_block",
                "latest_ml_alert_reason": "threshold_suspicion_elevated_by_strong_ml_evidence",
                "prediction_label": "malicious",
                "prediction_reason": "classifier_and_anomaly_agree",
                "prediction_confidence": 0.960789,
                "prediction_anomaly_score": 0.635445,
                "prediction_is_anomalous": True,
                "predicted_family": "",
                "prediction_summary": "Classifier and anomaly detector both flagged the host.",
                "repeat": 1,
            },
        ]

        summary = build_scenario_comparison(rows)

        self.assertEqual(len(summary), 1)
        row = summary[0]
        self.assertEqual(row["scenario"], "stealth_scan_h1")
        self.assertEqual(row["threshold_mode"], "threshold_only")
        self.assertEqual(row["classifier_mode"], "classifier_only")
        self.assertEqual(row["anomaly_mode"], "anomaly_only")
        self.assertEqual(row["hybrid_mode"], "hybrid_blocking")
        self.assertTrue(row["threshold_detected"])
        self.assertTrue(row["classifier_detected"])
        self.assertTrue(row["anomaly_detected"])
        self.assertTrue(row["hybrid_detected"])
        self.assertTrue(row["hybrid_blocked"])
        self.assertEqual(row["hybrid_blocked_host"], "10.0.0.1")
        self.assertEqual(row["hybrid_block_detector"], "ml")
        self.assertEqual(row["hybrid_final_decision"], "hybrid_ml_block")
        self.assertEqual(row["prediction_reason"], "classifier_and_anomaly_agree")
        self.assertEqual(row["prediction_confidence"], 0.960789)
        self.assertEqual(row["prediction_anomaly_score"], 0.635445)
        self.assertEqual(row["ml_added_value"], "hybrid_ml_assisted_block")

    def test_build_scenario_comparison_handles_missing_modes_gracefully(self):
        rows = [
            {
                "mode": "hybrid",
                "mode_title": "Hybrid",
                "scenario": "periodic_beacon_h4",
                "scenario_family": "periodic_beacon_like",
                "expected_detection_target": "anomaly",
                "attack_detected": True,
                "mitigation_observed": False,
                "threshold_alert_count": 0,
                "ml_alert_count": 2,
                "hybrid_consensus_count": 0,
                "threshold_plus_ml_count": 0,
                "threshold_enriched_by_ml_count": 0,
                "known_class_match_count": 0,
                "ml_only_correlation_count": 0,
                "anomaly_only_correlation_count": 1,
                "mitigation_src_ip": "",
                "mitigation_detector": "",
                "latest_ml_alert_decision": "anomaly_only_alert",
                "latest_ml_alert_reason": "anomaly_score_above_threshold",
                "prediction_label": "benign",
                "prediction_reason": "anomaly_score_above_threshold",
                "prediction_confidence": 0.680202,
                "prediction_anomaly_score": 0.680202,
                "prediction_is_anomalous": True,
                "predicted_family": "",
                "prediction_summary": "Anomaly detector flagged the host.",
                "repeat": 1,
            },
        ]

        summary = build_scenario_comparison(rows)

        self.assertEqual(len(summary), 1)
        row = summary[0]
        self.assertEqual(row["threshold_mode"], "")
        self.assertEqual(row["classifier_mode"], "")
        self.assertEqual(row["anomaly_mode"], "")
        self.assertEqual(row["hybrid_mode"], "hybrid")
        self.assertFalse(row["threshold_detected"])
        self.assertFalse(row["classifier_detected"])
        self.assertFalse(row["anomaly_detected"])
        self.assertTrue(row["hybrid_detected"])
        self.assertFalse(row["hybrid_blocked"])
        self.assertEqual(row["hybrid_final_decision"], "anomaly_only_alert")
        self.assertEqual(row["ml_added_value"], "anomaly_alert_on_threshold_miss")
        self.assertIsNone(row["threshold_detection_rate"])

    def test_build_scenario_comparison_prefers_threshold_owned_block_over_latest_ml_alert(self):
        rows = [
            {
                "mode": "hybrid_blocking",
                "mode_title": "Hybrid Blocking",
                "scenario": "threshold_syn_flood_h4",
                "scenario_family": "syn_flood_open_port",
                "expected_detection_target": "threshold",
                "attack_detected": True,
                "mitigation_observed": True,
                "threshold_alert_count": 3,
                "ml_alert_count": 1,
                "hybrid_consensus_count": 1,
                "threshold_plus_ml_count": 1,
                "threshold_enriched_by_ml_count": 0,
                "known_class_match_count": 0,
                "ml_only_correlation_count": 0,
                "anomaly_only_correlation_count": 0,
                "mitigation_src_ip": "10.0.0.4",
                "mitigation_detector": "threshold",
                "latest_ml_alert_decision": "anomaly_only_alert",
                "latest_ml_alert_reason": "anomaly_score_above_threshold",
                "latest_threshold_reason": "packet_rate_threshold_exceeded",
                "repeat": 1,
            },
        ]

        summary = build_scenario_comparison(rows)

        self.assertEqual(len(summary), 1)
        row = summary[0]
        self.assertEqual(row["hybrid_final_decision"], "threshold_block_with_ml_consensus")
        self.assertEqual(row["hybrid_block_detector"], "threshold")
        self.assertEqual(row["ml_added_value"], "threshold_owned_block_with_ml_enrichment")


if __name__ == "__main__":
    unittest.main()
