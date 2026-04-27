"""Unit tests for optional ML IDS runtime behavior."""

import os
import tempfile
import unittest
from unittest.mock import patch

from config.settings import MLConfig
from ml.anomaly import RuntimeIsolationForestModel, RuntimeIsolationTree
from ml.feature_extractor import RUNTIME_FEATURE_NAMES
from ml.model_loader import save_model_bundle
from ml.pipeline import MLIDSPipeline
from security.ids import IDSAlert


class FakeRandomForestModel(object):
    def __init__(
        self,
        label="malicious",
        malicious_probability=0.95,
        classes=None,
    ):
        self.label = label
        self.malicious_probability = malicious_probability
        self.classes_ = list(classes or ["benign", "malicious"])

    def predict(self, rows):
        return [self.label for _ in rows]

    def predict_proba(self, rows):
        benign_probability = 1.0 - self.malicious_probability
        if self.classes_ == ["benign", "malicious"]:
            return [[benign_probability, self.malicious_probability] for _ in rows]

        row = []
        for class_name in self.classes_:
            if class_name == self.label:
                row.append(self.malicious_probability)
            elif class_name == "benign":
                row.append(benign_probability)
            else:
                row.append(0.0)
        return [row for _ in rows]


def _portable_runtime_model():
    return RuntimeIsolationForestModel(
        trees=[
            RuntimeIsolationTree(
                children_left=[1, -1, -1],
                children_right=[2, -1, -1],
                feature=[0, -2, -2],
                threshold=[0.5, -2.0, -2.0],
                n_node_samples=[9, 8, 1],
            )
        ],
        max_samples=8,
        anomaly_threshold=0.6,
        contamination=0.2,
    )


class PacketStub(object):
    def __init__(
        self,
        timestamp=1.0,
        src_ip="10.0.0.3",
        dst_ip="10.0.0.2",
        protocol="tcp",
        dst_port=80,
        src_port=12000,
        packet_length=100,
        tcp_syn_only=True,
        tcp_rst=False,
    ):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.transport_protocol = protocol
        self.dst_port = dst_port
        self.src_port = src_port
        self.packet_length = packet_length
        self.is_ipv4 = True
        self.tcp_syn_only = tcp_syn_only
        self.tcp_rst = tcp_rst


class MLPipelineTests(unittest.TestCase):
    @staticmethod
    def _threshold_context(**overrides):
        payload = {
            "threshold_triggered": False,
            "threshold_reason": "",
            "threshold_rule_family": "",
            "threshold_severity": "",
            "threshold_recent_event_count": 0,
            "unanswered_syn_count": 0,
            "scan_unique_destination_hosts": 0,
            "scan_unique_destination_ports": 0,
            "threshold_auto_quarantine_eligible": True,
            "recon_suspicious": False,
            "recon_suspicion_score": 0,
            "recon_visible_traffic": True,
            "forwarding_visibility": "tcp_syn_probe",
        }
        payload.update(overrides)
        return payload

    @staticmethod
    def _write_anomaly_bundle(model_path):
        save_model_bundle(
            model_path,
            {
                "model": _portable_runtime_model(),
                "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                "positive_labels": ("anomalous",),
                "metadata": {
                    "model_name": "isolation_forest",
                    "model_version": "1",
                    "anomaly_threshold": 0.6,
                    "contamination": 0.2,
                    "max_samples": 8,
                },
            },
        )

    def test_missing_model_falls_back_to_threshold_only(self):
        pipeline = MLIDSPipeline(
            MLConfig(
                enabled=True,
                mode="hybrid",
                model_path="models/does-not-exist.joblib",
            )
        )
        self.assertEqual(pipeline.effective_mode(), "threshold_only")

    def test_high_confidence_hybrid_alert_stays_alert_only_without_context(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(malicious_probability=0.97),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="high_confidence_block",
                    model_path=model_path,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                    confidence_threshold=0.70,
                    mitigation_threshold=0.90,
                )
            )

            result = pipeline.inspect(PacketStub())

        self.assertIsNotNone(result.alert)
        self.assertFalse(result.alert.should_mitigate)
        self.assertEqual(result.alert.decision, "ml_only_alert")

    def test_runtime_mode_switch_updates_effective_mode_without_restart(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(malicious_probability=0.94),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=False,
                    mode="threshold_only",
                    model_path=model_path,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                )
            )

            self.assertEqual(pipeline.effective_mode(), "threshold_only")

            change = pipeline.set_mode("ml")

        self.assertTrue(change["changed"])
        self.assertEqual(change["selected_mode_api"], "ml")
        self.assertEqual(change["effective_mode"], "ml_only")
        self.assertEqual(pipeline.status()["selected_mode_api"], "ml")
        self.assertEqual(pipeline.status()["effective_mode_api"], "ml")

    def test_threshold_and_ml_agreement_marks_alert_as_confirmed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(malicious_probability=0.88),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="consensus_severity",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    anomaly_score_threshold=0.6,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=30,
                    confidence_threshold=0.70,
                    mitigation_threshold=0.95,
                )
            )

            threshold_alert = IDSAlert(
                alert_type="port_scan_detected",
                src_ip="10.0.0.3",
                reason="unique_destination_ports_threshold_exceeded",
                timestamp=1.0,
            )
            result = pipeline.inspect(
                PacketStub(timestamp=2.0),
                threshold_alerts=[threshold_alert],
                threshold_context=self._threshold_context(
                    threshold_triggered=True,
                    threshold_reason="tcp_scan_threshold_exceeded",
                    threshold_rule_family="recon",
                    threshold_severity="high",
                    threshold_recent_event_count=1,
                    unanswered_syn_count=4,
                    scan_unique_destination_ports=4,
                ),
            )

        self.assertIsNotNone(result.alert)
        self.assertFalse(result.alert.should_mitigate)
        self.assertEqual(result.alert.decision, "threshold_enriched_by_ml")
        self.assertEqual(result.alert.severity, "critical")
        self.assertTrue(result.alert.details["agreement_with_threshold"])
        self.assertEqual(result.alert.details["correlation_status"], "known_class_match")
        self.assertTrue(result.alert.details["is_anomalous"])
        self.assertGreater(result.alert.details["anomaly_score"], 0.6)
        self.assertIn("abnormal_feature_summary", result.alert.details)
        self.assertIn("explanation", result.alert.details)
        self.assertEqual(result.alert.details["explanation"]["correlation_status"], "known_class_match")
        self.assertIn("Threshold and ML agreed", result.alert.details["explanation_summary"])

    def test_low_confidence_recon_signal_can_raise_hybrid_alert_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(
                        label="benign",
                        malicious_probability=0.61,
                    ),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="alert_only",
                    model_path=model_path,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    confidence_threshold=0.70,
                    alert_only_threshold=0.55,
                    alert_suppression_seconds=0,
                )
            )

            result = pipeline.inspect(
                PacketStub(timestamp=3.0),
                threshold_context=self._threshold_context(
                    recon_suspicious=True,
                    recon_suspicion_score=2,
                    unanswered_syn_count=3,
                    scan_unique_destination_ports=3,
                ),
            )

        self.assertIsNotNone(result.alert)
        self.assertFalse(result.alert.should_mitigate)
        self.assertEqual(result.alert.decision, "threshold_enriched_by_ml")
        self.assertEqual(result.alert.details["correlation_status"], "threshold_enriched_by_ml")
        self.assertEqual(result.alert.reason, "subthreshold_recon_pattern_enriched_by_ml")
        self.assertIn("sub-threshold pattern", result.alert.details["explanation_summary"])

    def test_layered_consensus_blocks_threshold_suspicious_pattern_with_strong_ml_support(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(malicious_probability=0.93),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="layered_consensus",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                    confidence_threshold=0.70,
                    hybrid_classifier_block_threshold=0.80,
                    hybrid_anomaly_support_threshold=0.60,
                    hybrid_block_repeat_count=2,
                )
            )

            first_result = pipeline.inspect(
                PacketStub(timestamp=1.0, packet_length=120, dst_port=22),
                threshold_context=self._threshold_context(
                    recon_suspicious=True,
                    recon_suspicion_score=2,
                    unanswered_syn_count=3,
                    scan_unique_destination_ports=3,
                ),
            )
            second_result = pipeline.inspect(
                PacketStub(timestamp=2.0, packet_length=120, dst_port=23),
                threshold_context=self._threshold_context(
                    recon_suspicious=True,
                    recon_suspicion_score=2,
                    unanswered_syn_count=4,
                    scan_unique_destination_ports=4,
                ),
            )

        self.assertIsNotNone(first_result.alert)
        self.assertTrue(first_result.alert.should_mitigate)
        self.assertEqual(first_result.alert.decision, "hybrid_ml_block")
        self.assertIsNotNone(second_result.alert)
        self.assertTrue(second_result.alert.should_mitigate)
        self.assertEqual(second_result.alert.decision, "hybrid_ml_block")
        self.assertEqual(
            second_result.alert.reason,
            "threshold_suspicion_elevated_by_strong_ml_evidence",
        )
        self.assertTrue(second_result.alert.details["hybrid_block_eligible"])
        self.assertEqual(
            second_result.alert.details["block_decision_path"],
            "threshold_suspicion_elevated_by_ml",
        )
        self.assertIn(
            "threshold_suspicious_context",
            second_result.alert.details["hybrid_block_reasons"],
        )
        self.assertIn(
            "anomaly_score_support",
            second_result.alert.details["hybrid_block_reasons"],
        )

    def test_layered_consensus_does_not_block_alert_only_icmp_threshold_context(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(malicious_probability=0.93),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="layered_consensus",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                    confidence_threshold=0.70,
                    hybrid_classifier_block_threshold=0.80,
                    hybrid_anomaly_support_threshold=0.60,
                    hybrid_block_repeat_count=2,
                )
            )

            result = pipeline.inspect(
                PacketStub(timestamp=1.0, packet_length=120, protocol="icmp"),
                threshold_context=self._threshold_context(
                    threshold_reason="icmp_sweep_threshold_exceeded",
                    threshold_recent_event_count=1,
                    threshold_auto_quarantine_eligible=False,
                    recon_suspicious=True,
                    recon_suspicion_score=2,
                    scan_unique_destination_hosts=4,
                    forwarding_visibility="icmp_probe_candidate",
                ),
            )

        self.assertIsNotNone(result.alert)
        self.assertFalse(result.alert.should_mitigate)
        self.assertNotEqual(result.alert.decision, "hybrid_ml_block")

    def test_layered_consensus_keeps_threshold_triggered_cases_threshold_owned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(malicious_probability=0.95),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="layered_consensus",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                )
            )

            threshold_alert = IDSAlert(
                alert_type="port_scan_detected",
                src_ip="10.0.0.3",
                reason="tcp_scan_threshold_exceeded",
                timestamp=1.0,
            )
            result = pipeline.inspect(
                PacketStub(timestamp=2.0, packet_length=120),
                threshold_alerts=[threshold_alert],
                threshold_context=self._threshold_context(
                    threshold_triggered=True,
                    threshold_reason="tcp_scan_threshold_exceeded",
                    threshold_rule_family="recon",
                    threshold_severity="high",
                    threshold_recent_event_count=1,
                    recon_suspicious=True,
                    recon_suspicion_score=3,
                ),
            )

        self.assertIsNotNone(result.alert)
        self.assertFalse(result.alert.should_mitigate)
        self.assertEqual(result.alert.decision, "threshold_enriched_by_ml")
        self.assertFalse(result.alert.details["hybrid_block_eligible"])

    def test_layered_consensus_can_block_known_family_after_repeated_confirmations(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(
                        label="tcp_scan",
                        malicious_probability=0.91,
                        classes=("benign", "malicious", "tcp_scan"),
                    ),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious", "tcp_scan"),
                    "metadata": {
                        "model_name": "random_forest",
                        "model_version": "1",
                        "label_mode": "family",
                    },
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="layered_consensus",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                    hybrid_block_repeat_count=2,
                )
            )

            first_result = pipeline.inspect(PacketStub(timestamp=1.0, packet_length=120, dst_port=22))
            second_result = pipeline.inspect(PacketStub(timestamp=2.0, packet_length=120, dst_port=23))

        self.assertIsNotNone(first_result.alert)
        self.assertFalse(first_result.alert.should_mitigate)
        self.assertEqual(first_result.alert.details["predicted_family"], "tcp_scan")
        self.assertIsNotNone(second_result.alert)
        self.assertTrue(second_result.alert.should_mitigate)
        self.assertEqual(second_result.alert.decision, "hybrid_ml_block")
        self.assertEqual(
            second_result.alert.reason,
            "known_family_prediction_supported_by_context",
        )
        self.assertIn(
            "known_malicious_family",
            second_result.alert.details["hybrid_block_reasons"],
        )

    def test_hybrid_escalation_is_not_suppressed_when_alert_becomes_block(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(malicious_probability=0.93),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="layered_consensus",
                    model_path=model_path,
                    inference_mode="classifier_only",
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=30,
                    confidence_threshold=0.70,
                    hybrid_classifier_block_threshold=0.80,
                    hybrid_block_repeat_count=2,
                )
            )

            first_result = pipeline.inspect(
                PacketStub(timestamp=1.0, packet_length=120, dst_port=22),
                threshold_context=self._threshold_context(
                    recon_suspicious=True,
                    recon_suspicion_score=1,
                    unanswered_syn_count=2,
                    scan_unique_destination_ports=2,
                ),
            )
            second_result = pipeline.inspect(
                PacketStub(timestamp=2.0, packet_length=120, dst_port=23),
                threshold_context=self._threshold_context(
                    recon_suspicious=True,
                    recon_suspicion_score=1,
                    unanswered_syn_count=2,
                    scan_unique_destination_ports=2,
                ),
            )

        self.assertIsNotNone(first_result.alert)
        self.assertFalse(first_result.alert.should_mitigate)
        self.assertIsNotNone(second_result.alert)
        self.assertTrue(second_result.alert.should_mitigate)
        self.assertEqual(second_result.alert.decision, "hybrid_ml_block")
        self.assertEqual(second_result.alert.details["repeated_window_count"], 2)
        self.assertEqual(
            second_result.alert.details["final_block_reason"],
            "threshold_suspicion_elevated_by_strong_ml_evidence",
        )

    def test_hybrid_anomaly_only_block_requires_explicit_opt_in_and_strong_context(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(
                        label="benign",
                        malicious_probability=0.2,
                    ),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="layered_consensus",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    anomaly_score_threshold=0.6,
                    hybrid_anomaly_support_threshold=0.6,
                    hybrid_anomaly_only_block_enabled=True,
                    hybrid_anomaly_only_block_threshold=0.6,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                )
            )

            with patch.object(
                pipeline,
                "_record_decision_window",
                return_value={
                    "signal_window_count": 3,
                    "threshold_suspicious_repeat_count": 3,
                    "threshold_near_miss_count": 3,
                    "anomaly_only_repeat_count": 3,
                    "anomalous_window_count": 3,
                    "anomaly_trend_delta": 0.12,
                    "anomaly_trend_rising": True,
                },
            ):
                result = pipeline.inspect(
                    PacketStub(timestamp=4.0, packet_length=120, dst_port=8080),
                    threshold_context=self._threshold_context(
                        recon_suspicious=True,
                        recon_suspicion_score=1,
                    ),
                )

        self.assertIsNotNone(result.alert)
        self.assertTrue(result.alert.should_mitigate)
        self.assertEqual(result.alert.decision, "hybrid_ml_block")
        self.assertEqual(
            result.alert.reason,
            "repeated_high_anomaly_pattern_supported_by_threshold_near_misses",
        )
        self.assertEqual(
            result.alert.details["block_decision_path"],
            "anomaly_only_narrow_escalation",
        )
        self.assertIn(
            "repeated_anomaly_only_windows",
            result.alert.details["hybrid_block_reasons"],
        )

    def test_hybrid_anomaly_only_block_can_trigger_without_threshold_signal_when_persistence_is_strong(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(
                        label="benign",
                        malicious_probability=0.2,
                    ),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="layered_consensus",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    anomaly_score_threshold=0.6,
                    hybrid_anomaly_support_threshold=0.6,
                    hybrid_anomaly_only_block_enabled=True,
                    hybrid_anomaly_only_block_threshold=0.6,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                )
            )

            with patch.object(
                pipeline,
                "_record_decision_window",
                return_value={
                    "signal_window_count": 4,
                    "threshold_suspicious_repeat_count": 0,
                    "threshold_near_miss_count": 0,
                    "anomaly_only_repeat_count": 4,
                    "anomalous_window_count": 4,
                    "anomaly_trend_delta": 0.18,
                    "anomaly_trend_rising": True,
                },
            ):
                result = pipeline.inspect(
                    PacketStub(timestamp=5.0, packet_length=120, dst_port=9000),
                    threshold_context=self._threshold_context(
                        recon_suspicious=False,
                        recon_visible_traffic=False,
                        forwarding_visibility="fast_path",
                    ),
                )

        self.assertIsNotNone(result.alert)
        self.assertTrue(result.alert.should_mitigate)
        self.assertEqual(result.alert.decision, "hybrid_ml_block")
        self.assertEqual(
            result.alert.reason,
            "repeated_high_anomaly_pattern_without_threshold_signal",
        )
        self.assertEqual(result.alert.details["correlation_status"], "anomaly_only")
        self.assertEqual(
            result.alert.details["block_decision_path"],
            "anomaly_only_strong_persistence_block",
        )
        self.assertIn(
            "repeated_anomalous_windows",
            result.alert.details["hybrid_block_reasons"],
        )
        self.assertEqual(result.alert.details["hybrid_anomaly_only_required_windows"], 4)
        self.assertEqual(result.alert.details["hybrid_threshold_near_miss_repeat_count"], 2)

    def test_hybrid_anomaly_only_block_without_threshold_signal_requires_stronger_persistence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(
                        label="benign",
                        malicious_probability=0.2,
                    ),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="layered_consensus",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    anomaly_score_threshold=0.6,
                    hybrid_anomaly_support_threshold=0.6,
                    hybrid_anomaly_only_block_enabled=True,
                    hybrid_anomaly_only_block_threshold=0.6,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                )
            )

            with patch.object(
                pipeline,
                "_record_decision_window",
                return_value={
                    "signal_window_count": 3,
                    "threshold_suspicious_repeat_count": 0,
                    "threshold_near_miss_count": 0,
                    "anomaly_only_repeat_count": 3,
                    "anomalous_window_count": 3,
                    "anomaly_trend_delta": 0.12,
                    "anomaly_trend_rising": True,
                },
            ):
                result = pipeline.inspect(
                    PacketStub(timestamp=5.0, packet_length=120, dst_port=9000),
                    threshold_context=self._threshold_context(
                        recon_suspicious=False,
                        recon_visible_traffic=False,
                        forwarding_visibility="fast_path",
                    ),
                )

        self.assertIsNotNone(result.alert)
        self.assertFalse(result.alert.should_mitigate)
        self.assertEqual(result.alert.decision, "anomaly_only_alert")
        self.assertEqual(result.alert.details["block_decision_path"], "")
        self.assertEqual(result.alert.details["hybrid_anomaly_only_required_windows"], 4)

    def test_hybrid_anomaly_only_detection_stays_alert_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(
                        label="benign",
                        malicious_probability=0.2,
                    ),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="high_confidence_block",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    anomaly_score_threshold=0.6,
                    anomaly_only_escalation_count=3,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                    confidence_threshold=0.70,
                    mitigation_threshold=0.80,
                )
            )

            result = pipeline.inspect(PacketStub(timestamp=3.0, packet_length=120))

        self.assertIsNotNone(result.alert)
        self.assertFalse(result.alert.should_mitigate)
        self.assertEqual(result.alert.decision, "anomaly_only_alert")
        self.assertEqual(result.alert.details["correlation_status"], "anomaly_only")
        self.assertTrue(result.alert.details["is_anomalous"])
        self.assertEqual(result.alert.severity, "medium")
        self.assertIn("Only the anomaly detector flagged", result.alert.details["explanation_summary"])
        self.assertIn("feature_context", result.alert.details["explanation"])

    def test_hybrid_classifier_only_signal_without_threshold_is_suppressed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(
                        label="malicious",
                        malicious_probability=0.86,
                    ),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="alert_only",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    anomaly_score_threshold=0.6,
                    ml_only_escalation_count=3,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                    confidence_threshold=0.70,
                )
            )

            first_result = pipeline.inspect(PacketStub(timestamp=1.0, packet_length=120))
            second_result = pipeline.inspect(PacketStub(timestamp=2.0, packet_length=120))
            third_result = pipeline.inspect(PacketStub(timestamp=3.0, packet_length=120))

        self.assertIsNone(first_result.alert)
        self.assertIsNone(second_result.alert)
        self.assertIsNone(third_result.alert)

    def test_hybrid_classifier_and_anomaly_consensus_alerts_without_threshold_context(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(
                        label="malicious",
                        malicious_probability=0.91,
                    ),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="layered_consensus",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                    confidence_threshold=0.70,
                    mitigation_threshold=0.80,
                    hybrid_anomaly_support_threshold=0.60,
                )
            )

            result = pipeline.inspect(
                PacketStub(timestamp=3.0, packet_length=120),
                threshold_context=self._threshold_context(
                    recon_suspicious=False,
                    recon_visible_traffic=False,
                    forwarding_visibility="fast_path",
                ),
            )

        self.assertIsNotNone(result.alert)
        self.assertFalse(result.alert.should_mitigate)
        self.assertEqual(result.alert.decision, "ml_only_alert")
        self.assertEqual(result.alert.details["correlation_status"], "ml_anomaly_consensus")
        self.assertEqual(
            result.alert.reason,
            "classifier_anomaly_consensus_without_threshold_context",
        )

    def test_repeated_classifier_anomaly_consensus_can_block_with_threshold_near_miss_history(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(
                        label="malicious",
                        malicious_probability=0.93,
                    ),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="layered_consensus",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                    confidence_threshold=0.70,
                    mitigation_threshold=0.80,
                    hybrid_anomaly_support_threshold=0.60,
                    hybrid_block_repeat_count=2,
                )
            )

            with patch.object(
                pipeline,
                "_record_decision_window",
                side_effect=[
                    {
                        "signal_window_count": 1,
                        "threshold_suspicious_repeat_count": 0,
                        "threshold_near_miss_count": 1,
                        "anomaly_only_repeat_count": 0,
                        "anomalous_window_count": 1,
                        "anomaly_trend_delta": 0.01,
                        "anomaly_trend_rising": False,
                    },
                    {
                        "signal_window_count": 2,
                        "threshold_suspicious_repeat_count": 0,
                        "threshold_near_miss_count": 2,
                        "anomaly_only_repeat_count": 0,
                        "anomalous_window_count": 2,
                        "anomaly_trend_delta": 0.08,
                        "anomaly_trend_rising": True,
                    },
                ],
            ):
                first_result = pipeline.inspect(
                    PacketStub(timestamp=3.0, packet_length=120),
                    threshold_context=self._threshold_context(
                        recon_suspicious=False,
                        recon_visible_traffic=False,
                        forwarding_visibility="fast_path",
                    ),
                )
                second_result = pipeline.inspect(
                    PacketStub(timestamp=4.0, packet_length=120),
                    threshold_context=self._threshold_context(
                        recon_suspicious=False,
                        recon_visible_traffic=False,
                        forwarding_visibility="fast_path",
                    ),
                )

        self.assertIsNotNone(first_result.alert)
        self.assertFalse(first_result.alert.should_mitigate)
        self.assertIsNotNone(second_result.alert)
        self.assertTrue(second_result.alert.should_mitigate)
        self.assertEqual(second_result.alert.decision, "hybrid_ml_block")
        self.assertEqual(
            second_result.alert.reason,
            "repeated_classifier_anomaly_consensus_supported_by_threshold_near_misses",
        )
        self.assertEqual(
            second_result.alert.details["block_decision_path"],
            "classifier_anomaly_consensus_block",
        )
        self.assertIn(
            "repeated_threshold_near_miss_windows",
            second_result.alert.details["hybrid_block_reasons"],
        )

    def test_threshold_plus_ml_summary_is_stable_without_known_family_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(
                        label="benign",
                        malicious_probability=0.2,
                    ),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="consensus_severity",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    anomaly_score_threshold=0.6,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                )
            )

            result = pipeline.inspect(
                PacketStub(timestamp=4.0, packet_length=120),
                threshold_alerts=[
                    IDSAlert(
                        alert_type="host_scan_detected",
                        src_ip="10.0.0.3",
                        reason="icmp_sweep_threshold_exceeded",
                        timestamp=3.0,
                    )
                ],
                threshold_context=self._threshold_context(
                    threshold_triggered=True,
                    threshold_reason="icmp_sweep_threshold_exceeded",
                    threshold_rule_family="",
                    threshold_severity="high",
                ),
            )

        self.assertIsNotNone(result.alert)
        self.assertEqual(result.alert.details["correlation_status"], "threshold_plus_ml")
        self.assertIn("Threshold and ML both flagged", result.alert.details["explanation_summary"])

    def test_repeated_anomaly_only_windows_escalate_severity_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="ml_only",
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="anomaly_only",
                    anomaly_score_threshold=0.6,
                    anomaly_only_escalation_count=2,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                )
            )

            first_result = pipeline.inspect(
                PacketStub(timestamp=1.0, packet_length=120, dst_port=9000)
            )
            second_result = pipeline.inspect(
                PacketStub(timestamp=2.0, packet_length=120, dst_port=9001)
            )

        self.assertIsNotNone(first_result.alert)
        self.assertEqual(first_result.alert.severity, "medium")
        self.assertFalse(first_result.alert.should_mitigate)
        self.assertIsNotNone(second_result.alert)
        self.assertEqual(second_result.alert.severity, "high")
        self.assertEqual(second_result.alert.reason, "repeated_anomaly_pattern_detected")
        self.assertFalse(second_result.alert.should_mitigate)

    def test_classifier_family_plus_high_anomaly_score_raises_severity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            anomaly_model_path = os.path.join(temp_dir, "anomaly.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(
                        label="tcp_scan",
                        malicious_probability=0.91,
                        classes=("benign", "malicious", "tcp_scan"),
                    ),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious", "tcp_scan"),
                    "metadata": {
                        "model_name": "random_forest",
                        "model_version": "1",
                        "label_mode": "family",
                    },
                },
            )
            self._write_anomaly_bundle(anomaly_model_path)
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    hybrid_policy="alert_only",
                    model_path=model_path,
                    anomaly_model_path=anomaly_model_path,
                    inference_mode="combined",
                    anomaly_score_threshold=0.6,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                    confidence_threshold=0.70,
                )
            )

            result = pipeline.inspect(PacketStub(timestamp=4.0, dst_port=8080))

        self.assertIsNotNone(result.alert)
        self.assertEqual(result.alert.severity, "critical")
        self.assertEqual(
            result.alert.reason,
            "classifier_family_supported_by_high_anomaly_score",
        )
        self.assertEqual(result.alert.details["predicted_family"], "tcp_scan")

    def test_ml_only_low_confidence_anomaly_stays_alert_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(
                        label="benign",
                        malicious_probability=0.6,
                    ),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="ml_only",
                    model_path=model_path,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    confidence_threshold=0.70,
                    alert_only_threshold=0.55,
                    alert_suppression_seconds=0,
                )
            )

            result = pipeline.inspect(PacketStub(timestamp=4.0))

        self.assertIsNotNone(result.alert)
        self.assertFalse(result.alert.should_mitigate)
        self.assertEqual(result.alert.details["correlation_status"], "anomaly_only")
        self.assertEqual(result.alert.decision, "anomaly_only_alert")

    def test_threshold_only_and_ml_only_correlations_expire_cleanly(self):
        pipeline = MLIDSPipeline(
            MLConfig(
                enabled=False,
                hybrid_correlation_window_seconds=5,
            )
        )

        threshold_alert = IDSAlert(
            alert_type="port_scan_detected",
            src_ip="10.0.0.3",
            reason="scan",
            timestamp=1.0,
        )
        threshold_events = pipeline.handle_threshold_alert(threshold_alert)
        self.assertEqual(threshold_events, [])

        ml_alert = type(
            "Alert",
            (),
            {
                "src_ip": "10.0.0.4",
                "alert_type": "random_forest_detected",
                "timestamp": 2.0,
                "confidence": 0.91,
                "suspicion_score": 0.93,
            },
        )()
        ml_events = pipeline.handle_ml_alert(ml_alert)
        self.assertEqual(ml_events, [])

        expired = pipeline.expire_correlations(8.5)
        statuses = sorted(event.status for event in expired)
        self.assertEqual(statuses, ["ml_only", "threshold_only"])

    def test_benign_prediction_can_lead_to_hybrid_disagreement(self):
        pipeline = MLIDSPipeline(
            MLConfig(
                enabled=False,
                hybrid_correlation_window_seconds=5,
            )
        )

        threshold_alert = IDSAlert(
            alert_type="port_scan_detected",
            src_ip="10.0.0.7",
            reason="scan",
            timestamp=10.0,
        )
        pipeline.handle_threshold_alert(threshold_alert)
        prediction = type(
            "Prediction",
            (),
            {
                "src_ip": "10.0.0.7",
                "timestamp": 11.0,
                "is_malicious": False,
                "confidence": 0.18,
                "suspicion_score": 0.12,
            },
        )()
        pipeline.note_prediction(prediction)

        expired = pipeline.expire_correlations(16.0)
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].status, "disagreement")

    def test_threshold_plus_ml_correlation_uses_layered_status(self):
        pipeline = MLIDSPipeline(
            MLConfig(
                enabled=False,
                hybrid_correlation_window_seconds=5,
            )
        )

        threshold_alert = IDSAlert(
            alert_type="port_scan_detected",
            src_ip="10.0.0.9",
            reason="tcp_scan_threshold_exceeded",
            timestamp=10.0,
        )
        pipeline.handle_threshold_alert(threshold_alert)
        ml_alert = type(
            "Alert",
            (),
            {
                "src_ip": "10.0.0.9",
                "alert_type": "random_forest_detected",
                "timestamp": 11.0,
                "confidence": 0.91,
                "suspicion_score": 0.93,
                "reason": "threshold_triggered_with_ml_context",
                "details": {"correlation_status": "known_class_match"},
            },
        )()

        events = pipeline.handle_ml_alert(ml_alert)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].status, "known_class_match")

    def test_reset_runtime_session_clears_pending_runtime_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(malicious_probability=0.88),
                    "feature_names": tuple(RUNTIME_FEATURE_NAMES),
                    "positive_labels": ("malicious",),
                    "metadata": {"model_name": "random_forest", "model_version": "1"},
                },
            )
            pipeline = MLIDSPipeline(
                MLConfig(
                    enabled=True,
                    mode="hybrid",
                    model_path=model_path,
                    minimum_packets_before_inference=1,
                    inference_packet_stride=1,
                    inference_cooldown_seconds=0.0,
                    alert_suppression_seconds=0,
                )
            )

            threshold_alert = IDSAlert(
                alert_type="port_scan_detected",
                src_ip="10.0.0.3",
                reason="unique_destination_ports_threshold_exceeded",
                timestamp=1.0,
            )
            pipeline.inspect(PacketStub(timestamp=2.0), threshold_alerts=[threshold_alert])
            self.assertTrue(pipeline.pending_threshold_alerts)
            self.assertTrue(pipeline.observed_packets)

            pipeline.reset_runtime_session()

            self.assertEqual(pipeline.pending_threshold_alerts, {})
            self.assertEqual(pipeline.pending_ml_alerts, {})
            self.assertEqual(pipeline.recent_prediction_state, {})
            self.assertEqual(pipeline.observed_packets, {})
            self.assertEqual(dict(pipeline.feature_extractor.host_windows), {})
            self.assertEqual(dict(pipeline.feature_extractor.unanswered_windows), {})
            self.assertEqual(dict(pipeline.feature_extractor.pending_attempt_counts), {})


if __name__ == "__main__":
    unittest.main()
