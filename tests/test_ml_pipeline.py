"""Unit tests for optional ML IDS runtime behavior."""

import os
import tempfile
import unittest

from config.settings import MLConfig
from ml.feature_extractor import RUNTIME_FEATURE_NAMES
from ml.model_loader import save_model_bundle
from ml.pipeline import MLIDSPipeline
from security.ids import IDSAlert


class FakeRandomForestModel(object):
    classes_ = ["benign", "malicious"]

    def __init__(self, label="malicious", malicious_probability=0.95):
        self.label = label
        self.malicious_probability = malicious_probability

    def predict(self, rows):
        return [self.label for _ in rows]

    def predict_proba(self, rows):
        benign_probability = 1.0 - self.malicious_probability
        return [[benign_probability, self.malicious_probability] for _ in rows]


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
            "recon_suspicious": False,
            "recon_suspicion_score": 0,
            "recon_visible_traffic": True,
            "forwarding_visibility": "tcp_syn_probe",
        }
        payload.update(overrides)
        return payload

    def test_missing_model_falls_back_to_threshold_only(self):
        pipeline = MLIDSPipeline(
            MLConfig(
                enabled=True,
                mode="hybrid",
                model_path="models/does-not-exist.joblib",
            )
        )
        self.assertEqual(pipeline.effective_mode(), "threshold_only")

    def test_high_confidence_hybrid_alert_can_mitigate(self):
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
        self.assertTrue(result.alert.should_mitigate)
        self.assertEqual(result.alert.decision, "hybrid_ml_block")

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
                    hybrid_policy="consensus_severity",
                    model_path=model_path,
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
