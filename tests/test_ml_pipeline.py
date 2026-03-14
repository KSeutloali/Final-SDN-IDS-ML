"""Unit tests for optional ML IDS runtime behavior."""

import os
import tempfile
import unittest

from config.settings import MLConfig
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
                    "feature_names": (
                        "packet_count",
                        "byte_count",
                        "unique_destination_ports",
                        "unique_destination_ips",
                        "connection_rate",
                        "syn_rate",
                        "icmp_rate",
                        "udp_rate",
                        "tcp_rate",
                        "average_packet_size",
                        "observation_window_seconds",
                        "packet_rate",
                        "bytes_per_second",
                        "failed_connection_rate",
                    ),
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

    def test_threshold_and_ml_agreement_marks_alert_as_confirmed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "rf.joblib")
            save_model_bundle(
                model_path,
                {
                    "model": FakeRandomForestModel(malicious_probability=0.88),
                    "feature_names": (
                        "packet_count",
                        "byte_count",
                        "unique_destination_ports",
                        "unique_destination_ips",
                        "connection_rate",
                        "syn_rate",
                        "icmp_rate",
                        "udp_rate",
                        "tcp_rate",
                        "average_packet_size",
                        "observation_window_seconds",
                        "packet_rate",
                        "bytes_per_second",
                        "failed_connection_rate",
                    ),
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
            )

        self.assertIsNotNone(result.alert)
        self.assertFalse(result.alert.should_mitigate)
        self.assertEqual(result.alert.decision, "confirmed_by_threshold")
        self.assertEqual(result.alert.severity, "critical")
        self.assertTrue(result.alert.details["agreement_with_threshold"])

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


if __name__ == "__main__":
    unittest.main()
