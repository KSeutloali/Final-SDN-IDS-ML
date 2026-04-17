"""Tests for monitoring metrics accounting."""

import unittest

from ml.pipeline import HybridCorrelationEvent
from monitoring.metrics import MetricsStore
from security.ids import IDSAlert


class MetricsStoreTests(unittest.TestCase):
    def test_hybrid_agreement_is_counted_once(self):
        metrics = MetricsStore()

        alert = IDSAlert(
            alert_type="random_forest_detected",
            src_ip="10.0.0.3",
            reason="threshold_and_ml_agree",
            detector="ml",
            details={"agreement_with_threshold": True},
        )
        metrics.record_alert(alert, source="ml")
        self.assertEqual(metrics.snapshot()["hybrid_agreements_total"], 0)

        metrics.record_hybrid_correlation(
            HybridCorrelationEvent(
                src_ip="10.0.0.3",
                status="agreement",
                reason="threshold_and_ml_agree",
                timestamp=1.0,
                correlation_window_seconds=10,
                threshold_timestamp=0.5,
                ml_timestamp=1.0,
                confidence=0.95,
                suspicion_score=0.97,
            )
        )

        snapshot = metrics.snapshot()
        self.assertEqual(snapshot["hybrid_agreements_total"], 1)
        self.assertEqual(snapshot["hybrid_correlated_total"], 1)

    def test_layered_hybrid_statuses_are_counted(self):
        metrics = MetricsStore()

        metrics.record_hybrid_correlation(
            HybridCorrelationEvent(
                src_ip="10.0.0.3",
                status="threshold_enriched_by_ml",
                reason="subthreshold_recon_pattern_enriched_by_ml",
                timestamp=1.0,
                correlation_window_seconds=10,
            )
        )
        metrics.record_hybrid_correlation(
            HybridCorrelationEvent(
                src_ip="10.0.0.4",
                status="anomaly_only",
                reason="ml_suspicion_above_alert_only_threshold",
                timestamp=2.0,
                correlation_window_seconds=10,
            )
        )

        snapshot = metrics.snapshot()
        self.assertEqual(snapshot["hybrid_agreements_total"], 1)
        self.assertEqual(snapshot["ml_only_detections_total"], 1)

    def test_reset_runtime_session_clears_live_counters(self):
        metrics = MetricsStore()

        alert = IDSAlert(
            alert_type="port_scan_detected",
            src_ip="10.0.0.3",
            reason="unique_destination_ports_threshold_exceeded",
        )
        metrics.record_alert(alert, source="threshold")
        metrics.record_controller_event("datapath_up", {"dpid": "0001"})
        metrics.record_flow_event(
            "flow_rule_installed",
            {"dpid": "0001", "reason": "mac_learning_forward"},
        )

        metrics.reset_runtime_session()
        snapshot = metrics.snapshot()

        self.assertEqual(snapshot["alerts_total"], 0)
        self.assertEqual(snapshot["controller_events_total"], 0)
        self.assertEqual(snapshot["flow_installs_total"], 0)
        self.assertEqual(snapshot["top_sources"], [])
        self.assertEqual(metrics.recent_events_list(), [])


if __name__ == "__main__":
    unittest.main()
