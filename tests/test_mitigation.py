"""Tests for mitigation gating helpers."""

import unittest
from types import SimpleNamespace

from security.mitigation import (
    clear_quarantines_for_topology_idle,
    should_auto_quarantine_threshold_alert,
)


class MitigationPolicyTests(unittest.TestCase):
    def test_non_icmp_threshold_alerts_remain_auto_quarantinable(self):
        alert = SimpleNamespace(
            reason="syn_rate_threshold_exceeded",
            details={"packet_count": 500},
        )
        self.assertTrue(should_auto_quarantine_threshold_alert(alert))

    def test_icmp_sweep_without_excess_host_coverage_stays_alert_only(self):
        alert = SimpleNamespace(
            reason="icmp_sweep_threshold_exceeded",
            details={
                "unique_destination_hosts": 4,
                "probe_count": 9,
                "exceeds_host_coverage_threshold": False,
            },
        )
        self.assertFalse(should_auto_quarantine_threshold_alert(alert))

    def test_icmp_sweep_with_excess_host_coverage_is_auto_quarantinable(self):
        alert = SimpleNamespace(
            reason="icmp_sweep_threshold_exceeded",
            details={
                "unique_destination_hosts": 5,
                "probe_count": 6,
                "exceeds_host_coverage_threshold": True,
            },
        )
        self.assertTrue(should_auto_quarantine_threshold_alert(alert))

    def test_icmp_sweep_backward_compatibility_defaults_to_auto_quarantine(self):
        alert = SimpleNamespace(
            reason="icmp_sweep_threshold_exceeded",
            details={"unique_destination_hosts": 4, "probe_count": 9},
        )
        self.assertTrue(should_auto_quarantine_threshold_alert(alert))

    def test_clear_quarantines_for_topology_idle_empties_quarantine_state(self):
        firewall = SimpleNamespace(
            quarantined_hosts={
                "10.0.0.1": SimpleNamespace(src_ip="10.0.0.1", reason="ids_port_scan_detected"),
                "10.0.0.3": SimpleNamespace(src_ip="10.0.0.3", reason="ml_random_forest_detected"),
            }
        )

        released = clear_quarantines_for_topology_idle(firewall)

        self.assertEqual(sorted(record.src_ip for record in released), ["10.0.0.1", "10.0.0.3"])
        self.assertEqual(firewall.quarantined_hosts, {})

    def test_clear_quarantines_for_topology_idle_handles_missing_firewall(self):
        released = clear_quarantines_for_topology_idle(None)
        self.assertEqual(released, [])


if __name__ == "__main__":
    unittest.main()
