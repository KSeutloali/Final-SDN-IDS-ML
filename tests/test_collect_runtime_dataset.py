"""Tests for runtime dataset collection scenario planning."""

import unittest

from scripts.collect_runtime_dataset import build_scenarios


class CollectRuntimeDatasetScenarioTests(unittest.TestCase):
    def _scenario_ids(self, scenarios):
        return [scenario.scenario_id for scenario in scenarios]

    def test_balanced_profile_keeps_existing_attack_families(self):
        scenarios = build_scenarios(
            collection_id="test-balanced",
            benign_repeats=1,
            attack_repeats=1,
            benign_loops=1,
            flood_count=100,
            flood_interval_usec=1000,
            collection_profile="balanced",
        )

        scenario_ids = self._scenario_ids(scenarios)
        self.assertIn("attack_port_scan_tcp_h3", scenario_ids)
        self.assertIn("attack_port_scan_udp_h3", scenario_ids)
        self.assertIn("attack_icmp_sweep_h3", scenario_ids)
        self.assertIn("attack_syn_flood_h1", scenario_ids)
        self.assertIn("attack_failed_connection_flood_h4", scenario_ids)
        self.assertNotIn("attack_port_scan_tcp_wide_h3", scenario_ids)
        self.assertNotIn("attack_host_scan_tcp_h3", scenario_ids)

    def test_scan_heavy_profile_adds_more_scan_coverage_without_removing_floods(self):
        balanced = build_scenarios(
            collection_id="test-balanced",
            benign_repeats=1,
            attack_repeats=1,
            benign_loops=1,
            flood_count=100,
            flood_interval_usec=1000,
            collection_profile="balanced",
        )
        scan_heavy = build_scenarios(
            collection_id="test-scan-heavy",
            benign_repeats=1,
            attack_repeats=1,
            benign_loops=1,
            flood_count=100,
            flood_interval_usec=1000,
            collection_profile="scan_heavy",
        )

        balanced_ids = self._scenario_ids(balanced)
        scan_heavy_ids = self._scenario_ids(scan_heavy)

        self.assertGreater(
            scan_heavy_ids.count("attack_port_scan_tcp_h3"),
            balanced_ids.count("attack_port_scan_tcp_h3"),
        )
        self.assertGreater(
            scan_heavy_ids.count("attack_port_scan_udp_h3"),
            balanced_ids.count("attack_port_scan_udp_h3"),
        )
        self.assertGreater(
            scan_heavy_ids.count("attack_icmp_sweep_h3"),
            balanced_ids.count("attack_icmp_sweep_h3"),
        )
        self.assertIn("attack_port_scan_tcp_wide_h3", scan_heavy_ids)
        self.assertIn("attack_host_scan_tcp_h3", scan_heavy_ids)
        self.assertIn("attack_syn_flood_h1", scan_heavy_ids)
        self.assertIn("attack_failed_connection_flood_h4", scan_heavy_ids)


if __name__ == "__main__":
    unittest.main()
