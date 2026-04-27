"""Tests for runtime dataset collection scenario planning."""

import unittest

from scripts.collect_runtime_dataset import (
    benign_bursty_command,
    benign_dual_service_command,
    benign_http_command,
    benign_mixed_command,
    build_scenarios,
    parse_args,
)


class CollectRuntimeDatasetScenarioTests(unittest.TestCase):
    def _scenario_ids(self, scenarios):
        return [scenario.scenario_id for scenario in scenarios]

    def _scenario_families(self, scenarios):
        return [scenario.scenario_family for scenario in scenarios]

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
        self.assertIn("benign_http_long_interval_h1", scenario_ids)
        self.assertIn("benign_bursty_h1", scenario_ids)

    def test_benign_helpers_invoke_script_through_shell(self):
        commands = (
            benign_http_command("10.0.0.2", 80, 1, 0.5),
            benign_mixed_command("10.0.0.2", 80, ("10.0.0.2", "10.0.0.5"), 1, 0.2, 0.5),
            benign_dual_service_command("10.0.0.2", 80, "10.0.0.5", 8080, 1, 0.5),
            benign_bursty_command("10.0.0.2", 80, "10.0.0.5", 8080, 2, 1, 0.1, 0.5),
        )

        for command in commands:
            self.assertIn(
                "sh /workspace/ryu-apps/traffic/benign_traffic.sh",
                command,
            )

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
        self.assertIn("attack_icmp_sweep_h1", scan_heavy_ids)
        self.assertIn("attack_syn_flood_h1", scan_heavy_ids)
        self.assertIn("attack_failed_connection_flood_h4", scan_heavy_ids)
        self.assertIn("attack_tcp_scan_stealth_h3", scan_heavy_ids)
        self.assertIn("attack_host_scan_stealth_h3", scan_heavy_ids)
        self.assertIn("attack_blended_stealth_scan_h1", scan_heavy_ids)
        self.assertIn("attack_periodic_beacon_h1", scan_heavy_ids)
        self.assertIn("attack_syn_abuse_below_threshold_h4", scan_heavy_ids)
        self.assertIn("attack_lateral_movement_h3", scan_heavy_ids)
        self.assertNotIn("attack_tcp_scan_stealth_h3", balanced_ids)

    def test_balanced_profile_covers_benign_and_malicious_families(self):
        scenarios = build_scenarios(
            collection_id="test-balanced",
            benign_repeats=1,
            attack_repeats=1,
            benign_loops=1,
            flood_count=100,
            flood_interval_usec=1000,
            collection_profile="balanced",
        )

        families = set(self._scenario_families(scenarios))
        self.assertIn("benign_http_repeated", families)
        self.assertIn("benign_mixed_icmp_http", families)
        self.assertIn("benign_multi_service", families)
        self.assertIn("benign_long_interval", families)
        self.assertIn("benign_bursty_legitimate", families)
        self.assertIn("tcp_port_scan", families)
        self.assertIn("udp_port_scan", families)
        self.assertIn("icmp_sweep", families)
        self.assertIn("syn_flood_open_port", families)
        self.assertIn("syn_flood_failed_connection", families)

    def test_benign_heavy_profile_focuses_on_diverse_benign_families(self):
        scenarios = build_scenarios(
            collection_id="test-benign-heavy",
            benign_repeats=1,
            attack_repeats=1,
            benign_loops=1,
            flood_count=100,
            flood_interval_usec=1000,
            collection_profile="benign_heavy",
            benign_concurrency=3,
            benign_jitter_seconds=0.5,
            random_seed=7,
        )

        scenario_ids = self._scenario_ids(scenarios)
        families = set(self._scenario_families(scenarios))
        labels = {scenario.label for scenario in scenarios}

        self.assertEqual(labels, {"benign"})
        self.assertIn("benign_bulk_transfer_h1", scenario_ids)
        self.assertIn("benign_backup_burst_h4", scenario_ids)
        self.assertIn("benign_admin_session_h1", scenario_ids)
        self.assertIn("benign_browser_mix_h1", scenario_ids)
        self.assertIn("benign_dns_then_http_h3", scenario_ids)
        self.assertIn("benign_chat_keepalive_h4", scenario_ids)
        self.assertIn("benign_udp_rr_h4", scenario_ids)
        self.assertIn("benign_peer_sync_h3", scenario_ids)
        self.assertIn("benign_browser_like_multi_fetch", families)
        self.assertIn("benign_dns_then_service_access", families)
        self.assertIn("benign_chat_keepalive", families)
        self.assertIn("benign_service_checks", families)
        self.assertIn("benign_bulk_transfer", families)
        self.assertIn("benign_backup_burst", families)
        self.assertIn("benign_admin_session", families)
        self.assertIn("benign_udp_request_response", families)
        self.assertIn("benign_peer_sync", families)

    def test_scan_heavy_profile_tags_layered_evaluation_metadata(self):
        scenarios = build_scenarios(
            collection_id="test-scan-heavy",
            benign_repeats=1,
            attack_repeats=1,
            benign_loops=1,
            flood_count=100,
            flood_interval_usec=1000,
            collection_profile="scan_heavy",
            benign_concurrency=2,
            benign_jitter_seconds=0.25,
            random_seed=13,
        )

        stealth_scan = next(
            scenario for scenario in scenarios if scenario.scenario_id == "attack_tcp_scan_stealth_h3"
        )
        blended_scan = next(
            scenario
            for scenario in scenarios
            if scenario.scenario_id == "attack_blended_stealth_scan_h1"
        )
        beacon = next(
            scenario for scenario in scenarios if scenario.scenario_id == "attack_periodic_beacon_h1"
        )
        lateral = next(
            scenario for scenario in scenarios if scenario.scenario_id == "attack_lateral_movement_h3"
        )

        self.assertEqual(stealth_scan.expected_detection_target, "classifier")
        self.assertTrue(stealth_scan.threshold_evasive)
        self.assertTrue(stealth_scan.known_family)
        self.assertFalse(stealth_scan.blended_with_benign)

        self.assertEqual(blended_scan.expected_detection_target, "hybrid")
        self.assertTrue(blended_scan.threshold_evasive)
        self.assertTrue(blended_scan.known_family)
        self.assertTrue(blended_scan.blended_with_benign)

        self.assertEqual(beacon.expected_detection_target, "anomaly")
        self.assertTrue(beacon.threshold_evasive)
        self.assertFalse(beacon.known_family)
        self.assertGreater(len(beacon.setup_actions), 0)
        self.assertGreater(len(beacon.cleanup_actions), 0)

        self.assertEqual(lateral.expected_detection_target, "anomaly")
        self.assertTrue(lateral.threshold_evasive)
        self.assertFalse(lateral.known_family)
        self.assertGreaterEqual(len(lateral.setup_actions), 2)
        self.assertGreaterEqual(len(lateral.cleanup_actions), 2)

    def test_benign_heavy_temp_service_scenarios_define_cleanup_actions(self):
        scenarios = build_scenarios(
            collection_id="test-benign-heavy",
            benign_repeats=1,
            attack_repeats=0,
            benign_loops=1,
            flood_count=100,
            flood_interval_usec=1000,
            collection_profile="benign_heavy",
            benign_concurrency=2,
            benign_jitter_seconds=0.25,
            random_seed=11,
        )

        admin_scenario = next(
            scenario for scenario in scenarios if scenario.scenario_id == "benign_admin_session_h1"
        )
        dns_scenario = next(
            scenario for scenario in scenarios if scenario.scenario_id == "benign_dns_then_http_h3"
        )
        chat_scenario = next(
            scenario for scenario in scenarios if scenario.scenario_id == "benign_chat_keepalive_h4"
        )
        udp_scenario = next(
            scenario for scenario in scenarios if scenario.scenario_id == "benign_udp_rr_h4"
        )

        self.assertGreater(len(admin_scenario.setup_actions), 0)
        self.assertGreater(len(admin_scenario.cleanup_actions), 0)
        self.assertIn("pkill", admin_scenario.cleanup_actions[0].command)
        self.assertGreater(len(dns_scenario.setup_actions), 0)
        self.assertGreater(len(dns_scenario.cleanup_actions), 0)
        self.assertIn("pkill", dns_scenario.cleanup_actions[0].command)
        self.assertGreater(len(chat_scenario.setup_actions), 0)
        self.assertGreater(len(chat_scenario.cleanup_actions), 0)
        self.assertIn("pkill", chat_scenario.cleanup_actions[0].command)
        self.assertGreater(len(udp_scenario.setup_actions), 0)
        self.assertGreater(len(udp_scenario.cleanup_actions), 0)
        self.assertIn("pkill", udp_scenario.cleanup_actions[0].command)

    def test_benign_heavy_legacy_bursty_scenario_is_bounded(self):
        scenarios = build_scenarios(
            collection_id="test-benign-heavy",
            benign_repeats=1,
            attack_repeats=0,
            benign_loops=1,
            flood_count=100,
            flood_interval_usec=1000,
            collection_profile="benign_heavy",
            benign_concurrency=3,
            benign_jitter_seconds=0.5,
            random_seed=5,
        )

        bursty = next(
            scenario for scenario in scenarios if scenario.scenario_id == "benign_bursty_h1"
        )

        self.assertIn("burst_size=3", bursty.rate_parameter)
        self.assertIn("pause=8.0s", bursty.rate_parameter)

    def test_parse_args_accepts_benign_heavy_controls(self):
        args = parse_args(
            [
                "--collection-profile",
                "benign_heavy",
                "--benign-concurrency",
                "4",
                "--benign-jitter-seconds",
                "0.75",
                "--random-seed",
                "99",
            ]
        )

        self.assertEqual(args.collection_profile, "benign_heavy")
        self.assertEqual(args.benign_concurrency, 4)
        self.assertAlmostEqual(args.benign_jitter_seconds, 0.75)
        self.assertEqual(args.random_seed, 99)


if __name__ == "__main__":
    unittest.main()
