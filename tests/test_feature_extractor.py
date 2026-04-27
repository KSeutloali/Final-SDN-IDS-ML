"""Tests for runtime ML feature extraction."""

from types import SimpleNamespace
import unittest

from ml.feature_extractor import LiveFeatureExtractor, RUNTIME_FEATURE_NAMES


class LiveFeatureExtractorTests(unittest.TestCase):
    def _config(self, **overrides):
        defaults = {
            "feature_window_seconds": 10,
            "unanswered_syn_timeout_seconds": 1.0,
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def _packet(self, **overrides):
        defaults = {
            "timestamp": 1.0,
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.2",
            "transport_protocol": "tcp",
            "ip_proto": 6,
            "dst_port": 80,
            "src_port": 42424,
            "packet_length": 96,
            "is_ipv4": True,
            "tcp_syn_only": True,
            "tcp_rst": False,
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_pending_syns_raise_unanswered_syn_rate_immediately(self):
        extractor = LiveFeatureExtractor(self._config())

        extractor.observe(self._packet(timestamp=1.0, dst_port=1, src_port=40001))
        extractor.observe(self._packet(timestamp=1.1, dst_port=2, src_port=40002))
        snapshot = extractor.observe(self._packet(timestamp=1.2, dst_port=3, src_port=40003))

        self.assertGreater(snapshot.feature_values["unanswered_syn_rate"], 0.0)
        self.assertGreater(snapshot.feature_values["unanswered_syn_ratio"], 0.0)
        self.assertGreater(snapshot.feature_values["destination_port_fanout_ratio"], 0.9)

    def test_reverse_tcp_response_clears_pending_syn_without_emitting_responder_snapshot(self):
        extractor = LiveFeatureExtractor(self._config())

        first_snapshot = extractor.observe(
            self._packet(timestamp=1.0, dst_port=80, src_port=41000)
        )
        reply = self._packet(
            timestamp=1.2,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            src_port=80,
            dst_port=41000,
            tcp_syn_only=False,
            tcp_rst=False,
        )
        snapshot = extractor.observe(reply)

        self.assertIsNone(snapshot)
        self.assertIsNone(extractor.pending_attempt_counts.get("10.0.0.3"))
        self.assertEqual(first_snapshot.feature_values["unanswered_syn_rate"], 1.0)
        self.assertNotIn("10.0.0.2", extractor.host_windows)

    def test_retransmitted_tcp_response_is_suppressed_for_responder(self):
        extractor = LiveFeatureExtractor(self._config())

        extractor.observe(self._packet(timestamp=1.0, dst_port=80, src_port=41010))
        first_reply = self._packet(
            timestamp=1.2,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            src_port=80,
            dst_port=41010,
            tcp_syn_only=False,
            tcp_rst=False,
        )
        retransmitted_reply = self._packet(
            timestamp=2.2,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            src_port=80,
            dst_port=41010,
            tcp_syn_only=False,
            tcp_rst=False,
        )

        self.assertIsNone(extractor.observe(first_reply))
        self.assertIsNone(extractor.observe(retransmitted_reply))
        self.assertNotIn("10.0.0.2", extractor.host_windows)

    def test_rst_reply_counts_as_failed_connection_for_initiator_only(self):
        extractor = LiveFeatureExtractor(self._config())

        first_snapshot = extractor.observe(
            self._packet(timestamp=1.0, dst_port=81, src_port=41001)
        )
        rst_reply = self._packet(
            timestamp=1.2,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            src_port=81,
            dst_port=41001,
            tcp_syn_only=False,
            tcp_rst=True,
        )

        snapshot = extractor.observe(rst_reply)

        self.assertIsNone(snapshot)
        self.assertIsNone(extractor.pending_attempt_counts.get("10.0.0.3"))
        self.assertEqual(len(extractor.failed_windows["10.0.0.3"]), 1)
        self.assertEqual(first_snapshot.feature_values["unanswered_syn_rate"], 1.0)
        self.assertNotIn("10.0.0.2", extractor.host_windows)

    def test_unparsed_tcp_probe_reply_is_attributed_to_initiator_not_responder(self):
        extractor = LiveFeatureExtractor(self._config())

        fragmented_probe_snapshot = extractor.observe(
            self._packet(
                timestamp=1.0,
                transport_protocol="ipv4",
                src_port=None,
                dst_port=None,
                tcp_syn_only=False,
            )
        )
        reply = self._packet(
            timestamp=1.2,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            src_port=80,
            dst_port=42424,
            tcp_syn_only=False,
            tcp_rst=False,
        )

        snapshot = extractor.observe(reply)

        self.assertIsNone(snapshot)
        self.assertIsNotNone(fragmented_probe_snapshot)
        self.assertIsNone(extractor.pending_attempt_counts.get("10.0.0.3"))
        self.assertNotIn("10.0.0.2", extractor.host_windows)

    def test_unparsed_tcp_probe_rst_counts_as_failed_connection_for_initiator(self):
        extractor = LiveFeatureExtractor(self._config())

        extractor.observe(
            self._packet(
                timestamp=1.0,
                transport_protocol="ipv4",
                src_port=None,
                dst_port=None,
                tcp_syn_only=False,
            )
        )
        rst_reply = self._packet(
            timestamp=1.2,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            src_port=80,
            dst_port=42424,
            tcp_syn_only=False,
            tcp_rst=True,
        )

        snapshot = extractor.observe(rst_reply)

        self.assertIsNone(snapshot)
        self.assertIsNone(extractor.pending_attempt_counts.get("10.0.0.3"))
        self.assertEqual(len(extractor.failed_windows["10.0.0.3"]), 1)
        self.assertNotIn("10.0.0.2", extractor.host_windows)

    def test_repeated_unparsed_tcp_probe_replies_do_not_emit_responder_snapshots(self):
        extractor = LiveFeatureExtractor(self._config())

        extractor.observe(
            self._packet(
                timestamp=1.0,
                transport_protocol="ipv4",
                src_port=None,
                dst_port=None,
                tcp_syn_only=False,
            )
        )
        extractor.observe(
            self._packet(
                timestamp=1.1,
                transport_protocol="ipv4",
                src_port=None,
                dst_port=None,
                tcp_syn_only=False,
            )
        )

        first_reply = self._packet(
            timestamp=1.2,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            src_port=80,
            dst_port=42424,
            tcp_syn_only=False,
            tcp_rst=False,
        )
        second_reply = self._packet(
            timestamp=1.3,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            src_port=443,
            dst_port=42424,
            tcp_syn_only=False,
            tcp_rst=False,
        )

        self.assertIsNone(extractor.observe(first_reply))
        self.assertIsNone(extractor.observe(second_reply))
        self.assertIsNone(extractor.pending_attempt_counts.get("10.0.0.3"))
        self.assertNotIn("10.0.0.2", extractor.host_windows)

    def test_recent_probe_pair_suppresses_unmatched_responder_reply(self):
        extractor = LiveFeatureExtractor(self._config())

        extractor.observe(
            self._packet(
                timestamp=1.0,
                transport_protocol="ipv4",
                src_port=None,
                dst_port=None,
                tcp_syn_only=False,
                is_fragmented_tcp_probe=True,
            )
        )
        matched_reply = self._packet(
            timestamp=1.2,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            src_port=80,
            dst_port=42424,
            tcp_syn_only=False,
            tcp_rst=False,
        )
        unmatched_reply = self._packet(
            timestamp=2.0,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            src_port=443,
            dst_port=42424,
            tcp_syn_only=False,
            tcp_rst=False,
        )

        self.assertIsNone(extractor.observe(matched_reply))
        self.assertIsNone(extractor.observe(unmatched_reply))
        self.assertNotIn("10.0.0.2", extractor.host_windows)

    def test_parsed_fragmented_tcp_probe_with_ports_still_suppresses_responder(self):
        extractor = LiveFeatureExtractor(self._config())

        fragmented_probe_snapshot = extractor.observe(
            self._packet(
                timestamp=1.0,
                transport_protocol="tcp",
                src_port=43000,
                dst_port=80,
                tcp_syn_only=False,
                tcp_rst=False,
                ip_flags=1,
                ip_fragment_offset=0,
                is_fragmented_tcp_probe=True,
            )
        )
        reply = self._packet(
            timestamp=1.2,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            src_port=80,
            dst_port=43000,
            tcp_syn_only=False,
            tcp_rst=False,
        )

        snapshot = extractor.observe(reply)

        self.assertIsNotNone(fragmented_probe_snapshot)
        self.assertIsNone(snapshot)
        self.assertIsNone(extractor.pending_attempt_counts.get("10.0.0.3"))
        self.assertNotIn("10.0.0.2", extractor.host_windows)

    def test_non_initial_tcp_fragment_does_not_count_as_connection_attempt(self):
        extractor = LiveFeatureExtractor(self._config())

        snapshot = extractor.observe(
            self._packet(
                timestamp=1.0,
                transport_protocol="ipv4",
                src_port=None,
                dst_port=None,
                tcp_syn_only=False,
                ip_fragment_offset=1,
                ip_flags=0,
            )
        )

        self.assertIsNotNone(snapshot)
        self.assertIsNone(extractor.pending_attempt_counts.get("10.0.0.3"))

    def test_expired_syn_attempts_become_unanswered_history(self):
        extractor = LiveFeatureExtractor(self._config(unanswered_syn_timeout_seconds=0.5))

        extractor.observe(self._packet(timestamp=1.0, dst_port=21, src_port=42001))
        snapshot = extractor.observe(self._packet(timestamp=1.7, dst_port=22, src_port=42002))

        self.assertGreaterEqual(snapshot.feature_values["unanswered_syn_rate"], 1.0)
        self.assertGreater(len(extractor.unanswered_windows["10.0.0.3"]), 0)

    def test_extended_recon_features_include_counts_and_trend_deltas(self):
        extractor = LiveFeatureExtractor(self._config())

        extractor.observe(self._packet(timestamp=1.0, dst_port=80, src_port=43001))
        extractor.observe(self._packet(timestamp=1.2, dst_port=81, src_port=43002))
        snapshot = extractor.observe(
            self._packet(
                timestamp=1.4,
                dst_ip="10.0.0.4",
                dst_port=82,
                src_port=43003,
            )
        )

        self.assertIn("unanswered_syn_count", snapshot.feature_values)
        self.assertIn("recon_probe_density", snapshot.feature_values)
        self.assertIn("packet_rate_delta", snapshot.feature_values)
        self.assertIn("unique_destination_ports_delta", snapshot.feature_values)
        self.assertGreater(snapshot.feature_values["unanswered_syn_count"], 0.0)
        self.assertGreater(snapshot.feature_values["recon_probe_density"], 0.0)
        self.assertNotEqual(snapshot.feature_values["packet_rate_delta"], 0.0)
        self.assertNotEqual(snapshot.feature_values["unique_destination_ports_delta"], 0.0)

    def test_existing_runtime_feature_schema_remains_backward_compatible(self):
        extractor = LiveFeatureExtractor(self._config())

        snapshot = extractor.observe(self._packet(timestamp=1.0))

        self.assertEqual(snapshot.sample_count, 1)
        for feature_name in RUNTIME_FEATURE_NAMES:
            self.assertIn(feature_name, snapshot.feature_values)
        self.assertEqual(
            len(snapshot.to_vector(RUNTIME_FEATURE_NAMES)),
            len(RUNTIME_FEATURE_NAMES),
        )
        self.assertIn("inter_arrival_mean_short", snapshot.feature_values)
        self.assertIn("destination_ip_entropy_short", snapshot.feature_values)
        self.assertIn("packet_rate_trend", snapshot.feature_values)

    def test_new_features_have_stable_sparse_defaults(self):
        extractor = LiveFeatureExtractor(self._config())

        snapshot = extractor.observe(self._packet(timestamp=1.0, dst_port=80, src_port=44001))

        self.assertEqual(snapshot.feature_values["inter_arrival_mean_short"], 0.0)
        self.assertEqual(snapshot.feature_values["inter_arrival_std_short"], 0.0)
        self.assertEqual(snapshot.feature_values["burstiness_short"], 0.0)
        self.assertEqual(snapshot.feature_values["destination_ip_entropy_short"], 0.0)
        self.assertEqual(snapshot.feature_values["destination_port_entropy_short"], 0.0)
        self.assertEqual(snapshot.feature_values["protocol_entropy_short"], 0.0)
        self.assertEqual(snapshot.feature_values["packet_size_std_short"], 0.0)
        self.assertEqual(snapshot.feature_values["packet_rate_trend"], 0.0)
        self.assertEqual(snapshot.feature_values["unanswered_syn_ratio_trend"], 0.0)
        self.assertGreaterEqual(
            snapshot.feature_values["host_packet_rate_baseline_ratio"],
            1.0,
        )

    def test_entropy_and_interarrival_features_follow_synthetic_traffic(self):
        extractor = LiveFeatureExtractor(self._config())

        extractor.observe(
            self._packet(
                timestamp=1.0,
                dst_ip="10.0.0.2",
                dst_port=80,
                src_port=45001,
                packet_length=100,
                transport_protocol="tcp",
                tcp_syn_only=True,
            )
        )
        extractor.observe(
            self._packet(
                timestamp=2.0,
                dst_ip="10.0.0.3",
                dst_port=53,
                src_port=45002,
                packet_length=140,
                transport_protocol="udp",
                tcp_syn_only=False,
            )
        )
        snapshot = extractor.observe(
            self._packet(
                timestamp=4.0,
                dst_ip="10.0.0.4",
                dst_port=None,
                src_port=None,
                packet_length=180,
                transport_protocol="icmp",
                tcp_syn_only=False,
            )
        )

        self.assertGreater(snapshot.feature_values["inter_arrival_mean_short"], 0.0)
        self.assertGreater(snapshot.feature_values["inter_arrival_std_short"], 0.0)
        self.assertNotEqual(snapshot.feature_values["burstiness_short"], 0.0)
        self.assertGreater(snapshot.feature_values["destination_ip_entropy_short"], 0.0)
        self.assertGreater(snapshot.feature_values["destination_port_entropy_short"], 0.0)
        self.assertGreater(snapshot.feature_values["protocol_entropy_short"], 0.0)
        self.assertGreater(snapshot.feature_values["packet_size_std_short"], 0.0)

    def test_novelty_baseline_and_trend_features_capture_new_recon_behavior(self):
        extractor = LiveFeatureExtractor(self._config())

        extractor.observe(
            self._packet(
                timestamp=1.0,
                dst_ip="10.0.0.2",
                dst_port=80,
                src_port=46001,
            )
        )
        extractor.observe(
            self._packet(
                timestamp=20.0,
                dst_ip="10.0.0.2",
                dst_port=80,
                src_port=46002,
            )
        )
        extractor.observe(
            self._packet(
                timestamp=22.0,
                dst_ip="10.0.0.3",
                dst_port=81,
                src_port=46003,
            )
        )
        snapshot = extractor.observe(
            self._packet(
                timestamp=24.0,
                dst_ip="10.0.0.4",
                dst_port=82,
                src_port=46004,
            )
        )

        self.assertGreater(snapshot.feature_values["new_destination_ip_ratio_short"], 0.0)
        self.assertGreater(snapshot.feature_values["new_destination_port_ratio_short"], 0.0)
        self.assertGreater(snapshot.feature_values["host_unique_dest_ip_baseline_ratio"], 1.0)
        self.assertGreater(snapshot.feature_values["host_unique_dest_port_baseline_ratio"], 1.0)
        self.assertGreater(snapshot.feature_values["packet_rate_trend"], 0.0)
        self.assertGreater(snapshot.feature_values["unique_destination_port_trend"], 0.0)


if __name__ == "__main__":
    unittest.main()
