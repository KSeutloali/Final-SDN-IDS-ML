"""Tests for runtime ML feature extraction."""

from types import SimpleNamespace
import unittest

from ml.feature_extractor import LiveFeatureExtractor


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

    def test_reverse_tcp_response_clears_pending_syn(self):
        extractor = LiveFeatureExtractor(self._config())

        extractor.observe(self._packet(timestamp=1.0, dst_port=80, src_port=41000))
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

        self.assertEqual(snapshot.feature_values["unanswered_syn_rate"], 0.0)
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


if __name__ == "__main__":
    unittest.main()
