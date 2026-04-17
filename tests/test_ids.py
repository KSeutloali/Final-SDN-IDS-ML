"""Unit tests for threshold IDS behavior."""

import unittest

from security.ids import ThresholdIDS
from config.settings import IDSConfig


class PacketStub(object):
    def __init__(
        self,
        timestamp,
        src_ip,
        dst_ip="10.0.0.2",
        protocol="tcp",
        dst_port=80,
        src_port=12345,
        tcp_syn_only=False,
        tcp_rst=False,
        icmp_type=None,
    ):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.transport_protocol = protocol
        self.dst_port = dst_port
        self.src_port = src_port
        self.is_ipv4 = True
        self.tcp_syn_only = tcp_syn_only
        self.tcp_rst = tcp_rst
        self.is_icmp = protocol == "icmp"
        self.icmp_type = 8 if self.is_icmp and icmp_type is None else icmp_type


class ThresholdIDSTests(unittest.TestCase):
    def test_packet_rate_threshold(self):
        ids = ThresholdIDS(
            IDSConfig(
                packet_rate_threshold=3,
                packet_rate_window_seconds=5,
                alert_suppression_seconds=0,
            )
        )

        alerts = []
        for timestamp in (1.0, 2.0, 3.0):
            alerts = ids.inspect(PacketStub(timestamp=timestamp, src_ip="10.0.0.3"))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "packet_flood_detected")

    def test_port_scan_threshold(self):
        ids = ThresholdIDS(
            IDSConfig(
                packet_rate_threshold=1000,
                syn_rate_threshold=1000,
                unique_destination_ports_threshold=3,
                scan_window_seconds=10,
                alert_suppression_seconds=0,
            )
        )

        alerts = []
        for offset, dst_port in enumerate((22, 80, 443), start=1):
            alerts = ids.inspect(
                PacketStub(
                    timestamp=float(offset),
                    src_ip="10.0.0.9",
                    dst_port=dst_port,
                    tcp_syn_only=True,
                )
            )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "port_scan_detected")

    def test_failed_connection_threshold(self):
        ids = ThresholdIDS(
            IDSConfig(
                packet_rate_threshold=1000,
                syn_rate_threshold=1000,
                failed_connection_threshold=2,
                failed_connection_window_seconds=10,
                connection_attempt_window_seconds=10,
                alert_suppression_seconds=0,
            )
        )

        ids.inspect(
            PacketStub(
                timestamp=1.0,
                src_ip="10.0.0.3",
                dst_ip="10.0.0.2",
                src_port=12000,
                dst_port=22,
                tcp_syn_only=True,
            )
        )
        ids.inspect(
            PacketStub(
                timestamp=2.0,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.3",
                src_port=22,
                dst_port=12000,
                tcp_rst=True,
            )
        )
        ids.inspect(
            PacketStub(
                timestamp=3.0,
                src_ip="10.0.0.3",
                dst_ip="10.0.0.2",
                src_port=12001,
                dst_port=23,
                tcp_syn_only=True,
            )
        )
        alerts = ids.inspect(
            PacketStub(
                timestamp=4.0,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.3",
                src_port=23,
                dst_port=12001,
                tcp_rst=True,
            )
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "failed_connection_rate_exceeded")
        self.assertEqual(alerts[0].src_ip, "10.0.0.3")

    def test_probe_pattern_detects_sparse_tcp_scan(self):
        ids = ThresholdIDS(
            IDSConfig(
                packet_rate_threshold=1000,
                syn_rate_threshold=1000,
                unique_destination_ports_threshold=6,
                scan_window_seconds=10,
                alert_suppression_seconds=0,
            )
        )

        alerts = []
        for offset, dst_port in enumerate((21, 22, 23, 80), start=1):
            alerts = ids.inspect(
                PacketStub(
                    timestamp=float(offset),
                    src_ip="10.0.0.9",
                    dst_port=dst_port,
                    tcp_syn_only=True,
                )
            )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "port_scan_detected")
        self.assertEqual(alerts[0].reason, "tcp_scan_threshold_exceeded")

    def test_icmp_host_probe_pattern_detects_sweep(self):
        ids = ThresholdIDS(
            IDSConfig(
                packet_rate_threshold=1000,
                syn_rate_threshold=1000,
                unique_destination_hosts_threshold=4,
                scan_window_seconds=10,
                alert_suppression_seconds=0,
            )
        )

        alerts = []
        for offset, dst_ip in enumerate(
            ("10.0.0.1", "10.0.0.2", "10.0.0.4", "10.0.0.5"),
            start=1,
        ):
            alerts = ids.inspect(
                PacketStub(
                    timestamp=float(offset),
                    src_ip="10.0.0.3",
                    dst_ip=dst_ip,
                    protocol="icmp",
                )
            )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "host_scan_detected")
        self.assertEqual(alerts[0].reason, "icmp_sweep_threshold_exceeded")

    def test_udp_probe_detection_uses_udp_specific_thresholds(self):
        ids = ThresholdIDS(
            IDSConfig(
                packet_rate_threshold=1000,
                syn_rate_threshold=1000,
                unique_destination_ports_threshold=12,
                udp_scan_unique_destination_ports_threshold=3,
                udp_scan_probe_threshold=3,
                scan_window_seconds=10,
                alert_suppression_seconds=0,
            )
        )

        alerts = []
        for offset, dst_port in enumerate((53, 67, 161), start=1):
            alerts = ids.inspect(
                PacketStub(
                    timestamp=float(offset),
                    src_ip="10.0.0.9",
                    protocol="udp",
                    dst_port=dst_port,
                )
            )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "port_scan_detected")
        self.assertEqual(alerts[0].reason, "udp_scan_threshold_exceeded")

    def test_combined_recon_threshold_detects_multi_host_multi_port_pattern(self):
        ids = ThresholdIDS(
            IDSConfig(
                packet_rate_threshold=1000,
                syn_rate_threshold=1000,
                unique_destination_ports_threshold=12,
                unique_destination_hosts_threshold=6,
                tcp_scan_unique_destination_ports_threshold=10,
                combined_recon_unique_destination_hosts_threshold=3,
                combined_recon_unique_destination_ports_threshold=3,
                combined_recon_probe_threshold=4,
                scan_window_seconds=10,
                alert_suppression_seconds=0,
            )
        )

        alerts = []
        probes = (
            ("10.0.0.2", 22),
            ("10.0.0.2", 23),
            ("10.0.0.3", 80),
            ("10.0.0.4", 443),
        )
        for offset, (dst_ip, dst_port) in enumerate(probes, start=1):
            alerts = ids.inspect(
                PacketStub(
                    timestamp=float(offset),
                    src_ip="10.0.0.9",
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    tcp_syn_only=True,
                )
            )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "port_scan_detected")
        self.assertEqual(alerts[0].reason, "combined_recon_threshold_exceeded")

    def test_source_context_exports_recent_threshold_state(self):
        ids = ThresholdIDS(
            IDSConfig(
                packet_rate_threshold=1000,
                syn_rate_threshold=1000,
                tcp_scan_unique_destination_ports_threshold=4,
                tcp_scan_probe_threshold=4,
                unanswered_syn_threshold=3,
                alert_suppression_seconds=0,
            )
        )

        packet = None
        alerts = []
        for offset, dst_port in enumerate((21, 22, 23, 24), start=1):
            packet = PacketStub(
                timestamp=float(offset),
                src_ip="10.0.0.9",
                dst_port=dst_port,
                tcp_syn_only=True,
            )
            alerts = ids.inspect(packet)

        context = ids.describe_source(
            packet,
            alerts=alerts,
            forwarding_visibility="tcp_syn_probe",
        )

        self.assertTrue(context["threshold_triggered"])
        self.assertEqual(context["threshold_rule_family"], "recon")
        self.assertGreaterEqual(context["scan_unique_destination_ports"], 4)
        self.assertTrue(context["recon_visible_traffic"])

    def test_unanswered_syn_detection_triggers_after_timeout(self):
        ids = ThresholdIDS(
            IDSConfig(
                packet_rate_threshold=1000,
                syn_rate_threshold=1000,
                unanswered_syn_threshold=3,
                unanswered_syn_timeout_seconds=1.0,
                unanswered_syn_window_seconds=10,
                alert_suppression_seconds=0,
            )
        )

        for offset, dst_port in enumerate((22, 23, 80), start=1):
            ids.inspect(
                PacketStub(
                    timestamp=float(offset),
                    src_ip="10.0.0.9",
                    dst_ip="10.0.0.2",
                    src_port=20000 + offset,
                    dst_port=dst_port,
                    tcp_syn_only=True,
                )
            )

        alerts = ids.inspect(
            PacketStub(
                timestamp=5.0,
                src_ip="10.0.0.10",
                protocol="icmp",
                dst_ip="10.0.0.2",
            )
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "port_scan_detected")
        self.assertEqual(alerts[0].reason, "unanswered_syn_threshold_exceeded")

    def test_answered_syns_do_not_count_as_unanswered(self):
        ids = ThresholdIDS(
            IDSConfig(
                packet_rate_threshold=1000,
                syn_rate_threshold=1000,
                unanswered_syn_threshold=2,
                unanswered_syn_timeout_seconds=1.0,
                unanswered_syn_window_seconds=10,
                alert_suppression_seconds=0,
            )
        )

        ids.inspect(
            PacketStub(
                timestamp=1.0,
                src_ip="10.0.0.9",
                dst_ip="10.0.0.2",
                src_port=12000,
                dst_port=80,
                tcp_syn_only=True,
            )
        )
        ids.inspect(
            PacketStub(
                timestamp=1.3,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.9",
                src_port=80,
                dst_port=12000,
                tcp_syn_only=False,
            )
        )

        alerts = ids.inspect(
            PacketStub(
                timestamp=3.0,
                src_ip="10.0.0.10",
                protocol="icmp",
                dst_ip="10.0.0.2",
            )
        )

        self.assertEqual(alerts, [])

    def test_tcp_responses_do_not_trigger_port_scan(self):
        ids = ThresholdIDS(
            IDSConfig(
                packet_rate_threshold=1000,
                syn_rate_threshold=1000,
                unique_destination_ports_threshold=3,
                scan_window_seconds=10,
                alert_suppression_seconds=0,
            )
        )

        alerts = []
        for offset, dst_port in enumerate((40001, 40002, 40003), start=1):
            alerts = ids.inspect(
                PacketStub(
                    timestamp=float(offset),
                    src_ip="10.0.0.2",
                    dst_ip="10.0.0.1",
                    src_port=80,
                    dst_port=dst_port,
                    tcp_syn_only=False,
                )
            )

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
