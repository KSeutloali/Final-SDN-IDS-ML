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
