"""Tests for controller forwarding visibility rules."""

import unittest
from types import SimpleNamespace

from config.settings import IDSConfig
from controller.forwarding_policy import should_install_forward_flow


def packet_stub(**overrides):
    defaults = {
        "is_ipv4": True,
        "transport_protocol": "tcp",
        "tcp_syn_only": False,
        "is_icmp": False,
        "icmp_type": None,
        "src_port": 12345,
        "dst_port": 80,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class ForwardingPolicyTests(unittest.TestCase):
    def test_tcp_syn_only_packets_stay_controller_visible(self):
        self.assertFalse(
            should_install_forward_flow(
                IDSConfig(),
                packet_stub(transport_protocol="tcp", tcp_syn_only=True),
            )
        )

    def test_established_tcp_packets_can_be_fast_pathed(self):
        self.assertTrue(
            should_install_forward_flow(
                IDSConfig(),
                packet_stub(transport_protocol="tcp", tcp_syn_only=False),
            )
        )

    def test_udp_probe_packets_stay_controller_visible(self):
        self.assertFalse(
            should_install_forward_flow(
                IDSConfig(),
                packet_stub(transport_protocol="udp", dst_port=161),
            )
        )

    def test_configured_udp_service_ports_can_be_fast_pathed(self):
        ids_config = IDSConfig(udp_fastpath_ports=(53,))
        self.assertTrue(
            should_install_forward_flow(
                ids_config,
                packet_stub(transport_protocol="udp", dst_port=53),
            )
        )

    def test_icmp_echo_requests_stay_controller_visible(self):
        self.assertFalse(
            should_install_forward_flow(
                IDSConfig(),
                packet_stub(
                    transport_protocol="icmp",
                    is_icmp=True,
                    icmp_type=8,
                ),
            )
        )

    def test_icmp_non_probe_packets_can_be_fast_pathed(self):
        self.assertTrue(
            should_install_forward_flow(
                IDSConfig(),
                packet_stub(
                    transport_protocol="icmp",
                    is_icmp=True,
                    icmp_type=0,
                ),
            )
        )


if __name__ == "__main__":
    unittest.main()
