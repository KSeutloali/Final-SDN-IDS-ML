"""Tests for controller event/state helpers."""

import unittest
from types import SimpleNamespace

from controller.events import (
    ControllerState,
    HostRecord,
    clear_runtime_topology_state,
    learn_host,
    unregister_datapath,
)


class ControllerEventsTests(unittest.TestCase):
    def test_unregister_datapath_removes_hosts_for_that_switch(self):
        state = ControllerState()
        state.datapaths = {1: object(), 2: object()}
        state.mac_to_port = {
            "0000000000000001": {"00:00:00:00:00:01": 1},
            "0000000000000002": {"00:00:00:00:00:02": 2},
        }
        state.hosts = {
            "00:00:00:00:00:01": HostRecord(
                mac_address="00:00:00:00:00:01",
                switch_id="0000000000000001",
                port_no=1,
                ip_address="10.0.0.1",
            ),
            "00:00:00:00:00:02": HostRecord(
                mac_address="00:00:00:00:00:02",
                switch_id="0000000000000002",
                port_no=2,
                ip_address="10.0.0.2",
            ),
        }

        unregister_datapath(state, 1)

        self.assertNotIn(1, state.datapaths)
        self.assertNotIn("0000000000000001", state.mac_to_port)
        self.assertNotIn("00:00:00:00:00:01", state.hosts)
        self.assertIn("00:00:00:00:00:02", state.hosts)

    def test_clear_runtime_topology_state_clears_hosts_and_mac_learning(self):
        state = ControllerState()
        state.mac_to_port = {"0000000000000001": {"00:00:00:00:00:01": 1}}
        state.hosts = {
            "00:00:00:00:00:01": HostRecord(
                mac_address="00:00:00:00:00:01",
                switch_id="0000000000000001",
                port_no=1,
                ip_address="10.0.0.1",
            )
        }

        clear_runtime_topology_state(state)

        self.assertEqual(state.mac_to_port, {})
        self.assertEqual(state.hosts, {})

    def test_learn_host_tracks_inventory_only_on_host_access_ports(self):
        state = ControllerState()
        packet_metadata = SimpleNamespace(
            dpid="0000000000000001",
            in_port=3,
            eth_src="00:00:00:00:00:01",
            src_ip="10.0.0.1",
            timestamp=123.0,
        )

        record = learn_host(state, packet_metadata)

        self.assertIsNone(record)
        self.assertEqual(state.mac_to_port["0000000000000001"]["00:00:00:00:00:01"], 3)
        self.assertEqual(state.hosts, {})

    def test_learn_host_records_inventory_on_host_access_port(self):
        state = ControllerState()
        packet_metadata = SimpleNamespace(
            dpid="0000000000000001",
            in_port=1,
            eth_src="00:00:00:00:00:01",
            src_ip="10.0.0.1",
            timestamp=123.0,
        )

        record = learn_host(state, packet_metadata)

        self.assertIsNotNone(record)
        self.assertEqual(record.switch_id, "0000000000000001")
        self.assertEqual(record.port_no, 1)
        self.assertEqual(record.ip_address, "10.0.0.1")
        self.assertIn("00:00:00:00:00:01", state.hosts)

    def test_learn_host_does_not_move_existing_inventory_record_to_trunk_port(self):
        state = ControllerState()
        edge_packet = SimpleNamespace(
            dpid="0000000000000001",
            in_port=1,
            eth_src="00:00:00:00:00:01",
            src_ip="10.0.0.1",
            timestamp=123.0,
        )
        trunk_packet = SimpleNamespace(
            dpid="0000000000000003",
            in_port=1,
            eth_src="00:00:00:00:00:01",
            src_ip="10.0.0.1",
            timestamp=124.0,
        )

        learn_host(state, edge_packet)
        record = learn_host(state, trunk_packet)

        self.assertIsNone(record)
        learned = state.hosts["00:00:00:00:00:01"]
        self.assertEqual(learned.switch_id, "0000000000000001")
        self.assertEqual(learned.port_no, 1)
        self.assertEqual(state.mac_to_port["0000000000000003"]["00:00:00:00:00:01"], 1)


if __name__ == "__main__":
    unittest.main()
