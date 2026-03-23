"""Event and state helpers for the firewall controller."""

import time
from dataclasses import dataclass, field
from typing import Dict

HOST_ACCESS_PORTS_BY_SWITCH = {
    "0000000000000001": frozenset((1, 2)),
    "0000000000000002": frozenset((2,)),
    "0000000000000003": frozenset((2, 3)),
}


def format_dpid(dpid):
    if dpid is None:
        return "unknown"
    return format(dpid, "016x")


@dataclass
class HostRecord:
    mac_address: str
    switch_id: str
    port_no: int
    ip_address: str = None
    last_seen: float = field(default_factory=time.time)


@dataclass
class ControllerState:
    datapaths: Dict[int, object] = field(default_factory=dict)
    mac_to_port: Dict[str, Dict[str, int]] = field(default_factory=dict)
    hosts: Dict[str, HostRecord] = field(default_factory=dict)

    def iter_datapaths(self):
        return list(self.datapaths.values())


def register_datapath(state, datapath):
    if datapath.id is None:
        return None
    state.datapaths[datapath.id] = datapath
    return format_dpid(datapath.id)


def unregister_datapath(state, datapath_id):
    switch_id = format_dpid(datapath_id)
    state.datapaths.pop(datapath_id, None)
    state.mac_to_port.pop(switch_id, None)
    for mac_address, record in list(state.hosts.items()):
        if record.switch_id == switch_id:
            del state.hosts[mac_address]


def learn_host(state, packet_metadata):
    switch_id = packet_metadata.dpid
    state.mac_to_port.setdefault(switch_id, {})[packet_metadata.eth_src] = packet_metadata.in_port

    if not _is_host_access_port(switch_id, packet_metadata.in_port):
        return None

    record = state.hosts.get(packet_metadata.eth_src)
    if record is None:
        record = HostRecord(
            mac_address=packet_metadata.eth_src,
            switch_id=switch_id,
            port_no=packet_metadata.in_port,
        )
        state.hosts[packet_metadata.eth_src] = record

    record.switch_id = switch_id
    record.port_no = packet_metadata.in_port
    record.last_seen = packet_metadata.timestamp
    if packet_metadata.src_ip:
        record.ip_address = packet_metadata.src_ip

    return record


def lookup_output_port(state, switch_id, destination_mac):
    return state.mac_to_port.get(switch_id, {}).get(destination_mac)


def clear_runtime_topology_state(state):
    state.mac_to_port.clear()
    state.hosts.clear()


def _is_host_access_port(switch_id, in_port):
    """Only count directly attached endpoints in the dashboard host inventory.

    MAC learning for forwarding still happens on every switch port. This filter is
    only for the higher-level "learned hosts" inventory so transit packets seen on
    inter-switch links do not create phantom hosts or move real hosts across the
    fabric in the UI.
    """

    allowed_ports = HOST_ACCESS_PORTS_BY_SWITCH.get(switch_id)
    if allowed_ports is None:
        return True
    return in_port in allowed_ports
