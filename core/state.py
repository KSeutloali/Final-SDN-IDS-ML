"""Shared in-memory controller state."""

import time
from dataclasses import dataclass, field
from typing import Dict


def format_dpid(dpid):
    return format(dpid, "016x")


@dataclass
class BlockRecord:
    src_ip: str
    reason: str
    expires_at: float
    created_at: float = field(default_factory=time.time)


@dataclass
class ControllerState:
    datapaths: Dict[int, object] = field(default_factory=dict)
    mac_to_port: Dict[str, Dict[str, int]] = field(default_factory=dict)
    blocked_sources: Dict[str, BlockRecord] = field(default_factory=dict)

    def remember_datapath(self, datapath):
        self.datapaths[datapath.id] = datapath

    def forget_datapath(self, datapath_id):
        self.datapaths.pop(datapath_id, None)
        self.mac_to_port.pop(format_dpid(datapath_id), None)

    def iter_datapaths(self):
        return list(self.datapaths.values())

    def learn_mac(self, dpid, mac_address, port):
        self.mac_to_port.setdefault(dpid, {})[mac_address] = port

    def lookup_port(self, dpid, mac_address):
        return self.mac_to_port.get(dpid, {}).get(mac_address)

    def upsert_block(self, src_ip, reason, expires_at):
        record = self.blocked_sources.get(src_ip)
        if record is None:
            record = BlockRecord(src_ip=src_ip, reason=reason, expires_at=expires_at)
            self.blocked_sources[src_ip] = record
            return record, "created"

        if expires_at > record.expires_at:
            record.reason = reason
            record.expires_at = expires_at
            return record, "extended"

        return record, "unchanged"

    def is_blocked(self, src_ip, now):
        record = self.blocked_sources.get(src_ip)
        return bool(record and record.expires_at > now)

    def active_block_records(self, now):
        return [
            record
            for record in self.blocked_sources.values()
            if record.expires_at > now
        ]

    def expire_blocks(self, now):
        expired = []
        for src_ip, record in list(self.blocked_sources.items()):
            if record.expires_at <= now:
                expired.append(record)
                del self.blocked_sources[src_ip]
        return expired
