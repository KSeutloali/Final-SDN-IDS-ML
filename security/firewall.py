"""Firewall policy evaluation and quarantine rule installation helpers."""

import ipaddress
import time
from dataclasses import dataclass, field
from uuid import uuid4


@dataclass
class QuarantineRecord(object):
    src_ip: str
    reason: str
    block_id: str = field(default_factory=lambda: "blk_%s" % uuid4().hex[:12])
    created_at: float = field(default_factory=time.time)
    last_seen_at: float = field(default_factory=time.time)
    hit_count: int = 1
    expires_at: float = None
    detector: str = None
    latest_detector: str = None
    contributing_detectors: list = field(default_factory=list)
    alert_type: str = None
    related_capture: dict = field(default_factory=dict)
    related_captures: list = field(default_factory=list)
    released_at: float = None
    released_by: str = None


TemporaryBlock = QuarantineRecord


@dataclass
class FirewallDecision(object):
    action: str
    reason: str
    rule_kind: str = None


class FirewallPolicy(object):
    """Evaluate packet metadata against static and dynamic firewall policy."""

    def __init__(self, firewall_config, priority_config, timeout_config, flow_manager):
        self.firewall_config = firewall_config
        self.priority_config = priority_config
        self.timeout_config = timeout_config
        self.flow_manager = flow_manager
        self.quarantined_hosts = {}
        self.temporary_blocks = self.quarantined_hosts
        self.activated_source_blocks = set()
        self.activated_tcp_port_blocks = set()
        self.activated_udp_port_blocks = set()

    def install_baseline_rules(self, datapath):
        for src_ip in self.activated_source_blocks:
            self.flow_manager.install_source_block(
                datapath,
                src_ip,
                priority=self.priority_config.static_source_block,
                reason="static_source_block",
            )

        for tcp_port in self.activated_tcp_port_blocks:
            self.flow_manager.install_service_port_block(
                datapath,
                protocol="tcp",
                port_number=tcp_port,
                priority=self.priority_config.restricted_service_block,
                reason="restricted_tcp_port_%s" % tcp_port,
            )

        for udp_port in self.activated_udp_port_blocks:
            self.flow_manager.install_service_port_block(
                datapath,
                protocol="udp",
                port_number=udp_port,
                priority=self.priority_config.restricted_service_block,
                reason="restricted_udp_port_%s" % udp_port,
            )

        for record in self.quarantined_hosts.values():
            self.flow_manager.install_source_block(
                datapath,
                record.src_ip,
                priority=self.priority_config.temporary_source_block,
                hard_timeout=0,
                reason=record.reason,
            )

    def evaluate(self, packet_metadata):
        if packet_metadata.src_ip and self._quarantine_for(packet_metadata.src_ip):
            return FirewallDecision(
                action="block",
                reason="quarantined_source_ip",
            )

        if packet_metadata.src_ip and packet_metadata.src_ip in self.firewall_config.blocked_source_ips:
            return FirewallDecision(
                action="block",
                reason="static_source_block",
                rule_kind="static_source_block",
            )

        if packet_metadata.is_arp:
            return self._evaluate_arp(packet_metadata)

        if not packet_metadata.is_ipv4:
            return FirewallDecision(action="allow", reason="non_ip_traffic")

        if packet_metadata.transport_protocol == "tcp":
            if packet_metadata.dst_port in self.firewall_config.restricted_tcp_ports:
                return FirewallDecision(
                    action="block",
                    reason="restricted_tcp_port_%s" % packet_metadata.dst_port,
                    rule_kind="restricted_tcp_port",
                )

        if packet_metadata.transport_protocol == "udp":
            if packet_metadata.dst_port in self.firewall_config.restricted_udp_ports:
                return FirewallDecision(
                    action="block",
                    reason="restricted_udp_port_%s" % packet_metadata.dst_port,
                    rule_kind="restricted_udp_port",
                )

        if packet_metadata.is_icmp:
            return self._evaluate_icmp(packet_metadata)

        if self.firewall_config.allow_internal_subnet and self._is_internal_flow(packet_metadata):
            return FirewallDecision(action="allow", reason="internal_subnet")

        if self.firewall_config.default_allow_ipv4:
            return FirewallDecision(action="allow", reason="default_allow_ipv4")

        return FirewallDecision(
            action="block",
            reason="default_ipv4_deny",
            rule_kind="packet_block",
        )

    def enforce_block_decision(self, datapath, packet_metadata, decision, datapaths=None):
        datapaths = list(datapaths or [datapath])

        if decision.rule_kind == "static_source_block":
            self.activated_source_blocks.add(packet_metadata.src_ip)
            for current_datapath in datapaths:
                self.flow_manager.install_source_block(
                    current_datapath,
                    packet_metadata.src_ip,
                    priority=self.priority_config.static_source_block,
                    reason=decision.reason,
                )
            return {"priority": self.priority_config.static_source_block}

        if decision.rule_kind == "restricted_tcp_port":
            self.activated_tcp_port_blocks.add(packet_metadata.dst_port)
            for current_datapath in datapaths:
                self.flow_manager.install_service_port_block(
                    current_datapath,
                    protocol="tcp",
                    port_number=packet_metadata.dst_port,
                    priority=self.priority_config.restricted_service_block,
                    reason=decision.reason,
                )
            return {"priority": self.priority_config.restricted_service_block}

        if decision.rule_kind == "restricted_udp_port":
            self.activated_udp_port_blocks.add(packet_metadata.dst_port)
            for current_datapath in datapaths:
                self.flow_manager.install_service_port_block(
                    current_datapath,
                    protocol="udp",
                    port_number=packet_metadata.dst_port,
                    priority=self.priority_config.restricted_service_block,
                    reason=decision.reason,
                )
            return {"priority": self.priority_config.restricted_service_block}

        if decision.rule_kind == "packet_block":
            self.flow_manager.install_exact_packet_block(
                datapath,
                packet_metadata,
                priority=self.priority_config.packet_block,
                hard_timeout=self.timeout_config.packet_block_seconds,
                reason=decision.reason,
            )
            return {
                "priority": self.priority_config.packet_block,
                "hard_timeout": self.timeout_config.packet_block_seconds,
            }

        return None

    def add_quarantine(
        self,
        src_ip,
        reason,
        datapaths,
        detector=None,
        alert_type=None,
        related_capture=None,
    ):
        if not src_ip:
            return None, False
        detector_label = str(detector or "threshold").strip().lower() or "threshold"
        now = time.time()

        current = self.quarantined_hosts.get(src_ip)
        if current is not None:
            current.last_seen_at = now
            current.hit_count = int(current.hit_count or 0) + 1
            current.latest_detector = detector_label
            existing_detectors = [
                str(item).strip().lower()
                for item in list(current.contributing_detectors or [])
                if str(item).strip()
            ]
            if not existing_detectors:
                existing_detectors = [str(current.detector or "threshold").strip().lower()]
            if detector_label not in existing_detectors:
                existing_detectors.append(detector_label)
            current.contributing_detectors = existing_detectors

            incoming_capture = dict(related_capture or {})
            if incoming_capture:
                if not current.related_capture:
                    current.related_capture = incoming_capture
                existing_primary_files = set()
                for capture_row in current.related_captures or []:
                    capture_path = str(
                        dict(capture_row or {}).get("primary_file", "")
                    ).strip()
                    if capture_path:
                        existing_primary_files.add(capture_path)
                if current.related_capture:
                    primary_capture_path = str(
                        current.related_capture.get("primary_file", "")
                    ).strip()
                    if primary_capture_path:
                        existing_primary_files.add(primary_capture_path)
                incoming_primary_path = str(
                    incoming_capture.get("primary_file", "")
                ).strip()
                if incoming_primary_path and incoming_primary_path not in existing_primary_files:
                    current.related_captures.append(incoming_capture)
            return current, False

        record = QuarantineRecord(
            src_ip=src_ip,
            reason=reason,
            detector=detector_label,
            latest_detector=detector_label,
            contributing_detectors=[detector_label],
            alert_type=alert_type,
            related_capture=dict(related_capture or {}),
        )
        if record.related_capture:
            record.related_captures = [dict(record.related_capture)]
        self.quarantined_hosts[src_ip] = record

        for datapath in datapaths:
            self.flow_manager.install_source_block(
                datapath,
                src_ip,
                priority=self.priority_config.temporary_source_block,
                hard_timeout=0,
                reason=reason,
            )

        return record, True

    def remove_quarantine(self, src_ip, datapaths, released_by="dashboard"):
        record = self.quarantined_hosts.get(src_ip)
        if record is None:
            return None, False

        for datapath in datapaths:
            self.flow_manager.remove_source_block(
                datapath,
                src_ip,
                priority=self.priority_config.temporary_source_block,
                reason="manual_unblock",
            )

        del self.quarantined_hosts[src_ip]
        record.released_at = time.time()
        record.released_by = released_by
        return record, True

    def add_temporary_block(
        self,
        src_ip,
        reason,
        datapaths,
        duration_seconds=None,
        detector=None,
        alert_type=None,
        related_capture=None,
    ):
        return self.add_quarantine(
            src_ip=src_ip,
            reason=reason,
            datapaths=datapaths,
            detector=detector,
            alert_type=alert_type,
            related_capture=related_capture,
        )

    def expire_temporary_blocks(self, now=None):
        return []

    def _evaluate_arp(self, packet_metadata):
        if not self.firewall_config.allow_arp:
            return FirewallDecision(
                action="block",
                reason="arp_disabled",
                rule_kind="packet_block",
            )
        return FirewallDecision(action="allow", reason="arp_permitted")

    def _evaluate_icmp(self, packet_metadata):
        if not self.firewall_config.permit_icmp:
            return FirewallDecision(
                action="block",
                reason="icmp_disabled",
                rule_kind="packet_block",
            )

        if self._is_internal_flow(packet_metadata):
            return FirewallDecision(action="allow", reason="icmp_internal")

        if self.firewall_config.permit_icmp_external:
            return FirewallDecision(action="allow", reason="icmp_external_allowed")

        return FirewallDecision(
            action="block",
            reason="icmp_outside_internal_subnet",
            rule_kind="packet_block",
        )

    def _quarantine_for(self, src_ip):
        return self.quarantined_hosts.get(src_ip)

    def _is_internal_flow(self, packet_metadata):
        if not packet_metadata.src_ip or not packet_metadata.dst_ip:
            return False
        return self._is_internal_ip(packet_metadata.src_ip) and self._is_internal_ip(
            packet_metadata.dst_ip
        )

    def _is_internal_ip(self, address):
        try:
            return ipaddress.ip_address(address) in self.firewall_config.internal_network
        except ValueError:
            return False
