"""Packet parsing helpers for Ethernet, ARP, IPv4, TCP, UDP, and ICMP."""

import time
from dataclasses import dataclass

from ryu.lib.packet import arp, ethernet, icmp, ipv4, lldp, packet, tcp, udp

TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_ACK = 0x10


@dataclass
class PacketMetadata:
    dpid: str
    in_port: int
    timestamp: float
    packet_length: int
    eth_src: str
    eth_dst: str
    eth_type: int = None
    src_ip: str = None
    dst_ip: str = None
    ip_proto: int = None
    transport_protocol: str = "ethernet"
    src_port: int = None
    dst_port: int = None
    arp_opcode: int = None
    icmp_type: int = None
    icmp_code: int = None
    tcp_flags: int = None
    is_lldp: bool = False
    is_arp: bool = False
    is_ipv4: bool = False
    is_icmp: bool = False

    def protocol_label(self):
        if self.is_lldp:
            return "lldp"
        if self.is_arp:
            return "arp"
        if self.is_icmp:
            return "icmp"
        return self.transport_protocol

    @property
    def is_tcp(self):
        return self.transport_protocol == "tcp"

    @property
    def tcp_syn(self):
        return bool(self.is_tcp and self.tcp_flags is not None and self.tcp_flags & TCP_FLAG_SYN)

    @property
    def tcp_ack(self):
        return bool(self.is_tcp and self.tcp_flags is not None and self.tcp_flags & TCP_FLAG_ACK)

    @property
    def tcp_rst(self):
        return bool(self.is_tcp and self.tcp_flags is not None and self.tcp_flags & TCP_FLAG_RST)

    @property
    def tcp_fin(self):
        return bool(self.is_tcp and self.tcp_flags is not None and self.tcp_flags & TCP_FLAG_FIN)

    @property
    def tcp_syn_only(self):
        return bool(self.tcp_syn and not self.tcp_ack and not self.tcp_rst)


class PacketParser(object):
    """Convert raw packet bytes into controller-friendly metadata."""

    def parse(self, raw_data, dpid, in_port):
        parsed_packet = packet.Packet(raw_data)
        eth_frame = parsed_packet.get_protocol(ethernet.ethernet)
        if eth_frame is None:
            return None

        metadata = PacketMetadata(
            dpid=dpid,
            in_port=in_port,
            timestamp=time.time(),
            packet_length=len(raw_data),
            eth_src=eth_frame.src,
            eth_dst=eth_frame.dst,
            eth_type=eth_frame.ethertype,
        )

        if parsed_packet.get_protocol(lldp.lldp):
            metadata.is_lldp = True
            return metadata

        arp_packet = parsed_packet.get_protocol(arp.arp)
        if arp_packet is not None:
            metadata.is_arp = True
            metadata.transport_protocol = "arp"
            metadata.src_ip = arp_packet.src_ip
            metadata.dst_ip = arp_packet.dst_ip
            metadata.arp_opcode = arp_packet.opcode
            return metadata

        ipv4_packet = parsed_packet.get_protocol(ipv4.ipv4)
        if ipv4_packet is None:
            return metadata

        metadata.is_ipv4 = True
        metadata.transport_protocol = "ipv4"
        metadata.src_ip = ipv4_packet.src
        metadata.dst_ip = ipv4_packet.dst
        metadata.ip_proto = ipv4_packet.proto

        icmp_packet = parsed_packet.get_protocol(icmp.icmp)
        if icmp_packet is not None:
            metadata.is_icmp = True
            metadata.transport_protocol = "icmp"
            metadata.icmp_type = icmp_packet.type
            metadata.icmp_code = icmp_packet.code
            return metadata

        tcp_packet = parsed_packet.get_protocol(tcp.tcp)
        if tcp_packet is not None:
            metadata.transport_protocol = "tcp"
            metadata.src_port = tcp_packet.src_port
            metadata.dst_port = tcp_packet.dst_port
            metadata.tcp_flags = tcp_packet.bits
            return metadata

        udp_packet = parsed_packet.get_protocol(udp.udp)
        if udp_packet is not None:
            metadata.transport_protocol = "udp"
            metadata.src_port = udp_packet.src_port
            metadata.dst_port = udp_packet.dst_port

        return metadata
