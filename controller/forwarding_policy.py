"""Forwarding visibility rules for controller-observed IDS traffic."""

ICMP_PROBE_TYPES = frozenset((8, 13, 15, 17))


def classify_visibility(ids_config, packet_metadata):
    """Return a short classification for forwarding visibility decisions."""

    if not getattr(packet_metadata, "is_ipv4", False):
        return "fast_path"

    if getattr(packet_metadata, "transport_protocol", None) == "tcp":
        if (
            getattr(ids_config, "keep_tcp_syn_packets_visible", True)
            and getattr(packet_metadata, "tcp_syn_only", False)
        ):
            return "tcp_syn_probe"
        return "fast_path"

    if getattr(packet_metadata, "transport_protocol", None) == "udp":
        if (
            getattr(ids_config, "keep_udp_probe_packets_visible", True)
            and _is_udp_probe_candidate(ids_config, packet_metadata)
        ):
            return "udp_probe_candidate"
        return "fast_path"

    if getattr(packet_metadata, "is_icmp", False):
        if (
            getattr(ids_config, "keep_icmp_echo_requests_visible", True)
            and getattr(packet_metadata, "icmp_type", None) in ICMP_PROBE_TYPES
        ):
            return "icmp_probe_candidate"
        return "fast_path"

    return "fast_path"


def should_install_forward_flow(ids_config, packet_metadata):
    """Return whether this packet should be fast-pathed with a learned flow.

    Recon-prone traffic is intentionally kept controller-visible so the threshold IDS
    can observe enough packets to build scan and sweep signals before the dataplane
    bypasses PacketIn processing.
    """

    return classify_visibility(ids_config, packet_metadata) == "fast_path"


def _is_udp_probe_candidate(ids_config, packet_metadata):
    trusted_ports = set(getattr(ids_config, "udp_fastpath_ports", ()) or ())
    src_port = getattr(packet_metadata, "src_port", None)
    dst_port = getattr(packet_metadata, "dst_port", None)
    if src_port in trusted_ports or dst_port in trusted_ports:
        return False
    return True
