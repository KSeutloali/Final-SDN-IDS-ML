"""OpenFlow 1.3 flow install, delete, and packet-out helpers."""

from ryu.ofproto import ether, inet


class FlowManager(object):
    """Manage OpenFlow 1.3 rules for forwarding and firewall actions."""

    def __init__(self, priority_config, timeout_config, flow_event_callback=None):
        self.priority_config = priority_config
        self.timeout_config = timeout_config
        self.flow_event_callback = flow_event_callback
        self._cookie_sequence = 1

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions=None,
        idle_timeout=0,
        hard_timeout=0,
        buffer_id=None,
        reason=None,
    ):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = actions or []
        instructions = []
        flags = datapath.ofproto.OFPFF_SEND_FLOW_REM

        if actions:
            instructions = [
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
            ]

        kwargs = {
            "datapath": datapath,
            "priority": priority,
            "match": match,
            "instructions": instructions,
            "idle_timeout": idle_timeout,
            "hard_timeout": hard_timeout,
            "cookie": self._next_cookie(),
            "flags": flags,
        }
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id

        datapath.send_msg(parser.OFPFlowMod(**kwargs))
        self._emit_flow_event(
            operation="install",
            datapath=datapath,
            priority=priority,
            match=match,
            actions=actions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            reason=reason,
        )
        return bool(buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER)

    def remove_flow(self, datapath, match, priority=None, reason=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        kwargs = {
            "datapath": datapath,
            "command": ofproto.OFPFC_DELETE,
            "out_port": ofproto.OFPP_ANY,
            "out_group": ofproto.OFPG_ANY,
            "match": match,
        }
        if priority is not None:
            kwargs["priority"] = priority
        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    def remove_source_block(self, datapath, src_ip, priority, reason=None):
        if not src_ip:
            return

        parser = datapath.ofproto_parser
        self.remove_flow(
            datapath,
            match=parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=src_ip),
            priority=priority,
            reason=reason or "source_ip_unblock",
        )
        self.remove_flow(
            datapath,
            match=parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, arp_spa=src_ip),
            priority=priority,
            reason=reason or "source_arp_unblock",
        )

    def install_table_miss(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(
            datapath,
            priority=self.priority_config.table_miss,
            match=parser.OFPMatch(),
            actions=actions,
            reason="table_miss",
        )

    def install_forward_flow(
        self,
        datapath,
        in_port,
        packet_metadata,
        out_port,
        buffer_id=None,
    ):
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(
            **self._forward_match_fields(in_port, packet_metadata)
        )
        return self.add_flow(
            datapath,
            priority=self.priority_config.forwarding,
            match=match,
            actions=actions,
            idle_timeout=self.timeout_config.learned_idle_seconds,
            hard_timeout=self.timeout_config.learned_hard_seconds,
            buffer_id=buffer_id,
            reason="mac_learning_forward",
        )

    def install_drop_flow(
        self,
        datapath,
        priority,
        match,
        idle_timeout=0,
        hard_timeout=0,
        reason=None,
    ):
        self.add_flow(
            datapath,
            priority=priority,
            match=match,
            actions=[],
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            reason=reason,
        )

    def install_source_block(self, datapath, src_ip, priority, hard_timeout=0, reason=None):
        if not src_ip:
            return

        parser = datapath.ofproto_parser
        self.install_drop_flow(
            datapath,
            priority=priority,
            match=parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=src_ip),
            hard_timeout=hard_timeout,
            reason=reason or "source_ip_block",
        )
        self.install_drop_flow(
            datapath,
            priority=priority,
            match=parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, arp_spa=src_ip),
            hard_timeout=hard_timeout,
            reason=reason or "source_arp_block",
        )

    def install_service_port_block(
        self,
        datapath,
        protocol,
        port_number,
        priority,
        reason=None,
    ):
        parser = datapath.ofproto_parser
        if protocol == "tcp":
            match = parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ip_proto=inet.IPPROTO_TCP,
                tcp_dst=port_number,
            )
        else:
            match = parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ip_proto=inet.IPPROTO_UDP,
                udp_dst=port_number,
            )
        self.install_drop_flow(
            datapath,
            priority=priority,
            match=match,
            reason=reason or "restricted_%s_port_%s" % (protocol, port_number),
        )

    def install_exact_packet_block(
        self,
        datapath,
        packet_metadata,
        priority,
        hard_timeout,
        reason=None,
    ):
        parser = datapath.ofproto_parser
        match_fields = self._match_fields_from_packet(packet_metadata)
        if not match_fields:
            return
        self.install_drop_flow(
            datapath,
            priority=priority,
            match=parser.OFPMatch(**match_fields),
            hard_timeout=hard_timeout,
            reason=reason or "exact_packet_block",
        )

    def send_packet(self, datapath, buffer_id, in_port, out_port, data):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = [parser.OFPActionOutput(out_port)]
        packet_out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=buffer_id,
            in_port=in_port,
            actions=actions,
            data=None if buffer_id != ofproto.OFP_NO_BUFFER else data,
        )
        datapath.send_msg(packet_out)

    def build_flow_removed_event(self, msg):
        return {
            "operation": "remove",
            "dpid": self._format_dpid(msg.datapath.id),
            "priority": getattr(msg, "priority", None),
            "reason": self._flow_removed_reason(msg),
            "match": self._serialize_match(msg.match),
            "actions": "expired",
            "idle_timeout": getattr(msg, "idle_timeout", 0),
            "hard_timeout": getattr(msg, "hard_timeout", 0),
            "duration_sec": getattr(msg, "duration_sec", 0),
            "duration_nsec": getattr(msg, "duration_nsec", 0),
            "packet_count": getattr(msg, "packet_count", 0),
            "byte_count": getattr(msg, "byte_count", 0),
            "cookie": getattr(msg, "cookie", 0),
        }

    def _emit_flow_event(
        self,
        operation,
        datapath,
        priority,
        match,
        actions,
        idle_timeout,
        hard_timeout,
        reason,
    ):
        if self.flow_event_callback is None:
            return

        payload = {
            "operation": operation,
            "dpid": self._format_dpid(datapath.id),
            "priority": priority,
            "reason": reason,
            "match": self._serialize_match(match),
            "actions": self._serialize_actions(actions),
            "idle_timeout": idle_timeout,
            "hard_timeout": hard_timeout,
        }
        self.flow_event_callback(payload)

    @staticmethod
    def _flow_removed_reason(msg):
        ofproto = msg.datapath.ofproto
        reason_map = {
            ofproto.OFPRR_IDLE_TIMEOUT: "idle_timeout",
            ofproto.OFPRR_HARD_TIMEOUT: "hard_timeout",
            ofproto.OFPRR_DELETE: "delete",
            ofproto.OFPRR_GROUP_DELETE: "group_delete",
        }
        return reason_map.get(getattr(msg, "reason", None), "removed")

    def _next_cookie(self):
        cookie = self._cookie_sequence
        self._cookie_sequence += 1
        return cookie

    @staticmethod
    def _forward_match_fields(in_port, packet_metadata):
        match_fields = {
            "in_port": in_port,
            "eth_dst": packet_metadata.eth_dst,
        }

        if packet_metadata.is_arp:
            match_fields["eth_type"] = ether.ETH_TYPE_ARP
            return match_fields

        if packet_metadata.is_ipv4:
            match_fields["eth_type"] = ether.ETH_TYPE_IP
            if packet_metadata.transport_protocol == "icmp":
                match_fields["ip_proto"] = inet.IPPROTO_ICMP
            elif packet_metadata.transport_protocol == "tcp":
                match_fields["ip_proto"] = inet.IPPROTO_TCP
                if packet_metadata.src_port is not None:
                    match_fields["tcp_src"] = packet_metadata.src_port
                if packet_metadata.dst_port is not None:
                    match_fields["tcp_dst"] = packet_metadata.dst_port
            elif packet_metadata.transport_protocol == "udp":
                match_fields["ip_proto"] = inet.IPPROTO_UDP
                if packet_metadata.src_port is not None:
                    match_fields["udp_src"] = packet_metadata.src_port
                if packet_metadata.dst_port is not None:
                    match_fields["udp_dst"] = packet_metadata.dst_port

        return match_fields

    @staticmethod
    def _match_fields_from_packet(packet_metadata):
        match_fields = {}

        if packet_metadata.is_arp:
            match_fields["eth_type"] = ether.ETH_TYPE_ARP
            if packet_metadata.src_ip:
                match_fields["arp_spa"] = packet_metadata.src_ip
            if packet_metadata.dst_ip:
                match_fields["arp_tpa"] = packet_metadata.dst_ip
            return match_fields

        if not packet_metadata.is_ipv4:
            return match_fields

        match_fields["eth_type"] = ether.ETH_TYPE_IP
        if packet_metadata.src_ip:
            match_fields["ipv4_src"] = packet_metadata.src_ip
        if packet_metadata.dst_ip:
            match_fields["ipv4_dst"] = packet_metadata.dst_ip

        if packet_metadata.transport_protocol == "tcp":
            match_fields["ip_proto"] = inet.IPPROTO_TCP
            if packet_metadata.src_port is not None:
                match_fields["tcp_src"] = packet_metadata.src_port
            if packet_metadata.dst_port is not None:
                match_fields["tcp_dst"] = packet_metadata.dst_port
        elif packet_metadata.transport_protocol == "udp":
            match_fields["ip_proto"] = inet.IPPROTO_UDP
            if packet_metadata.src_port is not None:
                match_fields["udp_src"] = packet_metadata.src_port
            if packet_metadata.dst_port is not None:
                match_fields["udp_dst"] = packet_metadata.dst_port
        elif packet_metadata.is_icmp:
            match_fields["ip_proto"] = inet.IPPROTO_ICMP

        return match_fields

    @staticmethod
    def _serialize_match(match):
        try:
            items = dict(match.items())
        except Exception:
            return str(match)

        if not items:
            return "table_miss"

        parts = []
        for key in sorted(items):
            parts.append("%s=%s" % (key, items[key]))
        return ",".join(parts)

    @staticmethod
    def _serialize_actions(actions):
        if not actions:
            return "drop"
        return ",".join(str(action) for action in actions)

    @staticmethod
    def _format_dpid(dpid):
        return "%016x" % dpid
