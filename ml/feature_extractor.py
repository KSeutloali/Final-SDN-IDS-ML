"""Live feature extraction for the optional ML-based IDS path.

The controller cannot reproduce every flow feature available in offline datasets
such as CIC. This module therefore focuses on statistics that are realistic to
compute from controller-observed packets and short rolling windows.
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from ml.feature_engineering import (
    baseline_ratio,
    burstiness,
    entropy,
    inter_arrival_stats,
    new_value_ratio,
    standard_deviation,
    trend_delta,
)


RUNTIME_FEATURE_NAMES = (
    "packet_count",
    "byte_count",
    "unique_destination_ports",
    "unique_destination_ips",
    "destination_port_fanout_ratio",
    "connection_rate",
    "syn_rate",
    "icmp_rate",
    "udp_rate",
    "tcp_rate",
    "average_packet_size",
    "observation_window_seconds",
    "packet_rate",
    "bytes_per_second",
    "failed_connection_rate",
    "unanswered_syn_rate",
    "unanswered_syn_ratio",
)


@dataclass
class FeatureSnapshot(object):
    """Controller-observable ML features for one source host."""

    src_ip: str
    timestamp: float
    feature_values: dict
    sample_count: int

    def to_dict(self):
        payload = {
            "src_ip": self.src_ip,
            "timestamp": self.timestamp,
            "sample_count": self.sample_count,
        }
        payload.update(self.feature_values)
        return payload

    def to_vector(self, feature_names):
        return [float(self.feature_values.get(name, 0.0)) for name in feature_names]


class LiveFeatureExtractor(object):
    """Build rolling-window per-host features from controller packet events."""

    def __init__(self, ml_config):
        self.window_seconds = max(1, int(ml_config.feature_window_seconds))
        self.medium_window_seconds = max(30, self.window_seconds)
        self.long_window_seconds = max(120, self.medium_window_seconds)
        self.host_windows = defaultdict(deque)
        self.host_history_windows = defaultdict(deque)
        self.failed_windows = defaultdict(deque)
        self.failed_history_windows = defaultdict(deque)
        self.unanswered_windows = defaultdict(deque)
        self.unanswered_history_windows = defaultdict(deque)
        self.host_feature_baselines = defaultdict(dict)
        self.connection_attempts = {}
        self.connection_attempt_queue = deque()
        self.coarse_connection_attempts = defaultdict(deque)
        self.coarse_connection_attempt_queue = deque()
        self.pending_attempt_counts = defaultdict(int)
        self.recent_probe_pairs = {}
        self.recent_probe_pair_queue = deque()
        self.recent_responder_flows = {}
        self.recent_responder_flow_queue = deque()
        self.attempt_timeout_seconds = max(
            0.5,
            min(
                float(self.window_seconds),
                float(getattr(ml_config, "unanswered_syn_timeout_seconds", 1.5)),
            ),
        )
        self.responder_flow_retention_seconds = max(
            float(self.window_seconds),
            self.attempt_timeout_seconds * 4.0,
        )

    def observe(self, packet_metadata):
        """Update feature state for one packet and return the current snapshot."""

        if (
            packet_metadata is None
            or not packet_metadata.is_ipv4
            or not packet_metadata.src_ip
        ):
            return None

        now = packet_metadata.timestamp
        src_ip = packet_metadata.src_ip

        self._expire_attempts(now)
        self._expire_probe_pairs(now)
        self._expire_responder_flows(now)
        if self._is_recent_responder_flow(packet_metadata):
            return None
        matched_attempt_src_ip = self._record_failed_connection(packet_metadata, now)
        if matched_attempt_src_ip is None:
            matched_attempt_src_ip = self._resolve_connection_attempt(packet_metadata)
        pair_response = self._is_recent_probe_pair_response(packet_metadata)

        # TCP responses to tracked outbound attempts should update the initiating
        # host's state, but they should not create an independent ML signal for
        # the responder. Otherwise a scan target can be misclassified as the
        # attacker simply for sending SYN-ACK/RST replies.
        if (
            matched_attempt_src_ip is not None
            and matched_attempt_src_ip != src_ip
        ):
            self._remember_responder_flow(packet_metadata, now)
            return None
        if pair_response:
            self._remember_responder_flow(packet_metadata, now)
            return None

        event = (
            now,
            packet_metadata.packet_length,
            packet_metadata.transport_protocol,
            packet_metadata.dst_ip,
            packet_metadata.dst_port,
            bool(packet_metadata.tcp_syn_only),
            bool(self._is_connection_attempt(packet_metadata)),
        )
        window = self.host_windows[src_ip]
        window.append(event)
        self._trim_window(window, now, self.window_seconds)

        history_window = self.host_history_windows[src_ip]
        history_window.append(event)
        self._trim_window(history_window, now, self.long_window_seconds)

        if getattr(packet_metadata, "is_fragmented_tcp_probe", False) and packet_metadata.dst_ip:
            self._remember_probe_pair(packet_metadata.src_ip, packet_metadata.dst_ip, now)
            if packet_metadata.src_port is not None and packet_metadata.dst_port is not None:
                attempt_key = (
                    packet_metadata.src_ip,
                    packet_metadata.dst_ip,
                    packet_metadata.src_port,
                    packet_metadata.dst_port,
                )
                if attempt_key not in self.connection_attempts:
                    self.pending_attempt_counts[packet_metadata.src_ip] += 1
                self.connection_attempts[attempt_key] = (now, packet_metadata.src_ip)
                self.connection_attempt_queue.append((now, attempt_key))
            else:
                attempt_key = (
                    packet_metadata.src_ip,
                    packet_metadata.dst_ip,
                )
                self.pending_attempt_counts[packet_metadata.src_ip] += 1
                self.coarse_connection_attempts[attempt_key].append(
                    (now, packet_metadata.src_ip)
                )
                self.coarse_connection_attempt_queue.append((now, attempt_key))
        elif packet_metadata.tcp_syn_only and packet_metadata.dst_ip:
            self._remember_probe_pair(packet_metadata.src_ip, packet_metadata.dst_ip, now)
            attempt_key = (
                packet_metadata.src_ip,
                packet_metadata.dst_ip,
                packet_metadata.src_port,
                packet_metadata.dst_port,
            )
            if attempt_key not in self.connection_attempts:
                self.pending_attempt_counts[packet_metadata.src_ip] += 1
            self.connection_attempts[attempt_key] = (now, packet_metadata.src_ip)
            self.connection_attempt_queue.append((now, attempt_key))
        elif self._is_unparsed_tcp_probe(packet_metadata):
            self._remember_probe_pair(packet_metadata.src_ip, packet_metadata.dst_ip, now)
            attempt_key = (
                packet_metadata.src_ip,
                packet_metadata.dst_ip,
            )
            self.pending_attempt_counts[packet_metadata.src_ip] += 1
            self.coarse_connection_attempts[attempt_key].append(
                (now, packet_metadata.src_ip)
            )
            self.coarse_connection_attempt_queue.append((now, attempt_key))

        feature_values = self._build_features(src_ip, now)
        return FeatureSnapshot(
            src_ip=src_ip,
            timestamp=now,
            feature_values=feature_values,
            sample_count=len(window),
        )

    def _build_features(self, src_ip, now):
        window = self.host_windows[src_ip]
        history_window = self.host_history_windows[src_ip]
        failed_window = self.failed_windows[src_ip]
        failed_history_window = self.failed_history_windows[src_ip]
        unanswered_window = self.unanswered_windows[src_ip]
        unanswered_history_window = self.unanswered_history_windows[src_ip]
        self._trim_timestamp_window(failed_window, now, self.window_seconds)
        self._trim_timestamp_window(
            failed_history_window,
            now,
            self.long_window_seconds,
        )
        self._trim_timestamp_window(unanswered_window, now, self.window_seconds)
        self._trim_timestamp_window(
            unanswered_history_window,
            now,
            self.long_window_seconds,
        )

        if not window:
            return self._zero_feature_values()

        medium_window = self._window_events(
            history_window,
            now,
            self.medium_window_seconds,
        )
        short_historical_window = [
            item for item in history_window if item[0] < (now - self.window_seconds)
        ]
        observation_window_seconds = self._observation_window_seconds(
            window,
            now,
            self.window_seconds,
        )
        medium_observation_window_seconds = self._observation_window_seconds(
            medium_window,
            now,
            self.medium_window_seconds,
        )

        packet_count = float(len(window))
        byte_count = float(sum(item[1] for item in window))
        destination_ports = [item[4] for item in window if item[4] is not None]
        destination_ips = [item[3] for item in window if item[3]]
        unique_destination_ports = float(len(set(destination_ports)))
        unique_destination_ips = float(len(set(destination_ips)))
        connection_attempts = float(sum(1 for item in window if item[6]))
        syn_count = float(sum(1 for item in window if item[5]))
        icmp_count = float(sum(1 for item in window if item[2] == "icmp"))
        udp_count = float(sum(1 for item in window if item[2] == "udp"))
        tcp_count = float(sum(1 for item in window if item[2] == "tcp"))
        failed_count = float(len(failed_window))
        unanswered_count = float(
            len(unanswered_window) + int(self.pending_attempt_counts.get(src_ip, 0))
        )
        medium_packet_count = float(len(medium_window))
        medium_destination_ports = [
            item[4] for item in medium_window if item[4] is not None
        ]
        medium_destination_ips = [item[3] for item in medium_window if item[3]]
        medium_unique_destination_ports = float(len(set(medium_destination_ports)))
        medium_syn_count = float(sum(1 for item in medium_window if item[5]))
        medium_unanswered_count = float(
            len(self._window_timestamps(unanswered_history_window, now, self.medium_window_seconds))
            + int(self.pending_attempt_counts.get(src_ip, 0))
        )
        destination_port_fanout_ratio = (
            unique_destination_ports / connection_attempts
            if connection_attempts
            else 0.0
        )
        unanswered_syn_ratio = (
            min(1.0, unanswered_count / syn_count)
            if syn_count
            else 0.0
        )
        packet_rate = packet_count / observation_window_seconds
        bytes_per_second = byte_count / observation_window_seconds
        connection_rate = connection_attempts / observation_window_seconds
        failed_connection_rate = failed_count / observation_window_seconds
        unanswered_syn_rate = unanswered_count / observation_window_seconds
        medium_packet_rate = (
            medium_packet_count / medium_observation_window_seconds
            if medium_packet_count
            else 0.0
        )
        medium_unanswered_syn_ratio = (
            min(1.0, medium_unanswered_count / medium_syn_count)
            if medium_syn_count
            else 0.0
        )
        recon_probe_density = (
            (float(max(len(window), int(connection_attempts))) + unanswered_count)
            / observation_window_seconds
        )
        short_inter_arrival_mean, short_inter_arrival_std = inter_arrival_stats(
            item[0] for item in window
        )
        medium_inter_arrival_mean, medium_inter_arrival_std = inter_arrival_stats(
            item[0] for item in medium_window
        )
        burstiness_short = burstiness(
            short_inter_arrival_mean,
            short_inter_arrival_std,
        )
        destination_ip_entropy_short = entropy(destination_ips)
        destination_port_entropy_short = entropy(destination_ports)
        protocol_entropy_short = entropy(item[2] for item in window if item[2])
        packet_size_std_short = standard_deviation(item[1] for item in window)
        historical_destination_ips = {
            item[3] for item in short_historical_window if item[3]
        }
        historical_destination_ports = {
            item[4] for item in short_historical_window if item[4] is not None
        }
        new_destination_ip_ratio_short = new_value_ratio(
            destination_ips,
            historical_destination_ips,
        )
        new_destination_port_ratio_short = new_value_ratio(
            destination_ports,
            historical_destination_ports,
        )
        baseline = self.host_feature_baselines[src_ip]
        packet_rate_delta = packet_rate - float(baseline.get("packet_rate", packet_rate))
        destination_port_fanout_delta = destination_port_fanout_ratio - float(
            baseline.get("destination_port_fanout_ratio", destination_port_fanout_ratio)
        )
        unique_destination_ips_delta = unique_destination_ips - float(
            baseline.get("unique_destination_ips", unique_destination_ips)
        )
        unique_destination_ports_delta = unique_destination_ports - float(
            baseline.get("unique_destination_ports", unique_destination_ports)
        )
        host_packet_rate_baseline_ratio = baseline_ratio(
            packet_rate,
            baseline.get("packet_rate"),
        )
        host_unique_dest_ip_baseline_ratio = baseline_ratio(
            unique_destination_ips,
            baseline.get("unique_destination_ips"),
        )
        host_unique_dest_port_baseline_ratio = baseline_ratio(
            unique_destination_ports,
            baseline.get("unique_destination_ports"),
        )
        host_unanswered_syn_ratio_baseline_ratio = baseline_ratio(
            unanswered_syn_ratio,
            baseline.get("unanswered_syn_ratio"),
        )
        packet_rate_trend = trend_delta(packet_rate, medium_packet_rate)
        unique_destination_port_trend = trend_delta(
            (unique_destination_ports / observation_window_seconds)
            if unique_destination_ports
            else 0.0,
            (
                medium_unique_destination_ports / medium_observation_window_seconds
                if medium_unique_destination_ports
                else 0.0
            ),
        )
        unanswered_syn_ratio_trend = trend_delta(
            unanswered_syn_ratio,
            medium_unanswered_syn_ratio,
        )

        feature_values = {
            "packet_count": packet_count,
            "byte_count": byte_count,
            "unique_destination_ports": unique_destination_ports,
            "unique_destination_ips": unique_destination_ips,
            "destination_port_fanout_ratio": destination_port_fanout_ratio,
            "connection_rate": connection_rate,
            "syn_rate": syn_count / observation_window_seconds,
            "icmp_rate": icmp_count / observation_window_seconds,
            "udp_rate": udp_count / observation_window_seconds,
            "tcp_rate": tcp_count / observation_window_seconds,
            "average_packet_size": (byte_count / packet_count) if packet_count else 0.0,
            "observation_window_seconds": float(observation_window_seconds),
            "packet_rate": packet_rate,
            "bytes_per_second": bytes_per_second,
            "failed_connection_rate": failed_connection_rate,
            "unanswered_syn_rate": unanswered_syn_rate,
            "unanswered_syn_ratio": unanswered_syn_ratio,
            # Extra runtime-visible recon features are recorded for live enrichment
            # and future retraining without changing the current model vector.
            "unanswered_syn_count": unanswered_count,
            "recon_probe_density": recon_probe_density,
            "packet_rate_delta": packet_rate_delta,
            "destination_port_fanout_delta": destination_port_fanout_delta,
            "unique_destination_ips_delta": unique_destination_ips_delta,
            "unique_destination_ports_delta": unique_destination_ports_delta,
            "inter_arrival_mean_short": short_inter_arrival_mean,
            "inter_arrival_std_short": short_inter_arrival_std,
            "inter_arrival_mean_medium": medium_inter_arrival_mean,
            "inter_arrival_std_medium": medium_inter_arrival_std,
            "burstiness_short": burstiness_short,
            "destination_ip_entropy_short": destination_ip_entropy_short,
            "destination_port_entropy_short": destination_port_entropy_short,
            "protocol_entropy_short": protocol_entropy_short,
            "packet_size_std_short": packet_size_std_short,
            "new_destination_ip_ratio_short": new_destination_ip_ratio_short,
            "new_destination_port_ratio_short": new_destination_port_ratio_short,
            "host_packet_rate_baseline_ratio": host_packet_rate_baseline_ratio,
            "host_unique_dest_ip_baseline_ratio": host_unique_dest_ip_baseline_ratio,
            "host_unique_dest_port_baseline_ratio": host_unique_dest_port_baseline_ratio,
            "host_unanswered_syn_ratio_baseline_ratio": (
                host_unanswered_syn_ratio_baseline_ratio
            ),
            "packet_rate_trend": packet_rate_trend,
            "unique_destination_port_trend": unique_destination_port_trend,
            "unanswered_syn_ratio_trend": unanswered_syn_ratio_trend,
        }
        self._update_baseline(src_ip, feature_values)
        return feature_values

    def _record_failed_connection(self, packet_metadata, now):
        if (
            not packet_metadata.tcp_rst
            or not packet_metadata.src_ip
            or not packet_metadata.dst_ip
            or packet_metadata.src_port is None
            or packet_metadata.dst_port is None
        ):
            return None

        attempt_key = (
            packet_metadata.dst_ip,
            packet_metadata.src_ip,
            packet_metadata.dst_port,
            packet_metadata.src_port,
        )
        attempt_data = self.connection_attempts.pop(attempt_key, None)
        if attempt_data is None:
            coarse_attempt_key = (
                packet_metadata.dst_ip,
                packet_metadata.src_ip,
            )
            attempt_data = self._pop_coarse_attempt(coarse_attempt_key)
        if attempt_data is None:
            return None
        _, attempt_src_ip = attempt_data
        self._decrement_pending_attempt(attempt_src_ip)

        failed_window = self.failed_windows[attempt_src_ip]
        failed_window.append(now)
        self._trim_timestamp_window(failed_window, now, self.window_seconds)

        failed_history_window = self.failed_history_windows[attempt_src_ip]
        failed_history_window.append(now)
        self._trim_timestamp_window(
            failed_history_window,
            now,
            self.long_window_seconds,
        )
        return attempt_src_ip

    def _resolve_connection_attempt(self, packet_metadata):
        if (
            packet_metadata is None
            or not getattr(packet_metadata, "is_tcp", packet_metadata.transport_protocol == "tcp")
            or not getattr(packet_metadata, "src_ip", None)
            or not getattr(packet_metadata, "dst_ip", None)
            or packet_metadata.src_port is None
            or packet_metadata.dst_port is None
        ):
            return None

        if getattr(packet_metadata, "tcp_syn_only", False) or getattr(packet_metadata, "tcp_rst", False):
            return None

        attempt_key = (
            packet_metadata.dst_ip,
            packet_metadata.src_ip,
            packet_metadata.dst_port,
            packet_metadata.src_port,
        )
        attempt_data = self.connection_attempts.pop(attempt_key, None)
        if attempt_data is None:
            coarse_attempt_key = (
                packet_metadata.dst_ip,
                packet_metadata.src_ip,
            )
            attempt_data = self._pop_coarse_attempt(coarse_attempt_key)
        if attempt_data is None:
            return None
        _, attempt_src_ip = attempt_data
        self._decrement_pending_attempt(attempt_src_ip)
        return attempt_src_ip

    def _expire_attempts(self, now):
        while self.connection_attempt_queue:
            timestamp_value, attempt_key = self.connection_attempt_queue[0]
            if (now - timestamp_value) <= self.attempt_timeout_seconds:
                break
            self.connection_attempt_queue.popleft()
            attempt_data = self.connection_attempts.get(attempt_key)
            if attempt_data is None:
                continue
            attempt_timestamp, attempt_src_ip = attempt_data
            if attempt_timestamp == timestamp_value:
                del self.connection_attempts[attempt_key]
                self._decrement_pending_attempt(attempt_src_ip)
                unanswered_window = self.unanswered_windows[attempt_src_ip]
                unanswered_window.append(now)
                self._trim_timestamp_window(unanswered_window, now, self.window_seconds)
                unanswered_history_window = self.unanswered_history_windows[attempt_src_ip]
                unanswered_history_window.append(now)
                self._trim_timestamp_window(
                    unanswered_history_window,
                    now,
                    self.long_window_seconds,
                )

        while self.coarse_connection_attempt_queue:
            timestamp_value, attempt_key = self.coarse_connection_attempt_queue[0]
            if (now - timestamp_value) <= self.attempt_timeout_seconds:
                break
            self.coarse_connection_attempt_queue.popleft()
            attempt_queue = self.coarse_connection_attempts.get(attempt_key)
            if not attempt_queue:
                continue
            attempt_timestamp, attempt_src_ip = attempt_queue[0]
            if attempt_timestamp == timestamp_value:
                attempt_queue.popleft()
                if not attempt_queue:
                    del self.coarse_connection_attempts[attempt_key]
                self._decrement_pending_attempt(attempt_src_ip)
                unanswered_window = self.unanswered_windows[attempt_src_ip]
                unanswered_window.append(now)
                self._trim_timestamp_window(unanswered_window, now, self.window_seconds)
                unanswered_history_window = self.unanswered_history_windows[attempt_src_ip]
                unanswered_history_window.append(now)
                self._trim_timestamp_window(
                    unanswered_history_window,
                    now,
                    self.long_window_seconds,
                )

    @staticmethod
    def _observation_window_seconds(window, now, max_window_seconds):
        if not window:
            return 0.0
        first_seen = window[0][0]
        return max(1.0, min(float(max_window_seconds), now - first_seen + 0.001))

    @staticmethod
    def _trim_window(window, now, window_seconds):
        while window and (now - window[0][0]) > window_seconds:
            window.popleft()

    @staticmethod
    def _trim_timestamp_window(window, now, window_seconds):
        while window and (now - window[0]) > window_seconds:
            window.popleft()

    def reset(self):
        self.host_windows.clear()
        self.host_history_windows.clear()
        self.failed_windows.clear()
        self.failed_history_windows.clear()
        self.unanswered_windows.clear()
        self.unanswered_history_windows.clear()
        self.host_feature_baselines.clear()
        self.connection_attempts.clear()
        self.connection_attempt_queue.clear()
        self.coarse_connection_attempts.clear()
        self.coarse_connection_attempt_queue.clear()
        self.pending_attempt_counts.clear()
        self.recent_probe_pairs.clear()
        self.recent_probe_pair_queue.clear()
        self.recent_responder_flows.clear()
        self.recent_responder_flow_queue.clear()

    def _decrement_pending_attempt(self, src_ip):
        if not src_ip:
            return
        pending_count = int(self.pending_attempt_counts.get(src_ip, 0))
        if pending_count <= 1:
            self.pending_attempt_counts.pop(src_ip, None)
            return
        self.pending_attempt_counts[src_ip] = pending_count - 1

    def _remember_responder_flow(self, packet_metadata, now):
        if (
            packet_metadata is None
            or getattr(packet_metadata, "transport_protocol", "") != "tcp"
            or not getattr(packet_metadata, "src_ip", None)
            or not getattr(packet_metadata, "dst_ip", None)
            or getattr(packet_metadata, "src_port", None) is None
            or getattr(packet_metadata, "dst_port", None) is None
        ):
            return

        flow_key = (
            packet_metadata.src_ip,
            packet_metadata.dst_ip,
            packet_metadata.src_port,
            packet_metadata.dst_port,
        )
        self.recent_responder_flows[flow_key] = now
        self.recent_responder_flow_queue.append((now, flow_key))

    def _remember_probe_pair(self, src_ip, dst_ip, now):
        if not src_ip or not dst_ip:
            return
        pair_key = (src_ip, dst_ip)
        self.recent_probe_pairs[pair_key] = now
        self.recent_probe_pair_queue.append((now, pair_key))

    def _is_recent_responder_flow(self, packet_metadata):
        if (
            packet_metadata is None
            or getattr(packet_metadata, "transport_protocol", "") != "tcp"
            or not getattr(packet_metadata, "src_ip", None)
            or not getattr(packet_metadata, "dst_ip", None)
            or getattr(packet_metadata, "src_port", None) is None
            or getattr(packet_metadata, "dst_port", None) is None
            or getattr(packet_metadata, "tcp_syn_only", False)
        ):
            return False

        flow_key = (
            packet_metadata.src_ip,
            packet_metadata.dst_ip,
            packet_metadata.src_port,
            packet_metadata.dst_port,
        )
        return flow_key in self.recent_responder_flows

    def _is_recent_probe_pair_response(self, packet_metadata):
        if (
            packet_metadata is None
            or getattr(packet_metadata, "transport_protocol", "") != "tcp"
            or getattr(packet_metadata, "tcp_syn_only", False)
            or not getattr(packet_metadata, "src_ip", None)
            or not getattr(packet_metadata, "dst_ip", None)
            or getattr(packet_metadata, "dst_port", None) is None
            or int(packet_metadata.dst_port) < 1024
        ):
            return False
        pair_key = (packet_metadata.dst_ip, packet_metadata.src_ip)
        return pair_key in self.recent_probe_pairs

    def _expire_probe_pairs(self, now):
        while self.recent_probe_pair_queue:
            timestamp_value, pair_key = self.recent_probe_pair_queue[0]
            if (now - timestamp_value) <= self.responder_flow_retention_seconds:
                break
            self.recent_probe_pair_queue.popleft()
            existing_timestamp = self.recent_probe_pairs.get(pair_key)
            if existing_timestamp == timestamp_value:
                del self.recent_probe_pairs[pair_key]

    def _expire_responder_flows(self, now):
        while self.recent_responder_flow_queue:
            timestamp_value, flow_key = self.recent_responder_flow_queue[0]
            if (now - timestamp_value) <= self.responder_flow_retention_seconds:
                break
            self.recent_responder_flow_queue.popleft()
            existing_timestamp = self.recent_responder_flows.get(flow_key)
            if existing_timestamp == timestamp_value:
                del self.recent_responder_flows[flow_key]

    def _pop_coarse_attempt(self, attempt_key):
        attempt_queue = self.coarse_connection_attempts.get(attempt_key)
        if not attempt_queue:
            return None
        attempt_data = attempt_queue.popleft()
        if not attempt_queue:
            del self.coarse_connection_attempts[attempt_key]
        return attempt_data

    @staticmethod
    def _is_connection_attempt(packet_metadata):
        if getattr(packet_metadata, "is_fragmented_tcp_probe", False):
            return True
        if packet_metadata.transport_protocol == "tcp":
            return packet_metadata.tcp_syn_only
        if LiveFeatureExtractor._is_unparsed_tcp_probe(packet_metadata):
            return True
        if packet_metadata.transport_protocol == "udp":
            return packet_metadata.dst_port is not None
        return False

    @staticmethod
    def _is_unparsed_tcp_probe(packet_metadata):
        if getattr(packet_metadata, "is_fragmented_tcp_probe", False):
            return True
        if hasattr(packet_metadata, "ip_fragment_offset") or hasattr(packet_metadata, "ip_flags"):
            return False
        return bool(
            packet_metadata is not None
            and getattr(packet_metadata, "transport_protocol", "") != "tcp"
            and getattr(packet_metadata, "ip_proto", None) == 6
            and getattr(packet_metadata, "src_ip", None)
            and getattr(packet_metadata, "dst_ip", None)
        )

    def _zero_feature_values(self):
        feature_values = dict((name, 0.0) for name in RUNTIME_FEATURE_NAMES)
        feature_values.update(
            {
                "unanswered_syn_count": 0.0,
                "recon_probe_density": 0.0,
                "packet_rate_delta": 0.0,
                "destination_port_fanout_delta": 0.0,
                "unique_destination_ips_delta": 0.0,
                "unique_destination_ports_delta": 0.0,
                "inter_arrival_mean_short": 0.0,
                "inter_arrival_std_short": 0.0,
                "inter_arrival_mean_medium": 0.0,
                "inter_arrival_std_medium": 0.0,
                "burstiness_short": 0.0,
                "destination_ip_entropy_short": 0.0,
                "destination_port_entropy_short": 0.0,
                "protocol_entropy_short": 0.0,
                "packet_size_std_short": 0.0,
                "new_destination_ip_ratio_short": 0.0,
                "new_destination_port_ratio_short": 0.0,
                "host_packet_rate_baseline_ratio": 0.0,
                "host_unique_dest_ip_baseline_ratio": 0.0,
                "host_unique_dest_port_baseline_ratio": 0.0,
                "host_unanswered_syn_ratio_baseline_ratio": 0.0,
                "packet_rate_trend": 0.0,
                "unique_destination_port_trend": 0.0,
                "unanswered_syn_ratio_trend": 0.0,
            }
        )
        return feature_values

    def _update_baseline(self, src_ip, feature_values):
        baseline = self.host_feature_baselines[src_ip]
        alpha = 0.25
        for name in (
            "packet_rate",
            "destination_port_fanout_ratio",
            "unique_destination_ips",
            "unique_destination_ports",
            "unanswered_syn_ratio",
        ):
            current_value = float(feature_values.get(name, 0.0))
            previous_value = baseline.get(name)
            if previous_value is None:
                baseline[name] = current_value
                continue
            baseline[name] = ((1.0 - alpha) * float(previous_value)) + (alpha * current_value)

    @staticmethod
    def _window_events(window, now, window_seconds):
        cutoff = now - float(window_seconds)
        return [item for item in window if item[0] >= cutoff]

    @staticmethod
    def _window_timestamps(window, now, window_seconds):
        cutoff = now - float(window_seconds)
        return [timestamp_value for timestamp_value in window if timestamp_value >= cutoff]

def extract_features(extractor, packet_metadata):
    """Convenience wrapper for the project report and simple scripts."""

    return extractor.observe(packet_metadata)
