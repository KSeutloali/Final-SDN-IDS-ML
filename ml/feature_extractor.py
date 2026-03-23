"""Live feature extraction for the optional ML-based IDS path.

The controller cannot reproduce every flow feature available in offline datasets
such as CIC. This module therefore focuses on statistics that are realistic to
compute from controller-observed packets and short rolling windows.
"""

from collections import defaultdict, deque
from dataclasses import dataclass


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
        self.host_windows = defaultdict(deque)
        self.failed_windows = defaultdict(deque)
        self.unanswered_windows = defaultdict(deque)
        self.connection_attempts = {}
        self.connection_attempt_queue = deque()
        self.pending_attempt_counts = defaultdict(int)
        self.attempt_timeout_seconds = max(
            0.5,
            min(
                float(self.window_seconds),
                float(getattr(ml_config, "unanswered_syn_timeout_seconds", 1.5)),
            ),
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
        self._resolve_connection_attempt(packet_metadata)
        self._record_failed_connection(packet_metadata, now)

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
        self._trim_window(window, now)

        if packet_metadata.tcp_syn_only and packet_metadata.dst_ip:
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

        feature_values = self._build_features(src_ip, now)
        return FeatureSnapshot(
            src_ip=src_ip,
            timestamp=now,
            feature_values=feature_values,
            sample_count=len(window),
        )

    def _build_features(self, src_ip, now):
        window = self.host_windows[src_ip]
        failed_window = self.failed_windows[src_ip]
        unanswered_window = self.unanswered_windows[src_ip]
        while failed_window and (now - failed_window[0]) > self.window_seconds:
            failed_window.popleft()
        while unanswered_window and (now - unanswered_window[0]) > self.window_seconds:
            unanswered_window.popleft()

        if not window:
            return dict((name, 0.0) for name in RUNTIME_FEATURE_NAMES)

        first_seen = window[0][0]
        observation_window_seconds = max(1.0, min(self.window_seconds, now - first_seen + 0.001))

        packet_count = float(len(window))
        byte_count = float(sum(item[1] for item in window))
        unique_destination_ports = float(
            len(set(item[4] for item in window if item[4] is not None))
        )
        unique_destination_ips = float(
            len(set(item[3] for item in window if item[3]))
        )
        connection_attempts = float(sum(1 for item in window if item[6]))
        syn_count = float(sum(1 for item in window if item[5]))
        icmp_count = float(sum(1 for item in window if item[2] == "icmp"))
        udp_count = float(sum(1 for item in window if item[2] == "udp"))
        tcp_count = float(sum(1 for item in window if item[2] == "tcp"))
        failed_count = float(len(failed_window))
        unanswered_count = float(
            len(unanswered_window) + int(self.pending_attempt_counts.get(src_ip, 0))
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

        return {
            "packet_count": packet_count,
            "byte_count": byte_count,
            "unique_destination_ports": unique_destination_ports,
            "unique_destination_ips": unique_destination_ips,
            "destination_port_fanout_ratio": destination_port_fanout_ratio,
            "connection_rate": connection_attempts / observation_window_seconds,
            "syn_rate": syn_count / observation_window_seconds,
            "icmp_rate": icmp_count / observation_window_seconds,
            "udp_rate": udp_count / observation_window_seconds,
            "tcp_rate": tcp_count / observation_window_seconds,
            "average_packet_size": (byte_count / packet_count) if packet_count else 0.0,
            "observation_window_seconds": float(observation_window_seconds),
            "packet_rate": packet_count / observation_window_seconds,
            "bytes_per_second": byte_count / observation_window_seconds,
            "failed_connection_rate": failed_count / observation_window_seconds,
            "unanswered_syn_rate": unanswered_count / observation_window_seconds,
            "unanswered_syn_ratio": unanswered_syn_ratio,
        }

    def _record_failed_connection(self, packet_metadata, now):
        if (
            not packet_metadata.tcp_rst
            or not packet_metadata.src_ip
            or not packet_metadata.dst_ip
            or packet_metadata.src_port is None
            or packet_metadata.dst_port is None
        ):
            return

        attempt_key = (
            packet_metadata.dst_ip,
            packet_metadata.src_ip,
            packet_metadata.dst_port,
            packet_metadata.src_port,
        )
        attempt_data = self.connection_attempts.pop(attempt_key, None)
        if attempt_data is None:
            return
        _, attempt_src_ip = attempt_data
        self._decrement_pending_attempt(attempt_src_ip)

        failed_window = self.failed_windows[packet_metadata.dst_ip]
        failed_window.append(now)
        while failed_window and (now - failed_window[0]) > self.window_seconds:
            failed_window.popleft()

    def _resolve_connection_attempt(self, packet_metadata):
        if (
            packet_metadata is None
            or not getattr(packet_metadata, "is_tcp", packet_metadata.transport_protocol == "tcp")
            or not getattr(packet_metadata, "src_ip", None)
            or not getattr(packet_metadata, "dst_ip", None)
            or packet_metadata.src_port is None
            or packet_metadata.dst_port is None
        ):
            return

        if getattr(packet_metadata, "tcp_syn_only", False):
            return

        attempt_key = (
            packet_metadata.dst_ip,
            packet_metadata.src_ip,
            packet_metadata.dst_port,
            packet_metadata.src_port,
        )
        attempt_data = self.connection_attempts.pop(attempt_key, None)
        if attempt_data is None:
            return
        _, attempt_src_ip = attempt_data
        self._decrement_pending_attempt(attempt_src_ip)

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
                while unanswered_window and (now - unanswered_window[0]) > self.window_seconds:
                    unanswered_window.popleft()

    def _trim_window(self, window, now):
        while window and (now - window[0][0]) > self.window_seconds:
            window.popleft()

    def reset(self):
        self.host_windows.clear()
        self.failed_windows.clear()
        self.unanswered_windows.clear()
        self.connection_attempts.clear()
        self.connection_attempt_queue.clear()
        self.pending_attempt_counts.clear()

    def _decrement_pending_attempt(self, src_ip):
        if not src_ip:
            return
        pending_count = int(self.pending_attempt_counts.get(src_ip, 0))
        if pending_count <= 1:
            self.pending_attempt_counts.pop(src_ip, None)
            return
        self.pending_attempt_counts[src_ip] = pending_count - 1

    @staticmethod
    def _is_connection_attempt(packet_metadata):
        if packet_metadata.transport_protocol == "tcp":
            return packet_metadata.tcp_syn_only
        if packet_metadata.transport_protocol == "udp":
            return packet_metadata.dst_port is not None
        return False


def extract_features(extractor, packet_metadata):
    """Convenience wrapper for the project report and simple scripts."""

    return extractor.observe(packet_metadata)
