"""Threshold-based IDS for scans, floods, and suspicious connection failures."""

from collections import defaultdict, deque
from dataclasses import dataclass, field
import time


@dataclass
class IDSAlert(object):
    """Normalized IDS alert used by mitigation and logging layers."""

    alert_type: str
    src_ip: str
    reason: str
    detector: str = "threshold"
    severity: str = "high"
    timestamp: float = field(default_factory=time.time)
    details: dict = field(default_factory=dict)

    def to_dict(self):
        payload = {
            "alert_type": self.alert_type,
            "src_ip": self.src_ip,
            "reason": self.reason,
            "detector": self.detector,
            "severity": self.severity,
            "timestamp": self.timestamp,
        }
        payload.update(self.details)
        return payload


class ThresholdIDS(object):
    """Detect suspicious traffic with lightweight sliding windows."""

    def __init__(self, ids_config):
        self.ids_config = ids_config
        self.packet_windows = defaultdict(deque)
        self.syn_windows = defaultdict(deque)
        self.host_windows = defaultdict(deque)
        self.port_windows = defaultdict(deque)
        self.failed_connection_windows = defaultdict(deque)
        self.connection_attempts = {}
        self.connection_attempt_queue = deque()
        self.alert_cache = {}

    def inspect(self, packet_metadata):
        """Inspect one packet and return a list of threshold alerts."""

        if (
            not self.ids_config.enabled
            or not packet_metadata.is_ipv4
            or not packet_metadata.src_ip
        ):
            return []

        now = packet_metadata.timestamp
        src_ip = packet_metadata.src_ip
        alerts = []

        self._expire_attempts(now)

        packet_count = self._record_packet_count(src_ip, now)
        if packet_count >= self.ids_config.packet_rate_threshold:
            alert = self._build_alert(
                alert_type="packet_flood_detected",
                src_ip=src_ip,
                now=now,
                reason="packet_rate_threshold_exceeded",
                details={
                    "packet_count": packet_count,
                    "window_seconds": self.ids_config.packet_rate_window_seconds,
                },
            )
            if alert is not None:
                alerts.append(alert)

        host_scan_count = self._record_destination_host(src_ip, packet_metadata.dst_ip, now)
        if host_scan_count >= self.ids_config.unique_destination_hosts_threshold:
            alert = self._build_alert(
                alert_type="host_scan_detected",
                src_ip=src_ip,
                now=now,
                reason="unique_destination_hosts_threshold_exceeded",
                details={
                    "unique_destination_hosts": host_scan_count,
                    "window_seconds": self.ids_config.scan_window_seconds,
                },
            )
            if alert is not None:
                alerts.append(alert)

        should_track_ports = (
            packet_metadata.transport_protocol == "udp"
            or (
                packet_metadata.transport_protocol == "tcp"
                and packet_metadata.tcp_syn_only
            )
        )
        if should_track_ports and packet_metadata.dst_port is not None:
            port_scan_count = self._record_destination_port(
                src_ip,
                packet_metadata.dst_ip,
                packet_metadata.dst_port,
                now,
            )
            if port_scan_count >= self.ids_config.unique_destination_ports_threshold:
                alert = self._build_alert(
                    alert_type="port_scan_detected",
                    src_ip=src_ip,
                    now=now,
                    reason="unique_destination_ports_threshold_exceeded",
                    details={
                        "unique_destination_ports": port_scan_count,
                        "window_seconds": self.ids_config.scan_window_seconds,
                    },
                )
                if alert is not None:
                    alerts.append(alert)

        if packet_metadata.transport_protocol == "tcp":
            if packet_metadata.tcp_syn_only:
                syn_count = self._record_syn_attempt(packet_metadata, now)
                if syn_count >= self.ids_config.syn_rate_threshold:
                    alert = self._build_alert(
                        alert_type="syn_flood_detected",
                        src_ip=src_ip,
                        now=now,
                        reason="syn_rate_threshold_exceeded",
                        details={
                            "syn_count": syn_count,
                            "window_seconds": self.ids_config.syn_rate_window_seconds,
                        },
                    )
                    if alert is not None:
                        alerts.append(alert)

            if packet_metadata.tcp_rst:
                failed_count = self._record_failed_connection(packet_metadata, now)
                if failed_count >= self.ids_config.failed_connection_threshold:
                    alert = self._build_alert(
                        alert_type="failed_connection_rate_exceeded",
                        src_ip=packet_metadata.dst_ip,
                        now=now,
                        reason="failed_connection_threshold_exceeded",
                        details={
                            "failed_connection_count": failed_count,
                            "window_seconds": (
                                self.ids_config.failed_connection_window_seconds
                            ),
                        },
                    )
                    if alert is not None:
                        alerts.append(alert)

        return alerts

    def _record_packet_count(self, src_ip, now):
        window = self.packet_windows[src_ip]
        window.append(now)
        self._trim_time_window(window, now, self.ids_config.packet_rate_window_seconds)
        return len(window)

    def _record_syn_attempt(self, packet_metadata, now):
        src_ip = packet_metadata.src_ip
        window = self.syn_windows[src_ip]
        window.append(now)
        self._trim_time_window(window, now, self.ids_config.syn_rate_window_seconds)

        if packet_metadata.dst_ip and packet_metadata.src_port is not None and packet_metadata.dst_port is not None:
            attempt_key = (
                packet_metadata.src_ip,
                packet_metadata.dst_ip,
                packet_metadata.src_port,
                packet_metadata.dst_port,
            )
            self.connection_attempts[attempt_key] = now
            self.connection_attempt_queue.append((now, attempt_key))

        return len(window)

    def _record_destination_host(self, src_ip, dst_ip, now):
        if not dst_ip:
            return 0

        window = self.host_windows[src_ip]
        window.append((now, dst_ip))
        self._trim_tuple_window(window, now, self.ids_config.scan_window_seconds)
        return len({current_dst_ip for _, current_dst_ip in window})

    def _record_destination_port(self, src_ip, dst_ip, dst_port, now):
        window = self.port_windows[src_ip]
        window.append((now, dst_ip, dst_port))
        self._trim_tuple_window(window, now, self.ids_config.scan_window_seconds)
        return len({current_dst_port for _, _, current_dst_port in window})

    def _record_failed_connection(self, packet_metadata, now):
        if (
            not packet_metadata.src_ip
            or not packet_metadata.dst_ip
            or packet_metadata.src_port is None
            or packet_metadata.dst_port is None
        ):
            return 0

        attempt_key = (
            packet_metadata.dst_ip,
            packet_metadata.src_ip,
            packet_metadata.dst_port,
            packet_metadata.src_port,
        )
        attempt_timestamp = self.connection_attempts.pop(attempt_key, None)
        if attempt_timestamp is None:
            return 0

        if (
            now - attempt_timestamp
            > self.ids_config.connection_attempt_window_seconds
        ):
            return 0

        src_ip = packet_metadata.dst_ip
        window = self.failed_connection_windows[src_ip]
        window.append(now)
        self._trim_time_window(
            window,
            now,
            self.ids_config.failed_connection_window_seconds,
        )
        return len(window)

    def _build_alert(self, alert_type, src_ip, now, reason, details):
        cache_key = (alert_type, src_ip)
        previous_alert = self.alert_cache.get(cache_key)
        if previous_alert is not None:
            if (now - previous_alert) < self.ids_config.alert_suppression_seconds:
                return None

        self.alert_cache[cache_key] = now
        return IDSAlert(
            alert_type=alert_type,
            src_ip=src_ip,
            reason=reason,
            timestamp=now,
            details=details,
        )

    def _expire_attempts(self, now):
        max_age = self.ids_config.connection_attempt_window_seconds
        while self.connection_attempt_queue:
            timestamp, attempt_key = self.connection_attempt_queue[0]
            if (now - timestamp) <= max_age:
                break
            self.connection_attempt_queue.popleft()
            if self.connection_attempts.get(attempt_key) == timestamp:
                del self.connection_attempts[attempt_key]

    @staticmethod
    def _trim_time_window(window, now, window_seconds):
        while window and (now - window[0]) > window_seconds:
            window.popleft()

    @staticmethod
    def _trim_tuple_window(window, now, window_seconds):
        while window and (now - window[0][0]) > window_seconds:
            window.popleft()
