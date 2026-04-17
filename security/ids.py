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
        self.unanswered_syn_windows = defaultdict(deque)
        self.connection_attempts = {}
        self.connection_attempt_queue = deque()
        self.alert_cache = {}
        self.alert_windows = defaultdict(deque)

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

        expired_unanswered_sources = self._expire_attempts(now)

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

        host_scan_count = 0
        host_probe_count = 0
        if self._should_track_destination_hosts(packet_metadata):
            host_scan_count, host_probe_count = self._record_destination_host(
                src_ip,
                packet_metadata.dst_ip,
                now,
            )

        port_scan_count = 0
        port_probe_count = 0
        should_track_ports = (
            packet_metadata.transport_protocol == "udp"
            or (
                packet_metadata.transport_protocol == "tcp"
                and packet_metadata.tcp_syn_only
            )
        )
        if should_track_ports and packet_metadata.dst_port is not None:
            port_scan_count, port_probe_count = self._record_destination_port(
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
            else:
                self._record_answered_connection(packet_metadata)

        recon_alert = self._evaluate_probe_patterns(
            packet_metadata=packet_metadata,
            src_ip=src_ip,
            now=now,
            host_scan_count=host_scan_count,
            host_probe_count=host_probe_count,
            port_scan_count=port_scan_count,
            port_probe_count=port_probe_count,
        )
        if recon_alert is not None:
            alerts.append(recon_alert)

        unanswered_sources = set(expired_unanswered_sources)
        if packet_metadata.transport_protocol == "tcp":
            unanswered_sources.add(src_ip)
        for candidate_src_ip in sorted(unanswered_sources):
            unanswered_alert = self._evaluate_unanswered_syn(candidate_src_ip, now)
            if unanswered_alert is not None:
                alerts.append(unanswered_alert)

        return alerts

    def describe_source(self, packet_metadata, alerts=None, forwarding_visibility=None):
        """Return recent threshold context for one source host."""

        if (
            packet_metadata is None
            or not getattr(packet_metadata, "is_ipv4", False)
            or not getattr(packet_metadata, "src_ip", None)
        ):
            return {}

        now = float(packet_metadata.timestamp)
        src_ip = packet_metadata.src_ip
        alerts = list(alerts or [])
        protocol = getattr(packet_metadata, "transport_protocol", "")

        packet_count = self._window_count(
            self.packet_windows[src_ip],
            now,
            self.ids_config.packet_rate_window_seconds,
        )
        syn_count = self._window_count(
            self.syn_windows[src_ip],
            now,
            self.ids_config.syn_rate_window_seconds,
        )
        failed_count = self._window_count(
            self.failed_connection_windows[src_ip],
            now,
            self.ids_config.failed_connection_window_seconds,
        )
        host_scan_count, host_probe_count = self._host_scan_metrics(src_ip, now)
        port_scan_count, port_probe_count = self._port_scan_metrics(src_ip, now)
        unanswered_count, unanswered_hosts, unanswered_ports = self._unanswered_syn_metrics(
            src_ip,
            now,
        )
        recent_alerts = self._recent_alerts(src_ip, now)
        primary_alert = alerts[0] if alerts else (recent_alerts[-1] if recent_alerts else None)
        rule_family = self._rule_family(
            getattr(primary_alert, "alert_type", None) if primary_alert is not None else None,
            getattr(primary_alert, "reason", None) if primary_alert is not None else None,
        )
        port_threshold, probe_threshold = self._port_scan_thresholds(protocol)
        host_threshold = (
            self.ids_config.icmp_sweep_unique_destination_hosts_threshold
            if protocol == "icmp"
            else self.ids_config.unique_destination_hosts_threshold
        )
        host_probe_threshold = (
            self.ids_config.icmp_sweep_probe_threshold
            if protocol == "icmp"
            else host_threshold
        )
        near_port_threshold = (
            port_scan_count >= max(1, int(port_threshold) - 1)
            and port_probe_count >= max(1, int(probe_threshold) - 1)
        )
        near_host_threshold = (
            host_scan_count >= max(1, int(host_threshold) - 1)
            and host_probe_count >= max(1, int(host_probe_threshold) - 1)
        )
        near_unanswered_threshold = unanswered_count >= max(
            1,
            int(self.ids_config.unanswered_syn_threshold) - 1,
        )
        combined_recon_near = (
            host_scan_count >= max(
                1,
                int(self.ids_config.combined_recon_unique_destination_hosts_threshold) - 1,
            )
            and port_scan_count >= max(
                1,
                int(self.ids_config.combined_recon_unique_destination_ports_threshold) - 1,
            )
            and max(host_probe_count, port_probe_count) >= max(
                1,
                int(self.ids_config.combined_recon_probe_threshold) - 1,
            )
        )
        recon_suspicion_score = int(near_port_threshold) + int(near_host_threshold) + int(
            near_unanswered_threshold
        ) + int(combined_recon_near)

        return {
            "threshold_triggered": bool(alerts),
            "threshold_reason": getattr(primary_alert, "reason", "") if primary_alert else "",
            "threshold_rule_family": rule_family,
            "threshold_alert_type": (
                getattr(primary_alert, "alert_type", "") if primary_alert else ""
            ),
            "threshold_severity": (
                getattr(primary_alert, "severity", "") if primary_alert else ""
            ),
            "threshold_recent_event_count": len(recent_alerts),
            "recent_threshold_events": [
                {
                    "alert_type": alert.alert_type,
                    "reason": alert.reason,
                    "severity": alert.severity,
                    "timestamp": alert.timestamp,
                    "rule_family": self._rule_family(alert.alert_type, alert.reason),
                }
                for alert in recent_alerts[-3:]
            ],
            "packet_count": packet_count,
            "syn_count": syn_count,
            "failed_connection_count": failed_count,
            "scan_unique_destination_hosts": host_scan_count,
            "scan_unique_destination_ports": port_scan_count,
            "host_probe_count": host_probe_count,
            "port_probe_count": port_probe_count,
            "unanswered_syn_count": unanswered_count,
            "unanswered_syn_unique_destination_hosts": unanswered_hosts,
            "unanswered_syn_unique_destination_ports": unanswered_ports,
            "recon_suspicious": bool(recon_suspicion_score),
            "recon_suspicion_score": recon_suspicion_score,
            "recon_visible_traffic": forwarding_visibility != "fast_path",
            "forwarding_visibility": forwarding_visibility or "fast_path",
        }

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
            self.connection_attempts[attempt_key] = {
                "timestamp": now,
                "unanswered_recorded": False,
            }
            self.connection_attempt_queue.append((now, attempt_key))

        return len(window)

    def _record_destination_host(self, src_ip, dst_ip, now):
        if not dst_ip:
            return 0, 0

        window = self.host_windows[src_ip]
        window.append((now, dst_ip))
        self._trim_tuple_window(window, now, self.ids_config.scan_window_seconds)
        return len({current_dst_ip for _, current_dst_ip in window}), len(window)

    def _record_destination_port(self, src_ip, dst_ip, dst_port, now):
        window = self.port_windows[src_ip]
        window.append((now, dst_ip, dst_port))
        self._trim_tuple_window(window, now, self.ids_config.scan_window_seconds)
        return len({current_dst_port for _, _, current_dst_port in window}), len(window)

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
        attempt_state = self.connection_attempts.pop(attempt_key, None)
        if attempt_state is None:
            return 0
        if attempt_state.get("unanswered_recorded"):
            return 0

        attempt_timestamp = attempt_state.get("timestamp")

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

    def _record_answered_connection(self, packet_metadata):
        if (
            not packet_metadata.src_ip
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
        self.connection_attempts.pop(attempt_key, None)

    def _record_unanswered_syn(self, src_ip, dst_ip, dst_port, now):
        window = self.unanswered_syn_windows[src_ip]
        window.append((now, dst_ip, dst_port))
        self._trim_tuple_window(window, now, self.ids_config.unanswered_syn_window_seconds)
        return self._unanswered_syn_metrics(src_ip, now)

    def _evaluate_probe_patterns(
        self,
        packet_metadata,
        src_ip,
        now,
        host_scan_count,
        host_probe_count,
        port_scan_count,
        port_probe_count,
    ):
        protocol = packet_metadata.transport_protocol

        if protocol == "icmp":
            if (
                host_scan_count >= self.ids_config.icmp_sweep_unique_destination_hosts_threshold
                and host_probe_count >= self.ids_config.icmp_sweep_probe_threshold
            ):
                return self._build_alert(
                    alert_type="host_scan_detected",
                    src_ip=src_ip,
                    now=now,
                    reason="icmp_sweep_threshold_exceeded",
                    details={
                        "unique_destination_hosts": host_scan_count,
                        "probe_count": host_probe_count,
                        "window_seconds": self.ids_config.scan_window_seconds,
                    },
                )
            return None

        if protocol in ("tcp", "udp"):
            port_threshold, probe_threshold = self._port_scan_thresholds(protocol)
            if (
                port_scan_count >= port_threshold
                and port_probe_count >= probe_threshold
            ):
                return self._build_alert(
                    alert_type="port_scan_detected",
                    src_ip=src_ip,
                    now=now,
                    reason="%s_scan_threshold_exceeded" % protocol,
                    details={
                        "unique_destination_ports": port_scan_count,
                        "probe_count": port_probe_count,
                        "window_seconds": self.ids_config.scan_window_seconds,
                    },
                )

            if (
                host_scan_count >= self.ids_config.unique_destination_hosts_threshold
                and host_probe_count >= self.ids_config.unique_destination_hosts_threshold
            ):
                return self._build_alert(
                    alert_type="host_scan_detected",
                    src_ip=src_ip,
                    now=now,
                    reason="%s_host_scan_threshold_exceeded" % protocol,
                    details={
                        "unique_destination_hosts": host_scan_count,
                        "probe_count": host_probe_count,
                        "window_seconds": self.ids_config.scan_window_seconds,
                    },
                )

            if (
                host_scan_count >= self.ids_config.combined_recon_unique_destination_hosts_threshold
                and port_scan_count >= self.ids_config.combined_recon_unique_destination_ports_threshold
                and max(host_probe_count, port_probe_count)
                >= self.ids_config.combined_recon_probe_threshold
            ):
                return self._build_alert(
                    alert_type="port_scan_detected",
                    src_ip=src_ip,
                    now=now,
                    reason="combined_recon_threshold_exceeded",
                    details={
                        "unique_destination_hosts": host_scan_count,
                        "unique_destination_ports": port_scan_count,
                        "probe_count": max(host_probe_count, port_probe_count),
                        "window_seconds": self.ids_config.scan_window_seconds,
                    },
                )

        return None

    def _evaluate_unanswered_syn(self, src_ip, now):
        unanswered_count, unique_hosts, unique_ports = self._unanswered_syn_metrics(
            src_ip,
            now,
        )
        if unanswered_count < self.ids_config.unanswered_syn_threshold:
            return None

        if unique_hosts >= self.ids_config.combined_recon_unique_destination_hosts_threshold:
            alert_type = "host_scan_detected"
            reason = "unanswered_syn_host_scan_threshold_exceeded"
        else:
            alert_type = "port_scan_detected"
            reason = "unanswered_syn_threshold_exceeded"

        return self._build_alert(
            alert_type=alert_type,
            src_ip=src_ip,
            now=now,
            reason=reason,
            details={
                "unanswered_syn_count": unanswered_count,
                "unique_destination_hosts": unique_hosts,
                "unique_destination_ports": unique_ports,
                "window_seconds": self.ids_config.unanswered_syn_window_seconds,
            },
        )

    def _unanswered_syn_metrics(self, src_ip, now):
        window = self.unanswered_syn_windows[src_ip]
        self._trim_tuple_window(window, now, self.ids_config.unanswered_syn_window_seconds)
        return (
            len(window),
            len({dst_ip for _, dst_ip, _ in window if dst_ip}),
            len({dst_port for _, _, dst_port in window if dst_port is not None}),
        )

    @staticmethod
    def _should_track_destination_hosts(packet_metadata):
        if packet_metadata.transport_protocol == "udp":
            return True
        if packet_metadata.transport_protocol == "tcp":
            return bool(packet_metadata.tcp_syn_only)
        return bool(
            packet_metadata.is_icmp
            and packet_metadata.icmp_type in (8, 13, 15, 17)
        )

    def _port_scan_thresholds(self, protocol):
        if protocol == "udp":
            return (
                self.ids_config.udp_scan_unique_destination_ports_threshold,
                self.ids_config.udp_scan_probe_threshold,
            )
        return (
            self.ids_config.tcp_scan_unique_destination_ports_threshold,
            self.ids_config.tcp_scan_probe_threshold,
        )

    def _build_alert(self, alert_type, src_ip, now, reason, details):
        cache_key = (alert_type, src_ip)
        previous_alert = self.alert_cache.get(cache_key)
        if previous_alert is not None:
            if (now - previous_alert) < self.ids_config.alert_suppression_seconds:
                return None

        self.alert_cache[cache_key] = now
        alert = IDSAlert(
            alert_type=alert_type,
            src_ip=src_ip,
            reason=reason,
            timestamp=now,
            details=details,
        )
        alert_window = self.alert_windows[src_ip]
        alert_window.append(alert)
        self._trim_alert_window(alert_window, now)
        return alert

    def _expire_attempts(self, now):
        unanswered_sources = set()
        unanswered_cutoff = now - self.ids_config.unanswered_syn_timeout_seconds
        for timestamp, attempt_key in self.connection_attempt_queue:
            if timestamp > unanswered_cutoff:
                break
            attempt_state = self.connection_attempts.get(attempt_key)
            if attempt_state is None or attempt_state.get("unanswered_recorded"):
                continue
            src_ip, dst_ip, _, dst_port = attempt_key
            self._record_unanswered_syn(src_ip, dst_ip, dst_port, now)
            attempt_state["unanswered_recorded"] = True
            unanswered_sources.add(src_ip)

        max_age = max(
            self.ids_config.connection_attempt_window_seconds,
            self.ids_config.unanswered_syn_timeout_seconds,
        )
        while self.connection_attempt_queue:
            timestamp, attempt_key = self.connection_attempt_queue[0]
            if (now - timestamp) <= max_age:
                break
            self.connection_attempt_queue.popleft()
            attempt_state = self.connection_attempts.get(attempt_key)
            if attempt_state is not None and attempt_state.get("timestamp") == timestamp:
                del self.connection_attempts[attempt_key]

        return unanswered_sources

    @staticmethod
    def _trim_time_window(window, now, window_seconds):
        while window and (now - window[0]) > window_seconds:
            window.popleft()

    @staticmethod
    def _trim_tuple_window(window, now, window_seconds):
        while window and (now - window[0][0]) > window_seconds:
            window.popleft()

    def _trim_alert_window(self, window, now):
        retention_seconds = max(
            self.ids_config.alert_suppression_seconds,
            self.ids_config.scan_window_seconds,
            self.ids_config.failed_connection_window_seconds,
            self.ids_config.unanswered_syn_window_seconds,
            self.ids_config.packet_rate_window_seconds,
            self.ids_config.syn_rate_window_seconds,
        )
        while window and (now - window[0].timestamp) > retention_seconds:
            window.popleft()

    def _recent_alerts(self, src_ip, now):
        window = self.alert_windows[src_ip]
        self._trim_alert_window(window, now)
        return list(window)

    def _host_scan_metrics(self, src_ip, now):
        window = self.host_windows[src_ip]
        self._trim_tuple_window(window, now, self.ids_config.scan_window_seconds)
        return len({dst_ip for _, dst_ip in window if dst_ip}), len(window)

    def _port_scan_metrics(self, src_ip, now):
        window = self.port_windows[src_ip]
        self._trim_tuple_window(window, now, self.ids_config.scan_window_seconds)
        return len({dst_port for _, _, dst_port in window if dst_port is not None}), len(window)

    @staticmethod
    def _window_count(window, now, window_seconds):
        ThresholdIDS._trim_time_window(window, now, window_seconds)
        return len(window)

    @staticmethod
    def _rule_family(alert_type, reason):
        alert_text = "%s %s" % (alert_type or "", reason or "")
        normalized = alert_text.strip().lower()
        if any(token in normalized for token in ("scan", "sweep", "unanswered_syn", "failed_connection")):
            return "recon"
        if any(token in normalized for token in ("flood", "packet_rate", "syn_rate")):
            return "volumetric"
        if normalized:
            return "suspicious"
        return ""
