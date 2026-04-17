"""Lightweight controller, host, and flow counters for IDS support."""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import time


@dataclass
class HostStats(object):
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    alert_count: int = 0
    ml_alert_count: int = 0
    threshold_alert_count: int = 0
    block_count: int = 0
    last_seen: float = 0.0


@dataclass
class FlowStats(object):
    src_ip: str
    dst_ip: str
    protocol: str
    dst_port: int = None
    packet_count: int = 0
    byte_count: int = 0
    last_seen: float = 0.0


class MetricsStore(object):
    """Maintain low-cost counters for packets, alerts, and mitigations."""

    def __init__(self, max_recent_events=200, max_tracked_hosts=256, max_tracked_flows=1024):
        self.max_recent_events = max_recent_events
        self.max_tracked_hosts = max_tracked_hosts
        self.max_tracked_flows = max_tracked_flows
        self.total_packets = 0
        self.total_bytes = 0
        self.alerts_total = 0
        self.threshold_alerts_total = 0
        self.ml_alerts_total = 0
        self.hybrid_agreements_total = 0
        self.hybrid_disagreements_total = 0
        self.threshold_only_detections_total = 0
        self.ml_only_detections_total = 0
        self.hybrid_correlated_total = 0
        self.blocks_total = 0
        self.threshold_blocks_total = 0
        self.ml_blocks_total = 0
        self.manual_unblocks_total = 0
        self.capture_snapshots_saved_total = 0
        self.alert_capture_correlations_total = 0
        self.flow_installs_total = 0
        self.flow_removals_total = 0
        self.controller_events_total = 0
        self.ml_predictions_total = 0
        self.ml_malicious_predictions_total = 0
        self.ml_benign_predictions_total = 0
        self.packets_by_protocol = {}
        self.controller_events_by_type = {}
        self.flow_events_by_reason = {}
        self.host_stats = {}
        self.flow_stats = {}
        self.active_flow_keys = set()
        self.active_security_flow_keys = set()
        self.recent_events = deque(maxlen=max_recent_events)
        self.recent_ml_predictions = deque(maxlen=max_recent_events)
        self.recent_hybrid_events = deque(maxlen=max_recent_events)
        self.latest_capture_snapshot = None
        self.started_at = time.time()

    def record_packet(self, packet_metadata):
        """Update controller-wide, host, and flow counters for one packet."""

        self.total_packets += 1
        self.total_bytes += packet_metadata.packet_length

        protocol = packet_metadata.protocol_label()
        self.packets_by_protocol[protocol] = self.packets_by_protocol.get(protocol, 0) + 1

        if packet_metadata.src_ip:
            host_stats = self._host_stats(packet_metadata.src_ip, packet_metadata.timestamp)
            host_stats.packet_count += 1
            host_stats.byte_count += packet_metadata.packet_length
            if packet_metadata.tcp_syn_only:
                host_stats.syn_count += 1
            if packet_metadata.tcp_rst:
                host_stats.rst_count += 1

        flow_key = self._flow_key(packet_metadata)
        if flow_key is not None:
            flow_stats = self._flow_stats(flow_key, packet_metadata)
            flow_stats.packet_count += 1
            flow_stats.byte_count += packet_metadata.packet_length
            flow_stats.last_seen = packet_metadata.timestamp

    def record_alert(self, alert, source=None, related_capture=None, quarantine_status=None):
        """Record one IDS or ML alert."""

        detector = (source or getattr(alert, "detector", "threshold")).strip().lower()
        details = alert.to_dict()

        self.alerts_total += 1
        if detector == "ml":
            self.ml_alerts_total += 1
        else:
            self.threshold_alerts_total += 1

        if alert.src_ip:
            host_stats = self._host_stats(alert.src_ip, alert.timestamp)
            host_stats.alert_count += 1
            if detector == "ml":
                host_stats.ml_alert_count += 1
            else:
                host_stats.threshold_alert_count += 1

        payload = {"detector": detector}
        payload.update(details)
        if related_capture:
            self.alert_capture_correlations_total += 1
            payload["related_capture"] = dict(related_capture)
        if quarantine_status:
            payload["quarantine_status"] = quarantine_status
        event_category = "ml_alert" if detector == "ml" else "ids_alert"
        self.append_event(event_category, payload)

    def record_hybrid_correlation(self, correlation_event):
        if correlation_event is None:
            return

        status = correlation_event.status
        if status in (
            "agreement",
            "threshold_plus_ml",
            "threshold_enriched_by_ml",
            "known_class_match",
        ):
            self.hybrid_agreements_total += 1
            self.hybrid_correlated_total += 1
        elif status == "disagreement":
            self.hybrid_disagreements_total += 1
            self.hybrid_correlated_total += 1
        elif status == "threshold_only":
            self.threshold_only_detections_total += 1
        elif status in ("ml_only", "anomaly_only"):
            self.ml_only_detections_total += 1

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": "hybrid_correlation",
            "src_ip": correlation_event.src_ip,
            "status": status,
            "reason": correlation_event.reason,
            "correlation_window_seconds": correlation_event.correlation_window_seconds,
            "threshold_timestamp": correlation_event.threshold_timestamp,
            "ml_timestamp": correlation_event.ml_timestamp,
            "confidence": correlation_event.confidence,
            "suspicion_score": correlation_event.suspicion_score,
        }
        self.recent_hybrid_events.appendleft(event)
        self.recent_events.appendleft(dict(event))

    def record_quarantine(
        self,
        src_ip,
        reason,
        status,
        alert_type=None,
        source=None,
        related_capture=None,
    ):
        """Record one quarantine decision."""

        detector = (source or "threshold").strip().lower()
        is_new_or_extended = status != "duplicate"

        if is_new_or_extended:
            self.blocks_total += 1
            if detector == "ml":
                self.ml_blocks_total += 1
            else:
                self.threshold_blocks_total += 1
            if src_ip:
                self._host_stats(src_ip, time.time()).block_count += 1

        self.append_event(
            "mitigation",
            {
                "src_ip": src_ip,
                "reason": reason,
                "status": status,
                "alert_type": alert_type,
                "detector": detector,
                "related_capture": dict(related_capture or {}),
            },
        )

    def record_block(self, src_ip, reason, expires_at, status, alert_type=None, source=None):
        """Backward-compatible wrapper for older temporary-block code paths."""

        self.record_quarantine(
            src_ip=src_ip,
            reason=reason,
            status=status,
            alert_type=alert_type,
            source=source,
        )

    def record_block_expired(self, src_ip, reason):
        """Backward-compatible no-op event kept for older callers."""
        self.append_event(
            "mitigation_expired",
            {
                "src_ip": src_ip,
                "reason": reason,
            },
        )

    def record_manual_unblock(
        self,
        src_ip,
        reason,
        detector=None,
        released_by="dashboard",
        related_capture=None,
    ):
        self.manual_unblocks_total += 1
        self.append_event(
            "manual_unblock",
            {
                "src_ip": src_ip,
                "reason": reason,
                "detector": detector or "threshold",
                "released_by": released_by,
                "related_capture": dict(related_capture or {}),
            },
        )

    def record_capture_snapshot(self, snapshot_metadata):
        if not snapshot_metadata:
            return
        self.capture_snapshots_saved_total += 1
        self.latest_capture_snapshot = dict(snapshot_metadata)
        self.append_event(
            "capture_snapshot",
            dict(snapshot_metadata),
        )

    def record_controller_event(self, event_type, details):
        self.controller_events_total += 1
        self.controller_events_by_type[event_type] = (
            self.controller_events_by_type.get(event_type, 0) + 1
        )
        payload = {"event_type": event_type}
        payload.update(details)
        self.append_event("controller", payload)

    def record_flow_event(self, action, details):
        flow_key = self._flow_event_key(details)
        is_security_flow = self._is_security_flow(details)

        if action == "flow_rule_removed":
            self.flow_removals_total += 1
            if flow_key in self.active_flow_keys:
                self.active_flow_keys.discard(flow_key)
            if flow_key in self.active_security_flow_keys:
                self.active_security_flow_keys.discard(flow_key)
        else:
            self.flow_installs_total += 1
            if flow_key is not None:
                self.active_flow_keys.add(flow_key)
                if is_security_flow:
                    self.active_security_flow_keys.add(flow_key)

        reason = details.get("reason") or "unspecified"
        self.flow_events_by_reason[reason] = self.flow_events_by_reason.get(reason, 0) + 1

        payload = {"event_type": action}
        payload.update(details)
        payload["security_flow"] = is_security_flow
        self.append_event("flow", payload)

    def record_ml_prediction(self, prediction):
        if prediction is None:
            return

        self.ml_predictions_total += 1
        if prediction.is_malicious:
            self.ml_malicious_predictions_total += 1
        else:
            self.ml_benign_predictions_total += 1

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": prediction.src_ip,
            "label": prediction.label,
            "reason": prediction.reason,
            "confidence": round(float(prediction.confidence), 6),
            "suspicion_score": round(float(prediction.suspicion_score), 6),
            "is_malicious": bool(prediction.is_malicious),
            "model_name": prediction.model_name,
        }
        self.recent_ml_predictions.appendleft(event)

    def append_event(self, category, details):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": category,
        }
        event.update(details)
        self.recent_events.appendleft(event)

    def recent_events_list(self):
        return list(self.recent_events)

    def recent_ml_predictions_list(self):
        return list(self.recent_ml_predictions)

    def recent_hybrid_events_list(self):
        return list(self.recent_hybrid_events)

    def snapshot(self, active_blocks=0, active_switches=0, active_hosts=0, ml_mode="threshold_only"):
        top_sources = sorted(
            self.host_stats.items(),
            key=lambda item: item[1].packet_count,
            reverse=True,
        )
        return {
            "uptime_seconds": int(time.time() - self.started_at),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "alerts_total": self.alerts_total,
            "threshold_alerts_total": self.threshold_alerts_total,
            "ml_alerts_total": self.ml_alerts_total,
            "hybrid_agreements_total": self.hybrid_agreements_total,
            "hybrid_disagreements_total": self.hybrid_disagreements_total,
            "hybrid_correlated_total": self.hybrid_correlated_total,
            "threshold_only_detections_total": self.threshold_only_detections_total,
            "ml_only_detections_total": self.ml_only_detections_total,
            "blocks_total": self.blocks_total,
            "threshold_blocks_total": self.threshold_blocks_total,
            "ml_blocks_total": self.ml_blocks_total,
            "manual_unblocks_total": self.manual_unblocks_total,
            "capture_snapshots_saved_total": self.capture_snapshots_saved_total,
            "alert_capture_correlations_total": self.alert_capture_correlations_total,
            "flow_installs_total": self.flow_installs_total,
            "flow_removals_total": self.flow_removals_total,
            "active_flows_total": len(self.active_flow_keys),
            "active_security_flows_total": len(self.active_security_flow_keys),
            "controller_events_total": self.controller_events_total,
            "ml_predictions_total": self.ml_predictions_total,
            "ml_malicious_predictions_total": self.ml_malicious_predictions_total,
            "ml_benign_predictions_total": self.ml_benign_predictions_total,
            "active_blocks": active_blocks,
            "active_quarantines": active_blocks,
            "active_switches": active_switches,
            "active_hosts": active_hosts,
            "ml_mode": ml_mode,
            "packets_by_protocol": dict(self.packets_by_protocol),
            "controller_events_by_type": dict(self.controller_events_by_type),
            "flow_events_by_reason": dict(self.flow_events_by_reason),
            "latest_capture_snapshot": dict(self.latest_capture_snapshot or {}),
            "top_sources": [
                {
                    "src_ip": src_ip,
                    "packet_count": host_stats.packet_count,
                    "byte_count": host_stats.byte_count,
                    "alert_count": host_stats.alert_count,
                    "ml_alert_count": host_stats.ml_alert_count,
                    "threshold_alert_count": host_stats.threshold_alert_count,
                    "block_count": host_stats.block_count,
                }
                for src_ip, host_stats in top_sources[:5]
            ],
        }

    def reset_runtime_session(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.alerts_total = 0
        self.threshold_alerts_total = 0
        self.ml_alerts_total = 0
        self.hybrid_agreements_total = 0
        self.hybrid_disagreements_total = 0
        self.threshold_only_detections_total = 0
        self.ml_only_detections_total = 0
        self.hybrid_correlated_total = 0
        self.blocks_total = 0
        self.threshold_blocks_total = 0
        self.ml_blocks_total = 0
        self.manual_unblocks_total = 0
        self.capture_snapshots_saved_total = 0
        self.alert_capture_correlations_total = 0
        self.flow_installs_total = 0
        self.flow_removals_total = 0
        self.controller_events_total = 0
        self.ml_predictions_total = 0
        self.ml_malicious_predictions_total = 0
        self.ml_benign_predictions_total = 0
        self.packets_by_protocol.clear()
        self.controller_events_by_type.clear()
        self.flow_events_by_reason.clear()
        self.host_stats.clear()
        self.flow_stats.clear()
        self.active_flow_keys.clear()
        self.active_security_flow_keys.clear()
        self.recent_events.clear()
        self.recent_ml_predictions.clear()
        self.recent_hybrid_events.clear()
        self.latest_capture_snapshot = None
        self.started_at = time.time()

    def _host_stats(self, src_ip, timestamp):
        if src_ip not in self.host_stats and len(self.host_stats) >= self.max_tracked_hosts:
            self._prune_oldest_host()

        stats = self.host_stats.setdefault(src_ip, HostStats())
        stats.last_seen = timestamp
        return stats

    def _flow_stats(self, flow_key, packet_metadata):
        if flow_key not in self.flow_stats and len(self.flow_stats) >= self.max_tracked_flows:
            self._prune_oldest_flow()

        stats = self.flow_stats.get(flow_key)
        if stats is None:
            stats = FlowStats(
                src_ip=packet_metadata.src_ip,
                dst_ip=packet_metadata.dst_ip,
                protocol=packet_metadata.protocol_label(),
                dst_port=packet_metadata.dst_port,
            )
            self.flow_stats[flow_key] = stats
        return stats

    def _prune_oldest_host(self):
        oldest_key = min(
            self.host_stats,
            key=lambda key: self.host_stats[key].last_seen,
        )
        del self.host_stats[oldest_key]

    def _prune_oldest_flow(self):
        oldest_key = min(
            self.flow_stats,
            key=lambda key: self.flow_stats[key].last_seen,
        )
        del self.flow_stats[oldest_key]

    @staticmethod
    def _flow_key(packet_metadata):
        if not packet_metadata.src_ip or not packet_metadata.dst_ip:
            return None
        return (
            packet_metadata.src_ip,
            packet_metadata.dst_ip,
            packet_metadata.protocol_label(),
            packet_metadata.dst_port,
        )

    @staticmethod
    def _flow_event_key(details):
        dpid = details.get("dpid")
        priority = details.get("priority")
        match = details.get("match")
        if not dpid or match is None:
            return None
        return (dpid, priority, match)

    @staticmethod
    def _is_security_flow(details):
        reason = (details.get("reason") or "").lower()
        priority = details.get("priority")
        if priority is not None:
            try:
                if int(priority) >= 220:
                    return True
            except (TypeError, ValueError):
                pass
        security_prefixes = (
            "ids_",
            "ml_",
            "temporary_",
            "restricted_",
            "static_",
            "exact_packet_block",
            "source_ip_block",
            "source_arp_block",
        )
        return reason.startswith(security_prefixes)
