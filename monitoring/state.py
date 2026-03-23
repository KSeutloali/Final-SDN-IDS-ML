"""Shared dashboard state snapshot writer, reader, and web adapter."""

from collections import deque
from datetime import datetime, timezone
import json
from pathlib import Path
from threading import Lock
import time

from core.ids_mode import ids_mode_label, ids_mode_options, normalize_ids_mode_public


def _utc_label(timestamp_value):
    return datetime.fromtimestamp(timestamp_value, timezone.utc).strftime("%H:%M:%S")


def _utc_iso(timestamp_value):
    return datetime.fromtimestamp(timestamp_value, timezone.utc).isoformat()


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _human_bytes(size_bytes):
    size_value = float(size_bytes or 0)
    units = ("B", "KB", "MB", "GB", "TB")
    unit_index = 0
    while size_value >= 1024.0 and unit_index < (len(units) - 1):
        size_value /= 1024.0
        unit_index += 1
    if unit_index == 0:
        return "%d %s" % (int(size_value), units[unit_index])
    return "%.1f %s" % (size_value, units[unit_index])


def _format_rate(value, suffix):
    numeric_value = _safe_float(value)
    if numeric_value >= 100:
        return "%.0f %s" % (numeric_value, suffix)
    if numeric_value >= 10:
        return "%.1f %s" % (numeric_value, suffix)
    return "%.2f %s" % (numeric_value, suffix)


def empty_dashboard_state():
    now = time.time()
    return {
        "generated_at": _utc_iso(now),
        "generated_at_epoch": now,
        "summary": {
            "uptime_seconds": 0,
            "total_packets": 0,
            "total_bytes": 0,
            "alerts_total": 0,
            "threshold_alerts_total": 0,
            "ml_alerts_total": 0,
            "hybrid_agreements_total": 0,
            "hybrid_disagreements_total": 0,
            "hybrid_correlated_total": 0,
            "threshold_only_detections_total": 0,
            "ml_only_detections_total": 0,
            "blocks_total": 0,
            "threshold_blocks_total": 0,
            "ml_blocks_total": 0,
            "manual_unblocks_total": 0,
            "capture_snapshots_saved_total": 0,
            "alert_capture_correlations_total": 0,
            "flow_installs_total": 0,
            "flow_removals_total": 0,
            "active_flows_total": 0,
            "active_security_flows_total": 0,
            "controller_events_total": 0,
            "ml_predictions_total": 0,
            "ml_malicious_predictions_total": 0,
            "ml_benign_predictions_total": 0,
            "active_blocks": 0,
            "active_quarantines": 0,
            "active_threshold_blocks": 0,
            "active_ml_blocks": 0,
            "active_switches": 0,
            "active_hosts": 0,
            "ml_mode": "threshold_only",
            "packets_by_protocol": {},
            "controller_events_by_type": {},
            "flow_events_by_reason": {},
            "latest_capture_snapshot": {},
            "top_sources": [],
        },
        "switches": [],
        "learned_hosts": [],
        "blocked_hosts": [],
        "recent_events": [],
        "recent_security_events": [],
        "recent_ml_predictions": [],
        "recent_hybrid_events": [],
        "ml_status": {
            "configured_mode": "threshold_only",
            "configured_mode_api": "threshold",
            "configured_mode_label": "Threshold IDS",
            "selected_mode": "threshold_only",
            "selected_mode_api": "threshold",
            "selected_mode_label": "Threshold IDS",
            "effective_mode": "threshold_only",
            "effective_mode_api": "threshold",
            "effective_mode_label": "Threshold IDS",
            "hybrid_policy": "alert_only",
            "model_available": False,
            "model_path": "",
            "model_error": None,
            "available_modes": ids_mode_options(),
        },
        "config": {},
        "timeseries": [],
    }


class DashboardStateWriter(object):
    """Persist controller monitoring data to a shared JSON file."""

    def __init__(self, dashboard_config):
        self.dashboard_config = dashboard_config
        self.state_file_path = Path(dashboard_config.state_file_path)
        self.state_file_path.parent.mkdir(parents=True, exist_ok=True)
        self.persist_interval_seconds = dashboard_config.persist_interval_seconds
        self.timeseries_points = dashboard_config.timeseries_points
        self._lock = Lock()
        self._last_persist_at = 0.0
        self._timeseries = deque(maxlen=self.timeseries_points)
        self._restore_existing_payload()
        if not self.state_file_path.exists():
            self._persist_payload(empty_dashboard_state())

    def publish(
        self,
        metrics,
        controller_state,
        firewall,
        force=False,
        ml_mode="threshold_only",
        ml_status=None,
        config_snapshot=None,
    ):
        """Write a new dashboard snapshot if the throttle window allows it."""

        now = time.time()
        with self._lock:
            if not force and (now - self._last_persist_at) < self.persist_interval_seconds:
                return None

            payload = self._build_payload(
                metrics,
                controller_state,
                firewall,
                now,
                ml_mode=ml_mode,
                ml_status=ml_status,
                config_snapshot=config_snapshot,
            )
            self._append_timeseries(payload["summary"], now)
            payload["timeseries"] = list(self._timeseries)

            self._persist_payload(payload)
            self._last_persist_at = now
            return payload

    def _build_payload(
        self,
        metrics,
        controller_state,
        firewall,
        now,
        ml_mode,
        ml_status,
        config_snapshot,
    ):
        active_switches = len(controller_state.datapaths)
        active_hosts = len(controller_state.hosts)
        active_blocks = len(firewall.quarantined_hosts)
        active_threshold_blocks, active_ml_blocks = self._blocked_detector_counts(firewall)
        summary = metrics.snapshot(
            active_blocks=active_blocks,
            active_switches=active_switches,
            active_hosts=active_hosts,
            ml_mode=ml_mode,
        )
        summary["active_threshold_blocks"] = active_threshold_blocks
        summary["active_ml_blocks"] = active_ml_blocks

        return {
            "generated_at": _utc_iso(now),
            "generated_at_epoch": now,
            "summary": summary,
            "switches": self._switch_rows(controller_state),
            "learned_hosts": self._host_rows(controller_state),
            "blocked_hosts": self._blocked_host_rows(firewall, now),
            "recent_events": metrics.recent_events_list()[:100],
            "recent_security_events": self._security_events(metrics),
            "recent_ml_predictions": metrics.recent_ml_predictions_list()[:60],
            "recent_hybrid_events": metrics.recent_hybrid_events_list()[:60],
            "ml_status": dict(ml_status or {}),
            "config": dict(config_snapshot or {}),
            "timeseries": [],
        }

    def _append_timeseries(self, summary, now):
        point = {
            "timestamp_epoch": now,
            "label": _utc_label(now),
            "total_packets": summary["total_packets"],
            "total_bytes": summary.get("total_bytes", 0),
            "alerts_total": summary["alerts_total"],
            "threshold_alerts_total": summary.get("threshold_alerts_total", 0),
            "ml_alerts_total": summary.get("ml_alerts_total", 0),
            "hybrid_agreements_total": summary.get("hybrid_agreements_total", 0),
            "hybrid_disagreements_total": summary.get("hybrid_disagreements_total", 0),
            "blocks_total": summary["blocks_total"],
            "threshold_blocks_total": summary.get("threshold_blocks_total", 0),
            "ml_blocks_total": summary.get("ml_blocks_total", 0),
            "active_blocks": summary["active_blocks"],
            "flow_installs_total": summary.get("flow_installs_total", 0),
            "flow_removals_total": summary.get("flow_removals_total", 0),
            "active_flows_total": summary.get("active_flows_total", 0),
            "active_security_flows_total": summary.get("active_security_flows_total", 0),
            "controller_events_total": summary.get("controller_events_total", 0),
            "ml_predictions_total": summary.get("ml_predictions_total", 0),
            "ml_malicious_predictions_total": summary.get(
                "ml_malicious_predictions_total",
                0,
            ),
            "ml_benign_predictions_total": summary.get("ml_benign_predictions_total", 0),
        }

        if self._timeseries:
            previous_point = self._timeseries[-1]
            if int(previous_point["timestamp_epoch"]) == int(now):
                self._timeseries[-1] = point
                return

        self._timeseries.append(point)

    def _persist_payload(self, payload):
        temp_path = self.state_file_path.with_suffix(".tmp")
        temp_path.write_text(
            json.dumps(payload, sort_keys=True),
            encoding="utf-8",
        )
        temp_path.replace(self.state_file_path)

    def _restore_existing_payload(self):
        if not self.state_file_path.exists():
            return
        try:
            payload = json.loads(self.state_file_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return

        timeseries = payload.get("timeseries") or []
        if isinstance(timeseries, list):
            self._timeseries.extend(timeseries[-self.timeseries_points:])
        try:
            self._last_persist_at = float(payload.get("generated_at_epoch") or 0.0)
        except (TypeError, ValueError):
            self._last_persist_at = 0.0

    @staticmethod
    def _switch_rows(controller_state):
        switch_rows = []
        for datapath_id in sorted(controller_state.datapaths):
            switch_rows.append(
                {
                    "dpid": "%016x" % datapath_id,
                }
            )
        return switch_rows

    @staticmethod
    def _host_rows(controller_state):
        host_rows = []
        for record in sorted(
            controller_state.hosts.values(),
            key=lambda item: item.last_seen,
            reverse=True,
        ):
            host_rows.append(
                {
                    "mac_address": record.mac_address,
                    "ip_address": record.ip_address,
                    "switch_id": record.switch_id,
                    "port_no": record.port_no,
                    "last_seen_epoch": record.last_seen,
                    "last_seen": _utc_label(record.last_seen),
                }
            )
        return host_rows[:32]

    @staticmethod
    def _blocked_host_rows(firewall, now):
        blocked_rows = []
        for block in sorted(
            firewall.quarantined_hosts.values(),
            key=lambda item: item.created_at,
            reverse=True,
        ):
            related_capture = dict(block.related_capture or {})
            blocked_rows.append(
                {
                    "src_ip": block.src_ip,
                    "reason": block.reason,
                    "detector": block.detector or "threshold",
                    "alert_type": block.alert_type,
                    "created_at": _utc_label(block.created_at),
                    "created_at_epoch": block.created_at,
                    "status": "quarantined",
                    "related_capture": related_capture,
                }
            )
        return blocked_rows

    @staticmethod
    def _blocked_detector_counts(firewall):
        threshold_count = 0
        ml_count = 0
        for block in firewall.quarantined_hosts.values():
            if (block.detector or "threshold").strip().lower() == "ml":
                ml_count += 1
            else:
                threshold_count += 1
        return threshold_count, ml_count

    @staticmethod
    def _security_events(metrics):
        security_events = []
        for event in metrics.recent_events_list():
            if event.get("category") not in (
                "ids_alert",
                "mitigation",
                "ml_alert",
                "hybrid_correlation",
                "manual_unblock",
                "capture_snapshot",
            ):
                continue
            security_events.append(event)
        return security_events[:30]


class DashboardStateReader(object):
    """Read the shared dashboard JSON state for the Flask application."""

    def __init__(self, dashboard_config):
        self.state_file_path = Path(dashboard_config.state_file_path)
        self._lock = Lock()

    def read(self):
        with self._lock:
            if not self.state_file_path.exists():
                return empty_dashboard_state()

            try:
                return json.loads(self.state_file_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return empty_dashboard_state()


class DashboardDataAdapter(object):
    """Build enriched dashboard payloads for the Flask UI and API."""

    def __init__(self, app_config):
        self.app_config = app_config
        self.state_reader = DashboardStateReader(app_config.dashboard)
        self.capture_root = Path("captures/output")
        self.active_capture_file = self.capture_root / ".active_capture_session"
        self.continuous_capture_state_file = (
            self.capture_root / "continuous" / "continuous_capture_state.json"
        )

    def read(self):
        raw_state = self.state_reader.read()
        return self._enrich_payload(raw_state)

    def payload_for(self, page_name):
        payload = self.read()
        payload["page"] = page_name
        return payload

    def health_payload(self):
        payload = self.read()
        summary = payload.get("summary", {})
        return {
            "status": "ok",
            "generated_at": payload.get("generated_at"),
            "generated_at_epoch": payload.get("generated_at_epoch"),
            "active_switches": summary.get("active_switches", 0),
            "active_hosts": summary.get("active_hosts", 0),
            "ml_mode": payload.get("ml", {}).get("effective_mode_api", "threshold"),
            "model_available": payload.get("ml", {}).get("model_available", False),
        }

    def resolve_capture_path(self, relative_path):
        if not relative_path:
            return None

        root_path = self.capture_root.resolve()
        candidate = (root_path / relative_path).resolve()
        if not str(candidate).startswith(str(root_path)):
            return None
        if not candidate.exists() or not candidate.is_file():
            return None
        return candidate

    def _enrich_payload(self, payload):
        state = empty_dashboard_state()
        state.update(payload or {})
        summary = dict(state.get("summary") or {})
        defaults = empty_dashboard_state()["summary"]
        for key, value in defaults.items():
            summary.setdefault(key, value)
        summary["active_quarantines"] = summary.get("active_blocks", 0)
        state["summary"] = summary

        recent_events = list(state.get("recent_events") or [])
        recent_ml_predictions = list(state.get("recent_ml_predictions") or [])
        recent_hybrid_events = list(state.get("recent_hybrid_events") or [])
        timeseries = list(state.get("timeseries") or [])
        blocked_hosts = list(state.get("blocked_hosts") or [])
        active_threshold_blocks = 0
        active_ml_blocks = 0
        for row in blocked_hosts:
            detector = (row.get("detector") or "threshold").strip().lower()
            if detector == "ml":
                active_ml_blocks += 1
            else:
                active_threshold_blocks += 1
            related_capture = dict(row.get("related_capture") or {})
            if related_capture.get("primary_file"):
                related_capture["download_path"] = self._download_path(
                    related_capture["primary_file"]
                )
            row["related_capture"] = related_capture
        summary["active_threshold_blocks"] = active_threshold_blocks
        summary["active_ml_blocks"] = active_ml_blocks
        switches = list(state.get("switches") or [])
        learned_hosts = list(state.get("learned_hosts") or [])
        raw_ml_status = dict(state.get("ml_status") or {})
        ml_status = self._merge_section_defaults(
            empty_dashboard_state()["ml_status"],
            raw_ml_status,
        )
        for prefix in ("configured_mode", "selected_mode", "effective_mode"):
            mode_key = prefix
            api_key = prefix + "_api"
            label_key = prefix + "_label"
            if mode_key not in raw_ml_status:
                ml_status.pop(mode_key, None)
            if api_key not in raw_ml_status:
                ml_status.pop(api_key, None)
            if label_key not in raw_ml_status:
                ml_status.pop(label_key, None)
        config_snapshot = self._merge_section_defaults(
            self._fallback_settings_snapshot(),
            state.get("config") or {},
        )

        protocol_rows = self._protocol_rows(summary.get("packets_by_protocol") or {})
        alert_rows = self._alert_rows(recent_events)
        ml_alert_rows = [row for row in alert_rows if row.get("detector") == "ml"]
        hybrid_rows = [row for row in alert_rows if row.get("detector") == "hybrid"]
        controller_activity = self._controller_activity_rows(recent_events)
        performance = self._performance_payload(summary, timeseries)
        traffic = self._traffic_payload(summary, timeseries, protocol_rows)
        captures = self._captures_payload()
        ml_payload = self._ml_payload(
            summary,
            ml_status,
            ml_alert_rows,
            recent_ml_predictions,
            hybrid_rows,
            recent_hybrid_events,
        )

        state["recent_events"] = recent_events
        state["recent_security_events"] = alert_rows[:30]
        state["recent_ml_predictions"] = recent_ml_predictions[:30]
        state["recent_hybrid_events"] = recent_hybrid_events[:30]
        state["switches"] = switches
        state["learned_hosts"] = learned_hosts[:32]
        state["blocked_hosts"] = blocked_hosts
        state["traffic"] = traffic
        state["alerts"] = {
            "rows": alert_rows[:40],
            "counts_by_severity": self._counts_by_key(alert_rows, "severity"),
            "counts_by_detector": self._counts_by_key(alert_rows, "detector"),
            "active_count": len(blocked_hosts),
        }
        state["performance"] = performance
        state["ml"] = ml_payload
        state["captures"] = captures
        config_snapshot["ids_runtime"] = self._ids_runtime_settings_payload(ml_payload)
        state["settings"] = config_snapshot
        state["controller_activity"] = controller_activity[:30]
        state["stale_after_seconds"] = max(
            1.5,
            self.app_config.dashboard.poll_interval_seconds * 1.75,
        )
        return state

    def _traffic_payload(self, summary, timeseries, protocol_rows):
        current_packet_rate = self._series_rate(timeseries, "total_packets")
        current_byte_rate = self._series_rate(timeseries, "total_bytes")
        return {
            "protocols": protocol_rows,
            "top_talkers": list(summary.get("top_sources") or []),
            "packet_rate_per_second": current_packet_rate,
            "byte_rate_per_second": current_byte_rate,
            "packet_rate_display": _format_rate(current_packet_rate, "pkt/s"),
            "byte_rate_display": _format_rate(current_byte_rate, "B/s"),
        }

    def _performance_payload(self, summary, timeseries):
        packet_in_rate = self._series_rate(timeseries, "total_packets")
        flow_install_rate = self._series_rate(timeseries, "flow_installs_total")
        event_processing_rate = self._series_rate(timeseries, "controller_events_total")
        return {
            "packet_in_rate": packet_in_rate,
            "packet_in_rate_display": _format_rate(packet_in_rate, "pkt/s"),
            "flow_install_rate": flow_install_rate,
            "flow_install_rate_display": _format_rate(flow_install_rate, "flow/s"),
            "event_processing_rate": event_processing_rate,
            "event_processing_rate_display": _format_rate(event_processing_rate, "evt/s"),
            "flow_installs_total": summary.get("flow_installs_total", 0),
            "flow_removals_total": summary.get("flow_removals_total", 0),
            "active_flows_total": summary.get("active_flows_total", 0),
            "active_security_flows_total": summary.get("active_security_flows_total", 0),
            "active_blocks": summary.get("active_blocks", 0),
            "controller_events_total": summary.get("controller_events_total", 0),
            "switch_count": summary.get("active_switches", 0),
            "host_count": summary.get("active_hosts", 0),
        }

    def _ml_payload(
        self,
        summary,
        ml_status,
        ml_alert_rows,
        recent_ml_predictions,
        hybrid_rows,
        recent_hybrid_events,
    ):
        confidences = [row.get("confidence", 0.0) for row in recent_ml_predictions if row.get("confidence") is not None]
        suspicion_scores = [
            row.get("suspicion_score", 0.0)
            for row in recent_ml_predictions
            if row.get("suspicion_score") is not None
        ]
        correlated_total = summary.get("hybrid_correlated_total", 0)
        agreement_total = summary.get("hybrid_agreements_total", 0)
        configured_mode = ml_status.get("configured_mode") or self.app_config.ml.mode
        selected_mode = ml_status.get("selected_mode") or configured_mode
        effective_mode = ml_status.get("effective_mode") or summary.get("ml_mode", "threshold_only")
        return {
            "configured_mode": configured_mode,
            "configured_mode_api": ml_status.get("configured_mode_api") or normalize_ids_mode_public(configured_mode),
            "configured_mode_label": ml_status.get("configured_mode_label") or ids_mode_label(configured_mode),
            "selected_mode": selected_mode,
            "selected_mode_api": ml_status.get("selected_mode_api") or normalize_ids_mode_public(selected_mode),
            "selected_mode_label": ml_status.get("selected_mode_label") or ids_mode_label(selected_mode),
            "effective_mode": effective_mode,
            "effective_mode_api": ml_status.get("effective_mode_api") or normalize_ids_mode_public(effective_mode),
            "effective_mode_label": ml_status.get("effective_mode_label") or ids_mode_label(effective_mode),
            "hybrid_policy": ml_status.get("hybrid_policy") or self.app_config.ml.hybrid_policy,
            "model_available": bool(ml_status.get("model_available")),
            "model_path": ml_status.get("model_path") or self.app_config.ml.model_path,
            "model_error": ml_status.get("model_error"),
            "available_modes": list(ml_status.get("available_modes") or ids_mode_options()),
            "prediction_counts": {
                "total": summary.get("ml_predictions_total", 0),
                "malicious": summary.get("ml_malicious_predictions_total", 0),
                "benign": summary.get("ml_benign_predictions_total", 0),
            },
            "alert_counts": {
                "total": summary.get("ml_alerts_total", 0),
                "blocks": summary.get("ml_blocks_total", 0),
                "agreements": summary.get("hybrid_agreements_total", 0),
                "disagreements": summary.get("hybrid_disagreements_total", 0),
                "threshold_only": summary.get("threshold_only_detections_total", 0),
                "ml_only": summary.get("ml_only_detections_total", 0),
                "correlated_total": correlated_total,
            },
            "recent_alerts": ml_alert_rows[:30],
            "recent_predictions": recent_ml_predictions[:30],
            "recent_hybrid_events": (recent_hybrid_events or hybrid_rows)[:30],
            "average_confidence": (sum(confidences) / len(confidences)) if confidences else 0.0,
            "average_suspicion_score": (
                sum(suspicion_scores) / len(suspicion_scores)
                if suspicion_scores
                else 0.0
            ),
            "agreement_rate": (
                (float(agreement_total) / float(correlated_total))
                if correlated_total
                else 0.0
            ),
        }

    @staticmethod
    def _ids_runtime_settings_payload(ml_payload):
        return {
            "configured_mode": ml_payload.get("configured_mode_label", "Threshold IDS"),
            "selected_mode": ml_payload.get("selected_mode_label", "Threshold IDS"),
            "effective_mode": ml_payload.get("effective_mode_label", "Threshold IDS"),
            "hybrid_policy": ml_payload.get("hybrid_policy", "alert_only"),
            "model_available": ml_payload.get("model_available", False),
            "model_path": ml_payload.get("model_path", ""),
        }

    def _captures_payload(self):
        sessions = []
        files = []
        snapshots = []
        continuous_files = []
        active_session = None
        continuous_state = self._continuous_capture_state()

        if self.active_capture_file.exists():
            try:
                active_session = self.active_capture_file.read_text(encoding="utf-8").strip() or None
            except OSError:
                active_session = None

        if self.capture_root.exists():
            excluded_names = {"continuous", "snapshots"}
            for session_dir in sorted(
                [
                    path
                    for path in self.capture_root.iterdir()
                    if path.is_dir() and path.name not in excluded_names
                ],
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            ):
                notes = self._capture_notes(session_dir / "capture_session.txt")
                session_name = session_dir.name
                session_files = []
                total_size = 0
                for capture_file in sorted(session_dir.glob("*.pcap")):
                    file_row = self._capture_file_row(
                        capture_file,
                        session_name=session_name,
                        scenario=notes.get("scenario") or self._scenario_from_session(session_name),
                        timestamp=notes.get("timestamp") or self._timestamp_from_session(session_name),
                        interface_name=self._interface_from_capture_name(
                            session_name,
                            capture_file.name,
                        ),
                        status="active" if session_name == active_session else notes.get("status", "inactive"),
                    )
                    session_files.append(file_row)
                    files.append(file_row)
                    total_size += file_row["size_bytes"]

                sessions.append(
                    {
                        "session_name": session_name,
                        "scenario": notes.get("scenario") or self._scenario_from_session(session_name),
                        "timestamp": notes.get("timestamp") or self._timestamp_from_session(session_name),
                        "started_at": notes.get("started_at") or notes.get("timestamp"),
                        "stopped_at": notes.get("stopped_at"),
                        "interfaces": self._capture_interfaces(notes, session_files),
                        "file_count": len(session_files),
                        "total_size_bytes": total_size,
                        "total_size_human": _human_bytes(total_size),
                        "active": session_name == active_session,
                        "status": "active" if session_name == active_session else notes.get("status", "inactive"),
                        "notes": notes,
                        "files": session_files,
                    }
                )

            snapshots_root = self.capture_root / "snapshots"
            if snapshots_root.exists():
                for snapshot_dir in sorted(
                    [path for path in snapshots_root.iterdir() if path.is_dir()],
                    key=lambda path: path.stat().st_mtime,
                    reverse=True,
                ):
                    metadata_path = snapshot_dir / "snapshot.json"
                    if not metadata_path.exists():
                        continue
                    try:
                        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        continue
                    snapshot_files = []
                    for file_row in metadata.get("files", []):
                        relative_path = file_row.get("relative_path")
                        if not relative_path:
                            continue
                        snapshot_files.append(
                            {
                                "interface": file_row.get("interface") or "-",
                                "file_name": file_row.get("file_name") or "-",
                                "relative_path": relative_path,
                                "download_path": self._download_path(relative_path),
                                "size_bytes": file_row.get("size_bytes") or 0,
                                "size_human": _human_bytes(file_row.get("size_bytes") or 0),
                            }
                        )

                    snapshots.append(
                        {
                            "snapshot_name": metadata.get("snapshot_name") or snapshot_dir.name,
                            "timestamp": metadata.get("created_at") or "-",
                            "source_ip": metadata.get("source_ip") or "-",
                            "alert_type": metadata.get("alert_type") or "-",
                            "detector": metadata.get("detector") or "-",
                            "reason": metadata.get("reason") or "-",
                            "status": metadata.get("status") or "preserved",
                            "size_bytes": metadata.get("size_bytes") or 0,
                            "size_human": _human_bytes(metadata.get("size_bytes") or 0),
                            "file_count": metadata.get("file_count") or len(snapshot_files),
                            "primary_file": metadata.get("primary_file"),
                            "primary_download_path": self._download_path(
                                metadata.get("primary_file")
                            )
                            if metadata.get("primary_file")
                            else None,
                            "files": snapshot_files,
                        }
                    )

            continuous_files = self._continuous_capture_files(continuous_state)

        all_files = list(files) + list(continuous_files)
        for snapshot in snapshots:
            all_files.extend(snapshot.get("files") or [])

        return {
            "active_session": active_session,
            "active": bool(active_session or continuous_state.get("active")),
            "sessions": sessions,
            "files": all_files,
            "manual_session_files": files,
            "continuous": continuous_state,
            "continuous_files": continuous_files,
            "snapshots": snapshots,
            "last_scan_at": _utc_iso(time.time()),
        }

    def _alert_rows(self, recent_events):
        rows = []
        for event in recent_events:
            category = event.get("category") or "controller"
            if category not in (
                "ids_alert",
                "ml_alert",
                "hybrid_correlation",
            ):
                continue

            detector = event.get("detector")
            if not detector:
                if category == "ml_alert":
                    detector = "ml"
                elif category == "hybrid_correlation":
                    detector = "hybrid"
                elif category in ("ids_alert", "mitigation", "mitigation_expired"):
                    detector = "threshold"
                else:
                    detector = "system"

            severity = event.get("severity")
            if not severity:
                if category == "mitigation":
                    severity = "high"
                elif category == "mitigation_expired":
                    severity = "low"
                elif category == "hybrid_correlation":
                    severity = (
                        "critical"
                        if event.get("status") == "agreement"
                        else "medium"
                    )
                else:
                    severity = "medium"

            related_capture = dict(event.get("related_capture") or {})
            if related_capture.get("primary_file"):
                related_capture["download_path"] = self._download_path(
                    related_capture["primary_file"]
                )

            rows.append(
                {
                    "timestamp": event.get("timestamp"),
                    "category": category,
                    "action": event.get("action") or category,
                    "alert_type": (
                        event.get("alert_type")
                        or event.get("event_type")
                        or event.get("status")
                        or "-"
                    ),
                    "severity": severity,
                    "src_ip": event.get("src_ip") or "-",
                    "reason": event.get("reason") or "-",
                    "detector": detector,
                    "status": event.get("status") or "-",
                    "quarantine_status": event.get("quarantine_status"),
                    "related_capture": related_capture,
                    "confidence": event.get("confidence"),
                    "suspicion_score": event.get("suspicion_score"),
                    "threshold_timestamp": event.get("threshold_timestamp"),
                    "ml_timestamp": event.get("ml_timestamp"),
                }
            )
        return rows

    @staticmethod
    def _merge_section_defaults(defaults, overrides):
        merged = dict(defaults or {})
        for key, value in (overrides or {}).items():
            if isinstance(merged.get(key), dict) and isinstance(value, dict):
                nested = dict(merged.get(key) or {})
                nested.update(value)
                merged[key] = nested
            else:
                merged[key] = value
        return merged

    @staticmethod
    def _controller_activity_rows(recent_events):
        rows = []
        for event in recent_events:
            category = event.get("category")
            if category not in ("controller", "flow"):
                continue
            rows.append(
                {
                    "timestamp": event.get("timestamp"),
                    "category": category,
                    "event_type": event.get("event_type") or event.get("action") or "-",
                    "reason": event.get("reason") or "-",
                    "dpid": event.get("dpid") or "-",
                    "priority": event.get("priority") or "-",
                    "packet_count": event.get("packet_count") or 0,
                    "byte_count": event.get("byte_count") or 0,
                }
            )
        return rows

    @staticmethod
    def _protocol_rows(protocol_counts):
        total_packets = float(sum(protocol_counts.values()) or 1.0)
        rows = []
        for protocol_name, packet_count in sorted(
            protocol_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            rows.append(
                {
                    "protocol": protocol_name,
                    "packet_count": packet_count,
                    "share_percent": round((float(packet_count) / total_packets) * 100.0, 2),
                }
            )
        return rows

    @staticmethod
    def _counts_by_key(rows, key_name):
        counts = {}
        for row in rows:
            key_value = row.get(key_name) or "unknown"
            counts[key_value] = counts.get(key_value, 0) + 1
        return counts

    @staticmethod
    def _series_rate(timeseries, key_name):
        if len(timeseries) < 2:
            return 0.0

        latest = timeseries[-1]
        previous = timeseries[-2]
        elapsed = _safe_float(latest.get("timestamp_epoch")) - _safe_float(previous.get("timestamp_epoch"))
        if elapsed <= 0:
            return 0.0

        delta = _safe_float(latest.get(key_name)) - _safe_float(previous.get(key_name))
        if delta < 0:
            return 0.0
        return delta / elapsed

    @staticmethod
    def _capture_notes(notes_path):
        notes = {}
        if not notes_path.exists():
            return notes
        try:
            for line in notes_path.read_text(encoding="utf-8").splitlines():
                if "=" not in line:
                    continue
                key_name, value = line.split("=", 1)
                notes[key_name.strip()] = value.strip()
        except OSError:
            return {}
        return notes

    def _continuous_capture_state(self):
        if not self.continuous_capture_state_file.exists():
            return {
                "active": False,
                "enabled": False,
                "stale": False,
                "interfaces": [],
                "rolling_root": str(self.capture_root / "continuous" / "ring"),
                "snapshots_root": str(self.capture_root / "snapshots"),
            }
        try:
            state = json.loads(
                self.continuous_capture_state_file.read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            return {
                "active": False,
                "enabled": False,
                "stale": False,
                "interfaces": [],
                "rolling_root": str(self.capture_root / "continuous" / "ring"),
                "snapshots_root": str(self.capture_root / "snapshots"),
            }
        state.setdefault("active", False)
        state.setdefault("enabled", False)
        state.setdefault("stale", False)
        state.setdefault("interfaces", [])
        stale_after_seconds = _safe_float(state.get("stale_after_seconds")) or 75.0
        updated_at_epoch = _safe_float(state.get("updated_at_epoch"))
        if state.get("active") and updated_at_epoch > 0.0:
            if (time.time() - updated_at_epoch) > stale_after_seconds:
                state["active"] = False
                state["stale"] = True
                state["reason"] = "capture_state_stale"
        return state

    def _continuous_capture_files(self, continuous_state):
        files = []
        rolling_root = Path(continuous_state.get("rolling_root") or (self.capture_root / "continuous" / "ring"))
        if not rolling_root.exists():
            return files

        for capture_file in sorted(
            rolling_root.glob("*/*.pcap"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )[:48]:
            interface_name = capture_file.parent.name
            files.append(
                self._capture_file_row(
                    capture_file,
                    session_name="continuous",
                    scenario="rolling_capture",
                    timestamp=_utc_iso(capture_file.stat().st_mtime),
                    interface_name=interface_name,
                    status="active" if continuous_state.get("active") else "inactive",
                )
            )
        return files

    def _capture_file_row(
        self,
        capture_file,
        session_name,
        scenario,
        timestamp,
        interface_name,
        status,
    ):
        stat_result = capture_file.stat()
        relative_path = str(capture_file.relative_to(self.capture_root))
        return {
            "session_name": session_name,
            "scenario": scenario,
            "timestamp": timestamp,
            "file_name": capture_file.name,
            "interface": interface_name,
            "relative_path": relative_path,
            "download_path": self._download_path(relative_path),
            "size_bytes": stat_result.st_size,
            "size_human": _human_bytes(stat_result.st_size),
            "modified_at": _utc_iso(stat_result.st_mtime),
            "status": status,
        }

    def _download_path(self, relative_path):
        return "%s/captures/download/%s" % (
            self.app_config.dashboard.base_path,
            relative_path,
        )

    @staticmethod
    def _scenario_from_session(session_name):
        parts = session_name.rsplit("-", 2)
        if len(parts) == 3:
            return parts[0]
        return session_name

    @staticmethod
    def _interface_from_capture_name(session_name, file_name):
        prefix = session_name + "-"
        suffix = ".pcap"
        if file_name.startswith(prefix) and file_name.endswith(suffix):
            return file_name[len(prefix):-len(suffix)]
        return "-"

    @staticmethod
    def _capture_interfaces(notes, session_files):
        if notes.get("interfaces"):
            return notes.get("interfaces")
        interfaces = []
        for file_row in session_files:
            interface_name = file_row.get("interface")
            if interface_name and interface_name not in interfaces:
                interfaces.append(interface_name)
        return ", ".join(interfaces) if interfaces else "-"

    @staticmethod
    def _timestamp_from_session(session_name):
        parts = session_name.rsplit("-", 2)
        if len(parts) == 3:
            return "%s-%s" % (parts[1], parts[2])
        return "-"

    def _fallback_settings_snapshot(self):
        controller_config = getattr(
            self.app_config,
            "controller",
            type(
                "ControllerConfig",
                (),
                {"openflow_host": "0.0.0.0", "openflow_port": 6633},
            )(),
        )
        dashboard_config = getattr(
            self.app_config,
            "dashboard",
            type(
                "DashboardConfig",
                (),
                {
                    "host": "0.0.0.0",
                    "port": 8080,
                    "base_path": "/sdn-security",
                    "poll_interval_seconds": 1.0,
                    "persist_interval_seconds": 0.25,
                    "timeseries_points": 120,
                },
            )(),
        )
        firewall_config = getattr(
            self.app_config,
            "firewall",
            type(
                "FirewallConfig",
                (),
                {
                    "internal_subnet": "10.0.0.0/24",
                    "permit_icmp": True,
                    "permit_icmp_external": False,
                    "default_allow_ipv4": True,
                    "blocked_source_ips": (),
                    "restricted_tcp_ports": (23,),
                    "restricted_udp_ports": (),
                    "dynamic_block_duration_seconds": 60,
                },
            )(),
        )
        mitigation_config = getattr(
            self.app_config,
            "mitigation",
            type(
                "MitigationConfig",
                (),
                {
                    "enabled": True,
                    "quarantine_enabled": True,
                    "auto_unblock_enabled": False,
                    "manual_unblock_enabled": True,
                },
            )(),
        )
        ids_config = getattr(
            self.app_config,
            "ids",
            type(
                "IDSConfig",
                (),
                {
                    "enabled": True,
                    "inspect_tcp_udp_packets": True,
                    "packet_rate_window_seconds": 5,
                    "packet_rate_threshold": 250,
                    "syn_rate_window_seconds": 5,
                    "syn_rate_threshold": 100,
                    "scan_window_seconds": 10,
                    "unique_destination_ports_threshold": 12,
                    "unique_destination_hosts_threshold": 6,
                    "failed_connection_window_seconds": 10,
                    "failed_connection_threshold": 8,
                    "connection_attempt_window_seconds": 15,
                    "alert_suppression_seconds": 20,
                },
            )(),
        )
        ml_config = getattr(
            self.app_config,
            "ml",
            type(
                "MLConfig",
                (),
                {
                    "enabled": False,
                    "mode": "threshold_only",
                    "mode_state_path": "runtime/ids_mode_state.json",
                    "hybrid_policy": "alert_only",
                    "model_path": "models/random_forest_ids.joblib",
                    "dataset_path": "datasets/cicids2018.parquet",
                    "feature_window_seconds": 10,
                    "minimum_packets_before_inference": 12,
                    "inference_packet_stride": 6,
                    "inference_cooldown_seconds": 2.0,
                    "confidence_threshold": 0.75,
                    "mitigation_threshold": 0.92,
                    "alert_suppression_seconds": 20,
                    "hybrid_correlation_window_seconds": 10,
                },
            )(),
        )
        logging_config = getattr(
            self.app_config,
            "logging",
            type(
                "LoggingConfig",
                (),
                {"level": "INFO", "log_allowed_traffic": False},
            )(),
        )
        capture_config = getattr(
            self.app_config,
            "capture",
            type(
                "CaptureConfig",
                (),
                {
                    "enabled": True,
                    "continuous_enabled": True,
                    "tool": "tcpdump",
                    "interfaces": (),
                    "output_directory": "captures/output",
                    "ring_file_seconds": 30,
                    "ring_file_count": 12,
                    "snapshot_files_per_interface": 2,
                    "snapshot_cooldown_seconds": 10,
                },
            )(),
        )
        return {
            "controller": {
                "openflow_host": controller_config.openflow_host,
                "openflow_port": controller_config.openflow_port,
            },
            "dashboard": {
                "host": dashboard_config.host,
                "port": dashboard_config.port,
                "base_path": dashboard_config.base_path,
                "poll_interval_seconds": dashboard_config.poll_interval_seconds,
                "persist_interval_seconds": dashboard_config.persist_interval_seconds,
                "timeseries_points": dashboard_config.timeseries_points,
            },
            "firewall": {
                "internal_subnet": firewall_config.internal_subnet,
                "permit_icmp": firewall_config.permit_icmp,
                "permit_icmp_external": firewall_config.permit_icmp_external,
                "default_allow_ipv4": firewall_config.default_allow_ipv4,
                "blocked_source_ips": list(firewall_config.blocked_source_ips),
                "restricted_tcp_ports": list(firewall_config.restricted_tcp_ports),
                "restricted_udp_ports": list(firewall_config.restricted_udp_ports),
                "dynamic_block_duration_seconds": firewall_config.dynamic_block_duration_seconds,
            },
            "mitigation": {
                "enabled": mitigation_config.enabled,
                "quarantine_enabled": getattr(
                    mitigation_config,
                    "quarantine_enabled",
                    True,
                ),
                "auto_unblock_enabled": getattr(
                    mitigation_config,
                    "auto_unblock_enabled",
                    False,
                ),
                "manual_unblock_enabled": getattr(
                    mitigation_config,
                    "manual_unblock_enabled",
                    True,
                ),
            },
            "ids": {
                "enabled": ids_config.enabled,
                "inspect_tcp_udp_packets": ids_config.inspect_tcp_udp_packets,
                "packet_rate_window_seconds": ids_config.packet_rate_window_seconds,
                "packet_rate_threshold": ids_config.packet_rate_threshold,
                "syn_rate_window_seconds": ids_config.syn_rate_window_seconds,
                "syn_rate_threshold": ids_config.syn_rate_threshold,
                "scan_window_seconds": ids_config.scan_window_seconds,
                "unique_destination_ports_threshold": ids_config.unique_destination_ports_threshold,
                "unique_destination_hosts_threshold": ids_config.unique_destination_hosts_threshold,
                "failed_connection_window_seconds": ids_config.failed_connection_window_seconds,
                "failed_connection_threshold": ids_config.failed_connection_threshold,
                "connection_attempt_window_seconds": ids_config.connection_attempt_window_seconds,
                "alert_suppression_seconds": ids_config.alert_suppression_seconds,
            },
            "ml": {
                "enabled": getattr(ml_config, "enabled", False),
                "mode": getattr(ml_config, "mode", "threshold_only"),
                "mode_state_path": getattr(
                    ml_config,
                    "mode_state_path",
                    "runtime/ids_mode_state.json",
                ),
                "hybrid_policy": getattr(ml_config, "hybrid_policy", "alert_only"),
                "model_path": getattr(
                    ml_config,
                    "model_path",
                    "models/random_forest_ids.joblib",
                ),
                "dataset_path": getattr(
                    ml_config,
                    "dataset_path",
                    "datasets/cicids2018.parquet",
                ),
                "feature_window_seconds": getattr(
                    ml_config,
                    "feature_window_seconds",
                    10,
                ),
                "minimum_packets_before_inference": getattr(
                    ml_config,
                    "minimum_packets_before_inference",
                    12,
                ),
                "inference_packet_stride": getattr(
                    ml_config,
                    "inference_packet_stride",
                    6,
                ),
                "inference_cooldown_seconds": getattr(
                    ml_config,
                    "inference_cooldown_seconds",
                    2.0,
                ),
                "confidence_threshold": getattr(
                    ml_config,
                    "confidence_threshold",
                    0.75,
                ),
                "mitigation_threshold": getattr(
                    ml_config,
                    "mitigation_threshold",
                    0.92,
                ),
                "alert_suppression_seconds": getattr(
                    ml_config,
                    "alert_suppression_seconds",
                    20,
                ),
                "hybrid_correlation_window_seconds": getattr(
                    ml_config,
                    "hybrid_correlation_window_seconds",
                    10,
                ),
            },
            "ids_runtime": {
                "configured_mode": ids_mode_label(getattr(ml_config, "mode", "threshold_only")),
                "selected_mode": ids_mode_label(getattr(ml_config, "mode", "threshold_only")),
                "effective_mode": ids_mode_label(getattr(ml_config, "mode", "threshold_only")),
                "hybrid_policy": getattr(ml_config, "hybrid_policy", "alert_only"),
                "model_available": False,
                "model_path": getattr(
                    ml_config,
                    "model_path",
                    "models/random_forest_ids.joblib",
                ),
            },
            "logging": {
                "level": logging_config.level,
                "log_allowed_traffic": logging_config.log_allowed_traffic,
            },
            "capture": {
                "enabled": capture_config.enabled,
                "continuous_enabled": capture_config.continuous_enabled,
                "tool": capture_config.tool,
                "interfaces": list(capture_config.interfaces),
                "output_directory": capture_config.output_directory,
                "ring_file_seconds": capture_config.ring_file_seconds,
                "ring_file_count": capture_config.ring_file_count,
                "snapshot_files_per_interface": capture_config.snapshot_files_per_interface,
                "snapshot_cooldown_seconds": capture_config.snapshot_cooldown_seconds,
            },
        }
