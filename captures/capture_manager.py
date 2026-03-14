"""Continuous rolling capture and preserved forensic snapshot management."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import shutil
import subprocess
from pathlib import Path
from threading import Lock
import time


def _utc_now():
    return datetime.now(timezone.utc)


def _utc_iso(timestamp_value=None):
    if timestamp_value is None:
        return _utc_now().isoformat()
    return datetime.fromtimestamp(timestamp_value, timezone.utc).isoformat()


def _safe_name(value):
    return str(value or "unknown").replace(":", "-").replace("/", "-").replace(" ", "_")


class PacketCaptureManager(object):
    """Manage rolling background captures and preserve alert snapshots."""

    def __init__(self, capture_config, logger=None):
        self.capture_config = capture_config
        self.logger = logger
        self.output_root = Path(capture_config.output_directory)
        self.continuous_root = self.output_root / "continuous"
        self.ring_root = self.continuous_root / "ring"
        self.snapshots_root = self.output_root / "snapshots"
        self.events_log_path = Path("runtime/capture_events.jsonl")
        self.state_path = self.continuous_root / "continuous_capture_state.json"
        self._lock = Lock()
        self._processes = {}
        self._last_snapshot_at = {}

        self.output_root.mkdir(parents=True, exist_ok=True)
        self.continuous_root.mkdir(parents=True, exist_ok=True)
        self.ring_root.mkdir(parents=True, exist_ok=True)
        self.snapshots_root.mkdir(parents=True, exist_ok=True)
        self.events_log_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def enabled(self):
        return bool(
            self.capture_config.enabled and self.capture_config.continuous_enabled
        )

    def start_continuous_capture(self):
        """Start one rotating tcpdump worker per configured interface."""

        with self._lock:
            if not self.enabled:
                self._write_state(
                    {
                        "active": False,
                        "enabled": False,
                        "reason": "capture_disabled",
                        "interfaces": [],
                        "started_at": None,
                    }
                )
                return {"active": False, "reason": "capture_disabled"}

            tcpdump_path = shutil.which(self.capture_config.tool)
            if tcpdump_path is None:
                self._log_warning(
                    "capture_tool_missing",
                    tool=self.capture_config.tool,
                )
                self._write_state(
                    {
                        "active": False,
                        "enabled": False,
                        "reason": "capture_tool_missing",
                        "tool": self.capture_config.tool,
                        "interfaces": [],
                    }
                )
                return {"active": False, "reason": "capture_tool_missing"}

            if self._running_process_rows():
                return self.status()

            started_at = _utc_iso()
            interface_rows = []
            active_any = False

            for interface_name in self.capture_config.interfaces:
                safe_interface = _safe_name(interface_name)
                interface_root = self.ring_root / safe_interface
                interface_root.mkdir(parents=True, exist_ok=True)
                output_pattern = interface_root / (
                    "%s_%%Y%%m%%d-%%H%%M%%S.pcap" % safe_interface
                )
                command = [
                    tcpdump_path,
                    "-i",
                    interface_name,
                    "-nn",
                    "-U",
                    "-s",
                    str(self.capture_config.snaplen),
                    "-G",
                    str(self.capture_config.ring_file_seconds),
                    "-W",
                    str(self.capture_config.ring_file_count),
                    "-w",
                    str(output_pattern),
                ]
                try:
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except OSError as error:
                    interface_rows.append(
                        {
                            "interface": interface_name,
                            "status": "failed",
                            "error": str(error),
                        }
                    )
                    self._log_warning(
                        "capture_start_failed",
                        interface=interface_name,
                        reason=str(error),
                    )
                    continue

                active_any = True
                self._processes[interface_name] = {
                    "process": process,
                    "output_pattern": str(output_pattern),
                    "ring_root": str(interface_root),
                    "started_at": started_at,
                }
                interface_rows.append(
                    {
                        "interface": interface_name,
                        "status": "active",
                        "pid": process.pid,
                        "ring_root": str(interface_root),
                        "output_pattern": str(output_pattern),
                    }
                )
                self._append_event(
                    "capture_started",
                    {
                        "interface": interface_name,
                        "output_pattern": str(output_pattern),
                        "pid": process.pid,
                    },
                )

            state = {
                "active": active_any,
                "enabled": self.enabled,
                "tool": self.capture_config.tool,
                "started_at": started_at,
                "interfaces": interface_rows,
                "ring_file_seconds": self.capture_config.ring_file_seconds,
                "ring_file_count": self.capture_config.ring_file_count,
                "snaplen": self.capture_config.snaplen,
                "rolling_root": str(self.ring_root),
                "snapshots_root": str(self.snapshots_root),
            }
            self._write_state(state)
            return state

    def stop(self):
        """Stop all running capture workers and mark the rolling state inactive."""

        with self._lock:
            active_rows = self._running_process_rows()
            for interface_name, process_row in list(self._processes.items()):
                process = process_row.get("process")
                if process is None or process.poll() is not None:
                    continue
                process.terminate()
                try:
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                self._append_event(
                    "capture_stopped",
                    {
                        "interface": interface_name,
                        "pid": process.pid,
                    },
                )
            self._processes = {}
            self._write_state(
                {
                    "active": False,
                    "enabled": self.enabled,
                    "stopped_at": _utc_iso(),
                    "interfaces": [
                        {
                            "interface": row.get("interface"),
                            "status": "inactive",
                        }
                        for row in active_rows
                    ],
                    "ring_file_seconds": self.capture_config.ring_file_seconds,
                    "ring_file_count": self.capture_config.ring_file_count,
                    "rolling_root": str(self.ring_root),
                    "snapshots_root": str(self.snapshots_root),
                }
            )

    def status(self):
        state = self._read_state()
        if state:
            return state
        return {
            "active": bool(self._running_process_rows()),
            "enabled": self.enabled,
            "interfaces": self._running_process_rows(),
            "ring_file_seconds": self.capture_config.ring_file_seconds,
            "ring_file_count": self.capture_config.ring_file_count,
            "rolling_root": str(self.ring_root),
            "snapshots_root": str(self.snapshots_root),
        }

    def preserve_snapshot(
        self,
        src_ip,
        alert_type,
        detector,
        reason,
        timestamp=None,
    ):
        """Preserve the most recent rolling capture files for a detection event."""

        with self._lock:
            if not self.enabled:
                return None

            event_timestamp = float(timestamp or time.time())
            snapshot_key = "%s|%s|%s" % (src_ip or "-", alert_type or "-", detector or "-")
            previous_snapshot_at = self._last_snapshot_at.get(snapshot_key)
            if (
                previous_snapshot_at is not None
                and (event_timestamp - previous_snapshot_at)
                < self.capture_config.snapshot_cooldown_seconds
            ):
                return None

            state = self._read_state()
            if not state or not state.get("rolling_root"):
                return None

            snapshot_timestamp = datetime.fromtimestamp(
                event_timestamp,
                timezone.utc,
            ).strftime("%Y-%m-%dT%H-%M-%S")
            snapshot_name = "%s_%s_%s" % (
                snapshot_timestamp,
                _safe_name(alert_type),
                _safe_name(src_ip),
            )
            snapshot_dir = self.snapshots_root / snapshot_name
            snapshot_dir.mkdir(parents=True, exist_ok=True)

            copied_files = []
            ring_files = self._latest_ring_files(
                interfaces=[row.get("interface") for row in state.get("interfaces", [])],
                per_interface=self.capture_config.snapshot_files_per_interface,
            )
            for interface_name, file_paths in ring_files.items():
                for file_path in file_paths:
                    destination_name = "%s__%s" % (
                        _safe_name(interface_name),
                        file_path.name,
                    )
                    destination_path = snapshot_dir / destination_name
                    try:
                        shutil.copy2(str(file_path), str(destination_path))
                    except OSError:
                        continue
                    copied_files.append(
                        {
                            "interface": interface_name,
                            "file_name": destination_name,
                            "relative_path": str(destination_path.relative_to(self.output_root)),
                            "size_bytes": destination_path.stat().st_size,
                        }
                    )

            if not copied_files:
                return None

            metadata = {
                "snapshot_name": snapshot_name,
                "created_at": _utc_iso(event_timestamp),
                "timestamp_epoch": event_timestamp,
                "source_ip": src_ip,
                "alert_type": alert_type,
                "detector": detector,
                "reason": reason,
                "status": "preserved",
                "snapshot_directory": str(snapshot_dir.relative_to(self.output_root)),
                "files": copied_files,
                "file_count": len(copied_files),
                "size_bytes": sum(item["size_bytes"] for item in copied_files),
                "primary_file": copied_files[0]["relative_path"] if copied_files else None,
            }
            (snapshot_dir / "snapshot.json").write_text(
                json.dumps(metadata, sort_keys=True),
                encoding="utf-8",
            )
            self._append_event("snapshot_preserved", metadata)
            self._last_snapshot_at[snapshot_key] = event_timestamp
            return metadata

    def _latest_ring_files(self, interfaces, per_interface):
        ring_files = {}
        for interface_name in interfaces or self.capture_config.interfaces:
            if not interface_name:
                continue
            interface_root = self.ring_root / _safe_name(interface_name)
            if not interface_root.exists():
                continue
            files = sorted(
                interface_root.glob("*.pcap"),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            if not files:
                continue
            ring_files[interface_name] = list(reversed(files[:per_interface]))
        return ring_files

    def _running_process_rows(self):
        rows = []
        for interface_name, process_row in self._processes.items():
            process = process_row.get("process")
            if process is None or process.poll() is not None:
                continue
            rows.append(
                {
                    "interface": interface_name,
                    "status": "active",
                    "pid": process.pid,
                    "ring_root": process_row.get("ring_root"),
                    "output_pattern": process_row.get("output_pattern"),
                    "started_at": process_row.get("started_at"),
                }
            )
        return rows

    def _append_event(self, action, payload):
        event = {
            "timestamp": _utc_iso(),
            "action": action,
        }
        event.update(dict(payload or {}))
        with self.events_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True))
            handle.write("\n")

    def _write_state(self, payload):
        state = dict(payload or {})
        state["updated_at"] = _utc_iso()
        self.state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")

    def _read_state(self):
        if not self.state_path.exists():
            return {}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _log_warning(self, action, **fields):
        if self.logger is None:
            return
        try:
            self.logger.warning(
                "event=capture action=%s %s",
                action,
                " ".join(
                    "%s=%s" % (key, str(value).replace(" ", "_"))
                    for key, value in sorted(fields.items())
                    if value is not None and value != ""
                ),
            )
        except Exception:
            return

