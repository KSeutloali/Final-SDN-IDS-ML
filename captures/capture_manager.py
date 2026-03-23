"""Continuous rolling capture and preserved forensic snapshot management."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import shutil
import subprocess
from pathlib import Path
from threading import RLock
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

    def __init__(
        self,
        capture_config,
        logger=None,
        manage_workers=True,
        interface_runtime_map=None,
    ):
        self.capture_config = capture_config
        self.logger = logger
        self.manage_workers = bool(manage_workers)
        self.interface_runtime_map = dict(interface_runtime_map or {})
        self.output_root = Path(capture_config.output_directory)
        self.continuous_root = self.output_root / "continuous"
        self.ring_root = self.continuous_root / "ring"
        self.snapshots_root = self.output_root / "snapshots"
        self.events_log_path = Path("runtime/capture_events.jsonl")
        self.state_path = self.continuous_root / "continuous_capture_state.json"
        self._lock = RLock()
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
            if not self.manage_workers:
                return self.status()
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

            started_at = _utc_iso()
            for interface_name in self.capture_config.interfaces:
                if interface_name in self._processes:
                    continue
                self._start_worker(
                    interface_name,
                    started_at=started_at,
                    event_action="capture_started",
                )
            return self._refresh_state(restart_workers=False)

    def stop(self):
        """Stop all running capture workers and mark the rolling state inactive."""

        with self._lock:
            if not self.manage_workers:
                return
            active_rows = self._running_process_rows()
            for interface_name, process_row in list(self._processes.items()):
                process = process_row.get("process")
                if process is None or process.poll() is not None:
                    log_handle = process_row.get("log_handle")
                    if log_handle is not None and not log_handle.closed:
                        log_handle.close()
                    continue
                process.terminate()
                try:
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                log_handle = process_row.get("log_handle")
                if log_handle is not None and not log_handle.closed:
                    log_handle.close()
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

    def ensure_healthy(self, restart_workers=False):
        with self._lock:
            if not self.manage_workers:
                return self.status()
            return self._refresh_state(restart_workers=restart_workers)

    def status(self):
        if self.manage_workers:
            return self.ensure_healthy(restart_workers=False)
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

            state = self.status()
            if not self._snapshot_source_ready(state):
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
                max_age_seconds=self._state_stale_after_seconds(),
            )
            settle_seconds = max(
                0.0,
                float(getattr(self.capture_config, "snapshot_settle_seconds", 0.0)),
            )
            for interface_name, file_paths in ring_files.items():
                newest_index = len(file_paths) - 1
                for file_index, file_path in enumerate(file_paths):
                    if file_index == newest_index and settle_seconds > 0.0:
                        self._wait_for_stable_file(
                            file_path,
                            max_wait_seconds=min(settle_seconds, 2.0),
                        )
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
                            "captured_at_epoch": file_path.stat().st_mtime,
                        }
                    )

            if not copied_files:
                return None

            primary_file = max(
                copied_files,
                key=lambda item: (
                    int(item.get("size_bytes") or 0),
                    float(item.get("captured_at_epoch", 0.0)),
                ),
            )

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
                "primary_file": primary_file["relative_path"],
            }
            (snapshot_dir / "snapshot.json").write_text(
                json.dumps(metadata, sort_keys=True),
                encoding="utf-8",
            )
            self._append_event("snapshot_preserved", metadata)
            self._last_snapshot_at[snapshot_key] = event_timestamp
            return metadata

    def _latest_ring_files(self, interfaces, per_interface, max_age_seconds=None):
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
            if max_age_seconds is not None:
                oldest_allowed = time.time() - float(max_age_seconds)
                files = [
                    path for path in files if path.stat().st_mtime >= oldest_allowed
                ]
            if not files:
                continue
            ring_files[interface_name] = list(reversed(files[:per_interface]))
        return ring_files

    def _start_worker(self, interface_name, started_at, event_action):
        safe_interface = _safe_name(interface_name)
        interface_root = self.ring_root / safe_interface
        interface_root.mkdir(parents=True, exist_ok=True)
        log_path = interface_root / "tcpdump.log"
        output_pattern = interface_root / (
            "%s_%%Y%%m%%d-%%H%%M%%S.pcap" % safe_interface
        )
        interface_runtime = self.interface_runtime_map.get(interface_name, {})
        namespace_pid = interface_runtime.get("namespace_pid")

        if not self._interface_exists(interface_name):
            self._log_warning(
                "capture_interface_missing",
                interface=interface_name,
            )
            return {
                "interface": interface_name,
                "status": "missing",
                "reason": "interface_missing",
                "namespace_pid": namespace_pid,
                "ring_root": str(interface_root),
                "output_pattern": str(output_pattern),
                "log_path": str(log_path),
            }

        command = self._capture_command(interface_name, output_pattern)
        log_handle = None
        try:
            log_handle = open(log_path, "a")
            process = subprocess.Popen(
                command,
                stdout=log_handle,
                stderr=log_handle,
            )
        except OSError as error:
            if log_handle is not None and not log_handle.closed:
                log_handle.close()
            self._log_warning(
                "capture_start_failed",
                interface=interface_name,
                reason=str(error),
            )
            return {
                "interface": interface_name,
                "status": "failed",
                "error": str(error),
                "namespace_pid": namespace_pid,
                "ring_root": str(interface_root),
                "output_pattern": str(output_pattern),
                "log_path": str(log_path),
            }

        self._processes[interface_name] = {
            "process": process,
            "output_pattern": str(output_pattern),
            "ring_root": str(interface_root),
            "started_at": started_at,
            "log_handle": log_handle,
            "log_path": str(log_path),
            "namespace_pid": namespace_pid,
        }
        self._append_event(
            event_action,
            {
                "interface": interface_name,
                "output_pattern": str(output_pattern),
                "pid": process.pid,
                "log_path": str(log_path),
                "namespace_pid": namespace_pid,
            },
        )
        return {
            "interface": interface_name,
            "status": "active",
            "pid": process.pid,
            "namespace_pid": namespace_pid,
            "ring_root": str(interface_root),
            "output_pattern": str(output_pattern),
            "log_path": str(log_path),
            "started_at": started_at,
        }

    def _refresh_state(self, restart_workers):
        previous_state = self._read_state()
        exited_rows = self._reap_exited_processes()
        exited_by_interface = dict(
            (row.get("interface"), row) for row in exited_rows if row.get("interface")
        )

        if restart_workers and self.enabled:
            started_at = previous_state.get("started_at") or _utc_iso()
            for interface_name in self.capture_config.interfaces:
                if interface_name in self._processes:
                    continue
                event_action = (
                    "capture_restarted"
                    if interface_name in exited_by_interface
                    else "capture_started"
                )
                self._start_worker(
                    interface_name,
                    started_at=started_at,
                    event_action=event_action,
                )

        active_rows = self._running_process_rows()
        active_by_interface = dict(
            (row.get("interface"), row) for row in active_rows if row.get("interface")
        )
        interface_rows = []
        for interface_name in self.capture_config.interfaces:
            active_row = active_by_interface.get(interface_name)
            if active_row is not None:
                interface_rows.append(active_row)
                continue

            exited_row = exited_by_interface.get(interface_name)
            if exited_row is not None:
                interface_rows.append(exited_row)
                continue

            safe_interface = _safe_name(interface_name)
            interface_root = self.ring_root / safe_interface
            row = {
                "interface": interface_name,
                "status": "inactive",
                "reason": "not_started",
                "namespace_pid": self.interface_runtime_map.get(interface_name, {}).get("namespace_pid"),
                "ring_root": str(interface_root),
                "output_pattern": str(
                    interface_root / ("%s_%%Y%%m%%d-%%H%%M%%S.pcap" % safe_interface)
                ),
                "log_path": str(interface_root / "tcpdump.log"),
            }
            if not self._interface_exists(interface_name):
                row["status"] = "missing"
                row["reason"] = "interface_missing"
            interface_rows.append(row)

        active_started_at = None
        for row in active_rows:
            if row.get("started_at"):
                active_started_at = row.get("started_at")
                break

        state = {
            "active": bool(active_rows),
            "enabled": self.enabled,
            "tool": self.capture_config.tool,
            "started_at": active_started_at or previous_state.get("started_at"),
            "interfaces": interface_rows,
            "ring_file_seconds": self.capture_config.ring_file_seconds,
            "ring_file_count": self.capture_config.ring_file_count,
            "snaplen": self.capture_config.snaplen,
            "rolling_root": str(self.ring_root),
            "snapshots_root": str(self.snapshots_root),
            "stale_after_seconds": self._state_stale_after_seconds(),
        }
        self._write_state(state)
        return state

    def _reap_exited_processes(self):
        exited_rows = []
        for interface_name, process_row in list(self._processes.items()):
            process = process_row.get("process")
            if process is None:
                continue
            return_code = process.poll()
            if return_code is None:
                continue
            log_handle = process_row.get("log_handle")
            if log_handle is not None and not log_handle.closed:
                log_handle.close()
            exited_row = {
                "interface": interface_name,
                "status": "inactive",
                "reason": "worker_exited",
                "return_code": return_code,
                "namespace_pid": process_row.get("namespace_pid"),
                "ring_root": process_row.get("ring_root"),
                "output_pattern": process_row.get("output_pattern"),
                "log_path": process_row.get("log_path"),
                "started_at": process_row.get("started_at"),
            }
            exited_rows.append(exited_row)
            self._append_event(
                "capture_worker_exited",
                {
                    "interface": interface_name,
                    "pid": process.pid,
                    "return_code": return_code,
                    "log_path": process_row.get("log_path"),
                    "namespace_pid": process_row.get("namespace_pid"),
                },
            )
            self._log_warning(
                "capture_worker_exited",
                interface=interface_name,
                pid=process.pid,
                return_code=return_code,
                log_path=process_row.get("log_path"),
            )
            del self._processes[interface_name]
        return exited_rows

    def _snapshot_source_ready(self, state):
        if not state or not state.get("rolling_root"):
            return False
        if not state.get("active"):
            return False
        updated_at_epoch = float(state.get("updated_at_epoch") or 0.0)
        if updated_at_epoch <= 0.0:
            return False
        return (time.time() - updated_at_epoch) <= self._state_stale_after_seconds()

    def _state_stale_after_seconds(self):
        return max(float(self.capture_config.ring_file_seconds) * 2.5, 75.0)

    @staticmethod
    def _wait_for_stable_file(file_path, max_wait_seconds):
        deadline = time.time() + max(0.0, float(max_wait_seconds or 0.0))
        stable_samples = 0
        previous_signature = None
        while time.time() < deadline:
            try:
                stat_result = file_path.stat()
            except OSError:
                return
            current_signature = (int(stat_result.st_size), float(stat_result.st_mtime))
            if current_signature == previous_signature:
                stable_samples += 1
                if stable_samples >= 2:
                    return
            else:
                stable_samples = 0
                previous_signature = current_signature
            remaining = deadline - time.time()
            if remaining <= 0.0:
                return
            time.sleep(min(0.10, remaining))

    def _capture_command(self, interface_name, output_pattern):
        tcpdump_path = shutil.which(self.capture_config.tool)
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
        interface_runtime = self.interface_runtime_map.get(interface_name, {})
        namespace_pid = interface_runtime.get("namespace_pid")
        if not namespace_pid:
            return command
        mnexec_path = shutil.which("mnexec")
        if mnexec_path is None:
            raise OSError("mnexec is unavailable for namespaced capture startup")
        return [mnexec_path, "-a", str(namespace_pid)] + command

    def _interface_exists(self, interface_name):
        interface_runtime = self.interface_runtime_map.get(interface_name, {})
        namespace_pid = interface_runtime.get("namespace_pid")
        if not namespace_pid:
            return (Path("/sys/class/net") / str(interface_name)).exists()
        mnexec_path = shutil.which("mnexec")
        if mnexec_path is None:
            return False
        try:
            result = subprocess.run(
                [mnexec_path, "-a", str(namespace_pid), "ip", "link", "show", interface_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError:
            return False
        return result.returncode == 0

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
                    "namespace_pid": process_row.get("namespace_pid"),
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
        state["updated_at_epoch"] = time.time()
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
