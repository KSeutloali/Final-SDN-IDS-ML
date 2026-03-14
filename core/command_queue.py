"""Lightweight filesystem-backed command queue shared by dashboard and controller."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from threading import Lock
import uuid


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


class ControllerCommandQueue(object):
    """Persist small controller commands on disk for cross-process coordination."""

    def __init__(self, root_path="runtime/controller_commands"):
        self.root_path = Path(root_path)
        self.pending_path = self.root_path / "pending"
        self.processed_path = self.root_path / "processed"
        self.pending_path.mkdir(parents=True, exist_ok=True)
        self.processed_path.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def enqueue(self, action, payload):
        command_id = "%s-%s" % (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f"),
            uuid.uuid4().hex[:8],
        )
        command = {
            "command_id": command_id,
            "action": action,
            "payload": dict(payload or {}),
            "requested_at": _utc_now(),
            "status": "pending",
        }
        command_path = self.pending_path / ("%s.json" % command_id)
        with self._lock:
            command_path.write_text(json.dumps(command, sort_keys=True), encoding="utf-8")
        return command

    def pending_commands(self):
        for command_path in sorted(self.pending_path.glob("*.json")):
            try:
                command = json.loads(command_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            command["__path__"] = command_path
            yield command

    def mark_processed(self, command, status, result=None):
        command_id = command.get("command_id") or uuid.uuid4().hex
        archived = dict(command)
        archived.pop("__path__", None)
        archived["status"] = status
        archived["processed_at"] = _utc_now()
        archived["result"] = dict(result or {})

        archive_path = self.processed_path / ("%s.json" % command_id)
        archive_path.write_text(json.dumps(archived, sort_keys=True), encoding="utf-8")

        source_path = command.get("__path__")
        if source_path is not None:
            try:
                source_path.unlink()
            except OSError:
                pass

