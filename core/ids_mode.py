"""Shared IDS mode helpers and lightweight runtime persistence."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from threading import Lock


PUBLIC_IDS_MODES = ("threshold", "ml", "hybrid")
PUBLIC_TO_INTERNAL_IDS_MODE = {
    "threshold": "threshold_only",
    "ml": "ml_only",
    "hybrid": "hybrid",
}
INTERNAL_TO_PUBLIC_IDS_MODE = {
    value: key for key, value in PUBLIC_TO_INTERNAL_IDS_MODE.items()
}
IDS_MODE_LABELS = {
    "threshold": "Threshold IDS",
    "ml": "ML IDS",
    "hybrid": "Hybrid",
}


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_ids_mode_public(mode, default="threshold"):
    """Normalize public or internal mode names to the public API values."""

    normalized = (mode or "").strip().lower()
    if normalized in PUBLIC_TO_INTERNAL_IDS_MODE:
        return normalized
    if normalized in INTERNAL_TO_PUBLIC_IDS_MODE:
        return INTERNAL_TO_PUBLIC_IDS_MODE[normalized]

    fallback = (default or "threshold").strip().lower()
    if fallback in PUBLIC_TO_INTERNAL_IDS_MODE:
        return fallback
    if fallback in INTERNAL_TO_PUBLIC_IDS_MODE:
        return INTERNAL_TO_PUBLIC_IDS_MODE[fallback]
    return "threshold"


def normalize_ids_mode_internal(mode, default="threshold_only"):
    """Normalize public or internal mode names to the controller values."""

    return PUBLIC_TO_INTERNAL_IDS_MODE[
        normalize_ids_mode_public(
            mode,
            default=normalize_ids_mode_public(default),
        )
    ]


def ids_mode_label(mode):
    """Return a UI-friendly label for the given mode."""

    return IDS_MODE_LABELS[normalize_ids_mode_public(mode)]


def ids_mode_options():
    """Return the UI/API options for runtime IDS mode selection."""

    return [
        {"value": mode, "label": IDS_MODE_LABELS[mode]}
        for mode in PUBLIC_IDS_MODES
    ]


def explicit_ids_mode_from_env(env=None):
    """Return an explicitly configured startup mode, if one was provided."""

    env = env or os.environ
    for variable_name in ("SDN_IDS_MODE", "SDN_ML_MODE"):
        value = env.get(variable_name)
        if value is None or not str(value).strip():
            continue
        return normalize_ids_mode_public(value)
    return None


def resolve_startup_ids_mode(configured_mode, state_store=None, env=None):
    """Choose the controller startup mode.

    Explicit startup environment wins over persisted runtime state so normal
    compose restarts can intentionally move the controller back to the repo's
    configured operating mode.
    """

    explicit_mode = explicit_ids_mode_from_env(env=env)
    if explicit_mode is not None:
        return explicit_mode
    if state_store is not None:
        return state_store.current_mode(default=configured_mode)
    return normalize_ids_mode_public(configured_mode)


class IDSModeStateStore(object):
    """Persist the active IDS mode so it survives dashboard refreshes and restarts."""

    def __init__(self, state_path="runtime/ids_mode_state.json"):
        self.state_path = Path(state_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def read(self):
        if not self.state_path.exists():
            return {}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def current_mode(self, default="threshold"):
        payload = self.read()
        return normalize_ids_mode_public(payload.get("mode"), default=default)

    def persist(self, mode, effective_mode=None, requested_by="controller", previous_mode=None):
        selected_mode = normalize_ids_mode_public(mode)
        effective_public_mode = normalize_ids_mode_public(
            effective_mode or selected_mode,
            default=selected_mode,
        )
        payload = {
            "mode": selected_mode,
            "mode_label": ids_mode_label(selected_mode),
            "effective_mode": effective_public_mode,
            "effective_mode_label": ids_mode_label(effective_public_mode),
            "previous_mode": (
                normalize_ids_mode_public(previous_mode)
                if previous_mode is not None
                else None
            ),
            "requested_by": requested_by,
            "updated_at": _utc_now(),
        }
        temp_path = self.state_path.with_suffix(".tmp")
        with self._lock:
            temp_path.write_text(
                json.dumps(payload, sort_keys=True),
                encoding="utf-8",
            )
            temp_path.replace(self.state_path)
        return dict(payload)
