"""Controller-side recording of live-compatible ML training data."""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import threading
import time

from ml.feature_extractor import LiveFeatureExtractor


@dataclass(frozen=True)
class DatasetLabel(object):
    label: str
    scenario: str = ""
    scenario_id: str = ""
    run_id: str = ""
    collection_id: str = ""
    note: str = ""
    source: str = "manual"


class RuntimeDatasetRecorder(object):
    """Write controller-observed packets into a live-compatible JSONL dataset."""

    def __init__(self, ml_config):
        self.enabled = bool(getattr(ml_config, "dataset_recording_enabled", False))
        self.output_path = Path(
            getattr(ml_config, "dataset_recording_path", "runtime/ml_dataset.jsonl")
        )
        self.label_path = Path(
            getattr(ml_config, "dataset_label_path", "runtime/dataset_label.json")
        )
        self.label_refresh_seconds = max(
            0.2,
            float(getattr(ml_config, "dataset_label_refresh_seconds", 1.0)),
        )
        self.record_unlabeled = bool(
            getattr(ml_config, "dataset_record_unlabeled", False)
        )
        self.feature_extractor = LiveFeatureExtractor(ml_config)
        self._lock = threading.Lock()
        self._last_label_check = 0.0
        self._cached_label = None

    def status(self):
        return {
            "enabled": self.enabled,
            "output_path": str(self.output_path),
            "label_path": str(self.label_path),
            "record_unlabeled": self.record_unlabeled,
        }

    def current_label(self):
        return self._current_label()

    def record(self, packet_metadata, feature_snapshot=None):
        if not self.enabled:
            return False
        if packet_metadata is None or not getattr(packet_metadata, "is_ipv4", False):
            return False
        if not getattr(packet_metadata, "src_ip", None):
            return False

        label = self._current_label()
        if label is None and not self.record_unlabeled:
            return False

        if feature_snapshot is None:
            feature_snapshot = self.feature_extractor.observe(packet_metadata)
        if feature_snapshot is None:
            return False

        record = self._build_record(packet_metadata, feature_snapshot, label)
        self._append_record(record)
        return True

    def _current_label(self):
        now = time.time()
        if (now - self._last_label_check) < self.label_refresh_seconds:
            return self._cached_label

        self._last_label_check = now
        if not self.label_path.exists():
            self._cached_label = None
            return None

        try:
            payload = json.loads(self.label_path.read_text())
        except (OSError, TypeError, ValueError):
            self._cached_label = None
            return None

        label_value = str(payload.get("label", "")).strip()
        if not label_value:
            self._cached_label = None
            return None

        self._cached_label = DatasetLabel(
            label=label_value,
            scenario=str(payload.get("scenario", "")).strip(),
            scenario_id=str(payload.get("scenario_id", "")).strip(),
            run_id=str(payload.get("run_id", "")).strip(),
            collection_id=str(payload.get("collection_id", "")).strip(),
            note=str(payload.get("note", "")).strip(),
            source=str(payload.get("source", "manual")).strip() or "manual",
        )
        return self._cached_label

    def _build_record(self, packet_metadata, feature_snapshot, label):
        feature_values = dict(feature_snapshot.feature_values)
        record_label = (label.label if label is not None else "unlabeled").strip() or "unlabeled"

        record = {
            "Timestamp": datetime.fromtimestamp(
                float(packet_metadata.timestamp),
                tz=timezone.utc,
            ).isoformat(),
            "Src IP": packet_metadata.src_ip,
            "Dst IP": packet_metadata.dst_ip or "",
            "Dst Port": int(packet_metadata.dst_port) if packet_metadata.dst_port is not None else -1,
            "Protocol": packet_metadata.transport_protocol,
            "Total Packets": 1,
            "Total Bytes": int(packet_metadata.packet_length),
            "SYN Flag Count": 1 if getattr(packet_metadata, "tcp_syn_only", False) else 0,
            "RST Flag Count": 1 if getattr(packet_metadata, "tcp_rst", False) else 0,
            "Label": record_label,
            "Scenario": label.scenario if label is not None else "",
            "Scenario ID": label.scenario_id if label is not None else "",
            "Run ID": label.run_id if label is not None else "",
            "Collection ID": label.collection_id if label is not None else "",
            "Label Source": label.source if label is not None else "none",
            "Note": label.note if label is not None else "",
            "DPID": getattr(packet_metadata, "dpid", ""),
            "In Port": int(getattr(packet_metadata, "in_port", 0) or 0),
        }

        for feature_name, value in feature_values.items():
            record["Runtime %s" % feature_name] = float(value)
        return record

    def _append_record(self, record):
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self.output_path.open("a") as handle:
                handle.write(json.dumps(record, sort_keys=True))
                handle.write("\n")
