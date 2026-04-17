"""Orchestration for optional ML inference alongside the threshold IDS."""

from collections import defaultdict, deque
from dataclasses import dataclass, field

from core.ids_mode import (
    ids_mode_label,
    ids_mode_options,
    normalize_ids_mode_internal,
    normalize_ids_mode_public,
)
from ml.feature_extractor import LiveFeatureExtractor, RUNTIME_FEATURE_NAMES
from ml.inference import ModelInferenceEngine
from ml.model_loader import load_model


VALID_ML_MODES = ("threshold_only", "ml_only", "hybrid")
VALID_HYBRID_POLICIES = (
    "alert_only",
    "high_confidence_block",
    "consensus_severity",
    "layered_consensus",
)


@dataclass
class MLAlert(object):
    """Normalized ML alert that can be logged and optionally mitigated."""

    src_ip: str
    alert_type: str
    reason: str
    severity: str
    timestamp: float
    confidence: float
    suspicion_score: float
    label: str
    model_name: str
    decision: str
    should_mitigate: bool = False
    detector: str = "ml"
    details: dict = field(default_factory=dict)

    def to_dict(self):
        payload = {
            "src_ip": self.src_ip,
            "alert_type": self.alert_type,
            "reason": self.reason,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "confidence": round(float(self.confidence), 6),
            "suspicion_score": round(float(self.suspicion_score), 6),
            "label": self.label,
            "model_name": self.model_name,
            "decision": self.decision,
            "should_mitigate": self.should_mitigate,
            "detector": self.detector,
        }
        payload.update(self.details)
        return payload


@dataclass
class MLInspectionResult(object):
    """Combined runtime output from feature extraction and inference."""

    feature_snapshot: object = None
    prediction: object = None
    alert: MLAlert = None


@dataclass
class HybridCorrelationEvent(object):
    """Correlation outcome between threshold and ML detections."""

    src_ip: str
    status: str
    reason: str
    timestamp: float
    correlation_window_seconds: int
    threshold_timestamp: float = None
    ml_timestamp: float = None
    confidence: float = None
    suspicion_score: float = None


class MLIDSPipeline(object):
    """Optional ML inference path with threshold-first hybrid behavior."""

    def __init__(self, ml_config):
        self.ml_config = ml_config
        self.default_mode = self._validated_mode(ml_config.mode)
        self.mode = self.default_mode
        self.hybrid_policy = self._validated_hybrid_policy(ml_config.hybrid_policy)
        self.feature_extractor = LiveFeatureExtractor(ml_config)
        self.model_bundle = load_model(
            ml_config.model_path,
            fallback_feature_names=RUNTIME_FEATURE_NAMES,
            fallback_positive_labels=ml_config.positive_labels,
        )
        self.inference_engine = ModelInferenceEngine(self.model_bundle, ml_config)
        self.observed_packets = {}
        self.last_inference_at = {}
        self.last_inference_observation = {}
        self.last_alert_at = {}
        self.pending_threshold_alerts = {}
        self.pending_ml_alerts = {}
        self.recent_prediction_state = {}
        self.ml_only_signal_history = defaultdict(deque)

    def effective_mode(self):
        if self.mode == "threshold_only":
            return "threshold_only"
        if not self.inference_engine.is_available:
            return "threshold_only"
        return self.mode

    def status(self):
        effective_mode = self.effective_mode()
        return {
            "configured_mode": self.default_mode,
            "configured_mode_api": normalize_ids_mode_public(self.default_mode),
            "configured_mode_label": ids_mode_label(self.default_mode),
            "selected_mode": self.mode,
            "selected_mode_api": normalize_ids_mode_public(self.mode),
            "selected_mode_label": ids_mode_label(self.mode),
            "effective_mode": effective_mode,
            "effective_mode_api": normalize_ids_mode_public(effective_mode),
            "effective_mode_label": ids_mode_label(effective_mode),
            "hybrid_policy": self.hybrid_policy,
            "model_available": self.inference_engine.is_available,
            "model_path": self.model_bundle.source_path or self.ml_config.model_path,
            "model_error": self.model_bundle.load_error,
            "available_modes": ids_mode_options(),
            "mode_state_path": getattr(self.ml_config, "mode_state_path", ""),
        }

    def selection_error(self, mode):
        normalized_mode = self._validated_mode(mode)
        if normalized_mode == "threshold_only":
            return None
        if not self.inference_engine.is_available:
            return "model_unavailable"
        return None

    def set_mode(self, mode):
        normalized_mode = self._validated_mode(mode)
        previous_mode = self.mode
        previous_effective_mode = self.effective_mode()
        changed = normalized_mode != self.mode
        self.mode = normalized_mode
        if changed:
            self._reset_runtime_mode_state()
        effective_mode = self.effective_mode()
        return {
            "changed": changed,
            "previous_mode": previous_mode,
            "previous_mode_api": normalize_ids_mode_public(previous_mode),
            "previous_mode_label": ids_mode_label(previous_mode),
            "selected_mode": self.mode,
            "selected_mode_api": normalize_ids_mode_public(self.mode),
            "selected_mode_label": ids_mode_label(self.mode),
            "previous_effective_mode": previous_effective_mode,
            "previous_effective_mode_api": normalize_ids_mode_public(previous_effective_mode),
            "effective_mode": effective_mode,
            "effective_mode_api": normalize_ids_mode_public(effective_mode),
            "effective_mode_label": ids_mode_label(effective_mode),
        }

    def inspect(self, packet_metadata, threshold_alerts=None, threshold_context=None):
        """Run the ML feature/inference path when the effective mode allows it."""

        threshold_alerts = threshold_alerts or []
        threshold_context = dict(threshold_context or {})
        now = getattr(packet_metadata, "timestamp", 0.0)
        if self.effective_mode() == "threshold_only":
            return MLInspectionResult()

        for alert in threshold_alerts:
            if alert is None or not alert.src_ip:
                continue
            self.pending_threshold_alerts[alert.src_ip] = self._build_pending_threshold_state(
                alert,
                threshold_context=threshold_context,
            )

        feature_snapshot = self.feature_extractor.observe(packet_metadata)
        if feature_snapshot is None:
            return MLInspectionResult()

        self.observed_packets[feature_snapshot.src_ip] = (
            self.observed_packets.get(feature_snapshot.src_ip, 0) + 1
        )

        if not self._should_infer(feature_snapshot, now):
            return MLInspectionResult(feature_snapshot=feature_snapshot)

        prediction = self.inference_engine.predict(feature_snapshot)
        if prediction is not None:
            self._record_prediction_state(prediction, threshold_context=threshold_context)
        if prediction is None or not self._should_emit_alert(prediction, threshold_context):
            return MLInspectionResult(
                feature_snapshot=feature_snapshot,
                prediction=prediction,
            )

        if self._is_alert_suppressed(prediction.src_ip, prediction.timestamp):
            return MLInspectionResult(
                feature_snapshot=feature_snapshot,
                prediction=prediction,
            )

        alert = self._build_alert(prediction, threshold_context=threshold_context)
        self.last_alert_at[prediction.src_ip] = prediction.timestamp
        return MLInspectionResult(
            feature_snapshot=feature_snapshot,
            prediction=prediction,
            alert=alert,
        )

    def _build_alert(self, prediction, threshold_context=None):
        threshold_context = dict(threshold_context or {})
        threshold_triggered = bool(threshold_context.get("threshold_triggered"))
        threshold_suspicious = bool(threshold_context.get("recon_suspicious"))
        agreement = threshold_triggered or self._has_pending_threshold_agreement(
            prediction.src_ip,
            prediction.timestamp,
        )
        effective_mode = self.effective_mode()
        should_mitigate = False
        severity = "medium"
        decision = "log_only"
        reason = prediction.reason
        correlation_status = "ml_only"
        known_class_match = False
        repeat_count = 0
        low_confidence_suspicious = (
            not prediction.is_malicious
            and float(prediction.suspicion_score) >= float(self.ml_config.alert_only_threshold)
        )

        if effective_mode == "ml_only":
            correlation_status = "anomaly_only" if low_confidence_suspicious else "ml_only"
            decision = "anomaly_only_alert" if low_confidence_suspicious else "ml_only_alert"
            reason = (
                "ml_suspicion_above_alert_only_threshold"
                if low_confidence_suspicious
                else prediction.reason
            )
            repeat_count = self._record_ml_signal(prediction.src_ip, prediction.timestamp)
            if prediction.is_malicious and prediction.suspicion_score >= self.ml_config.mitigation_threshold:
                should_mitigate = True
                severity = "high"
                decision = "ml_only_block"
                correlation_status = "ml_only"
        elif effective_mode == "hybrid":
            if agreement:
                severity = "critical"
                decision = "threshold_enriched_by_ml"
                reason = "threshold_triggered_with_ml_context"
                known_class_match = prediction.is_malicious and bool(
                    threshold_context.get("threshold_rule_family")
                )
                correlation_status = (
                    "known_class_match" if known_class_match else "threshold_plus_ml"
                )
            elif threshold_suspicious:
                severity = "high"
                decision = "threshold_enriched_by_ml"
                reason = "subthreshold_recon_pattern_enriched_by_ml"
                correlation_status = "threshold_enriched_by_ml"
                repeat_count = self._record_ml_signal(prediction.src_ip, prediction.timestamp)
                if (
                    self.hybrid_policy == "high_confidence_block"
                    and prediction.is_malicious
                    and prediction.suspicion_score >= self.ml_config.mitigation_threshold
                    and (
                        (not self.ml_config.ml_only_escalation_enabled)
                        or repeat_count >= self.ml_config.ml_only_escalation_count
                        or int(threshold_context.get("recon_suspicion_score", 0)) >= 2
                    )
                ):
                    should_mitigate = True
                    decision = "hybrid_ml_block"
            else:
                correlation_status = "anomaly_only" if low_confidence_suspicious else "ml_only"
                decision = "anomaly_only_alert" if low_confidence_suspicious else "ml_only_alert"
                reason = (
                    "ml_suspicion_above_alert_only_threshold"
                    if low_confidence_suspicious
                    else prediction.reason
                )
                repeat_count = self._record_ml_signal(prediction.src_ip, prediction.timestamp)
                if (
                    self.hybrid_policy == "high_confidence_block"
                    and prediction.is_malicious
                    and prediction.suspicion_score >= self.ml_config.mitigation_threshold
                    and (
                        (not self.ml_config.ml_only_escalation_enabled)
                        or repeat_count >= self.ml_config.ml_only_escalation_count
                    )
                ):
                    should_mitigate = True
                    severity = "high"
                    decision = "hybrid_ml_block"

        if should_mitigate and reason == prediction.reason:
            reason = "ml_confidence_above_mitigation_threshold"

        details = {
            "agreement_with_threshold": agreement,
            "hybrid_status": correlation_status,
            "correlation_status": correlation_status,
            "threshold_triggered": threshold_triggered,
            "threshold_reason": threshold_context.get("threshold_reason", ""),
            "threshold_rule_family": threshold_context.get("threshold_rule_family", ""),
            "threshold_severity": threshold_context.get("threshold_severity", ""),
            "threshold_recent_event_count": int(
                threshold_context.get("threshold_recent_event_count", 0) or 0
            ),
            "threshold_context_suspicious": threshold_suspicious,
            "threshold_unanswered_syn_count": int(
                threshold_context.get("unanswered_syn_count", 0) or 0
            ),
            "threshold_unique_destination_hosts": int(
                threshold_context.get("scan_unique_destination_hosts", 0) or 0
            ),
            "threshold_unique_destination_ports": int(
                threshold_context.get("scan_unique_destination_ports", 0) or 0
            ),
            "recon_visible_traffic": bool(
                threshold_context.get("recon_visible_traffic", False)
            ),
            "forwarding_visibility": threshold_context.get("forwarding_visibility", ""),
            "known_class_match": known_class_match,
            "ml_only_repeat_count": repeat_count,
            "capture_recommended": correlation_status in ("ml_only", "anomaly_only"),
            "watchlist_candidate": correlation_status in (
                "threshold_enriched_by_ml",
                "ml_only",
                "anomaly_only",
            ),
            "confidence": round(float(prediction.confidence), 6),
            "suspicion_score": round(float(prediction.suspicion_score), 6),
            "label": prediction.label,
            "model_name": prediction.model_name,
            "model_version": prediction.model_version,
            "packet_count": round(float(prediction.feature_values.get("packet_count", 0.0)), 3),
            "unique_destination_ports": round(
                float(prediction.feature_values.get("unique_destination_ports", 0.0)),
                3,
            ),
            "unique_destination_ips": round(
                float(prediction.feature_values.get("unique_destination_ips", 0.0)),
                3,
            ),
            "destination_port_fanout_ratio": round(
                float(prediction.feature_values.get("destination_port_fanout_ratio", 0.0)),
                6,
            ),
            "syn_rate": round(float(prediction.feature_values.get("syn_rate", 0.0)), 6),
            "packet_rate": round(float(prediction.feature_values.get("packet_rate", 0.0)), 6),
            "failed_connection_rate": round(
                float(prediction.feature_values.get("failed_connection_rate", 0.0)),
                6,
            ),
            "unanswered_syn_rate": round(
                float(prediction.feature_values.get("unanswered_syn_rate", 0.0)),
                6,
            ),
            "unanswered_syn_ratio": round(
                float(prediction.feature_values.get("unanswered_syn_ratio", 0.0)),
                6,
            ),
            "unanswered_syn_count": round(
                float(prediction.feature_values.get("unanswered_syn_count", 0.0)),
                3,
            ),
            "recon_probe_density": round(
                float(prediction.feature_values.get("recon_probe_density", 0.0)),
                6,
            ),
            "packet_rate_delta": round(
                float(prediction.feature_values.get("packet_rate_delta", 0.0)),
                6,
            ),
            "destination_port_fanout_delta": round(
                float(prediction.feature_values.get("destination_port_fanout_delta", 0.0)),
                6,
            ),
            "observation_window_seconds": round(
                float(prediction.feature_values.get("observation_window_seconds", 0.0)),
                3,
            ),
        }
        return MLAlert(
            src_ip=prediction.src_ip,
            alert_type="random_forest_detected",
            reason=reason,
            severity=severity,
            timestamp=prediction.timestamp,
            confidence=prediction.confidence,
            suspicion_score=prediction.suspicion_score,
            label=prediction.label,
            model_name=prediction.model_name,
            decision=decision,
            should_mitigate=should_mitigate,
            details=details,
        )

    def _should_infer(self, feature_snapshot, now):
        if feature_snapshot.sample_count < self.ml_config.minimum_packets_before_inference:
            return False

        last_inference_at = self.last_inference_at.get(feature_snapshot.src_ip)
        if (
            last_inference_at is not None
            and (now - last_inference_at) < self.ml_config.inference_cooldown_seconds
        ):
            return False

        last_observation = self.last_inference_observation.get(feature_snapshot.src_ip, 0)
        current_observation = self.observed_packets.get(feature_snapshot.src_ip, 0)
        if (current_observation - last_observation) < self.ml_config.inference_packet_stride:
            return False

        self.last_inference_at[feature_snapshot.src_ip] = now
        self.last_inference_observation[feature_snapshot.src_ip] = current_observation
        return True

    def _should_emit_alert(self, prediction, threshold_context=None):
        if prediction is None:
            return False
        if prediction.is_malicious:
            return True
        threshold_context = dict(threshold_context or {})
        return (
            float(prediction.suspicion_score) >= float(self.ml_config.alert_only_threshold)
            and (
                self.effective_mode() == "ml_only"
                or bool(threshold_context.get("recon_suspicious"))
                or bool(threshold_context.get("recon_visible_traffic"))
            )
        )

    def _is_alert_suppressed(self, src_ip, now):
        previous = self.last_alert_at.get(src_ip)
        if previous is None:
            return False
        return (now - previous) < self.ml_config.alert_suppression_seconds

    def note_prediction(self, prediction):
        if prediction is None or not prediction.src_ip:
            return []

        events = self.expire_correlations(prediction.timestamp)
        pending_threshold = self.pending_threshold_alerts.get(prediction.src_ip)
        if (
            pending_threshold is not None
            and not prediction.is_malicious
            and self._within_correlation_window(
                pending_threshold["timestamp"],
                prediction.timestamp,
            )
        ):
            pending_threshold["seen_benign_prediction"] = True
            pending_threshold["confidence"] = float(prediction.confidence)
            pending_threshold["suspicion_score"] = float(prediction.suspicion_score)
        return events

    def handle_threshold_alert(self, alert):
        if alert is None or not alert.src_ip:
            return []

        now = alert.timestamp
        events = self.expire_correlations(now)
        pending_ml = self.pending_ml_alerts.get(alert.src_ip)
        if (
            pending_ml is not None
            and self._within_correlation_window(pending_ml["timestamp"], now)
        ):
            del self.pending_ml_alerts[alert.src_ip]
            status = pending_ml.get("status", "threshold_plus_ml")
            if status in ("ml_only", "anomaly_only"):
                status = "threshold_plus_ml"
            events.append(
                HybridCorrelationEvent(
                    src_ip=alert.src_ip,
                    status=status,
                    reason=pending_ml.get("reason", "threshold_and_ml_agree_within_window"),
                    timestamp=now,
                    correlation_window_seconds=self.ml_config.hybrid_correlation_window_seconds,
                    threshold_timestamp=alert.timestamp,
                    ml_timestamp=pending_ml["timestamp"],
                    confidence=pending_ml.get("confidence"),
                    suspicion_score=pending_ml.get("suspicion_score"),
                )
            )
            return events

        prediction_state = self.recent_prediction_state.get(alert.src_ip)
        seen_benign_prediction = bool(
            prediction_state is not None
            and not prediction_state.get("is_malicious")
            and self._within_correlation_window(
                prediction_state.get("timestamp"),
                now,
            )
        )
        self.pending_threshold_alerts[alert.src_ip] = self._build_pending_threshold_state(alert)
        self.pending_threshold_alerts[alert.src_ip]["seen_benign_prediction"] = seen_benign_prediction
        self.pending_threshold_alerts[alert.src_ip]["confidence"] = (
            prediction_state.get("confidence") if seen_benign_prediction else None
        )
        self.pending_threshold_alerts[alert.src_ip]["suspicion_score"] = (
            prediction_state.get("suspicion_score")
            if seen_benign_prediction
            else None
        )
        return events

    def handle_ml_alert(self, alert):
        if alert is None or not alert.src_ip:
            return []

        now = alert.timestamp
        details = dict(getattr(alert, "details", {}) or {})
        alert_reason = getattr(alert, "reason", "ml_alert_without_threshold_confirmation")
        events = self.expire_correlations(now)
        pending_threshold = self.pending_threshold_alerts.get(alert.src_ip)
        if (
            pending_threshold is not None
            and self._within_correlation_window(pending_threshold["timestamp"], now)
        ):
            del self.pending_threshold_alerts[alert.src_ip]
            events.append(
                HybridCorrelationEvent(
                    src_ip=alert.src_ip,
                    status=details.get("correlation_status", "threshold_plus_ml"),
                    reason=alert_reason,
                    timestamp=now,
                    correlation_window_seconds=self.ml_config.hybrid_correlation_window_seconds,
                    threshold_timestamp=pending_threshold["timestamp"],
                    ml_timestamp=alert.timestamp,
                    confidence=float(alert.confidence),
                    suspicion_score=float(alert.suspicion_score),
                )
            )
            return events

        self.pending_ml_alerts[alert.src_ip] = {
            "timestamp": alert.timestamp,
            "alert_type": alert.alert_type,
            "confidence": float(alert.confidence),
            "suspicion_score": float(alert.suspicion_score),
            "status": details.get("correlation_status", "ml_only"),
            "reason": alert_reason,
        }
        return events

    def expire_correlations(self, now):
        events = []
        expiry_window = self.ml_config.hybrid_correlation_window_seconds

        for src_ip, pending_threshold in list(self.pending_threshold_alerts.items()):
            if (now - pending_threshold["timestamp"]) <= expiry_window:
                continue
            status = "disagreement" if pending_threshold.get("seen_benign_prediction") else "threshold_only"
            reason = (
                "threshold_alert_with_benign_ml_prediction"
                if status == "disagreement"
                else "threshold_alert_without_ml_confirmation"
            )
            events.append(
                HybridCorrelationEvent(
                    src_ip=src_ip,
                    status=status,
                    reason=reason,
                    timestamp=now,
                    correlation_window_seconds=expiry_window,
                    threshold_timestamp=pending_threshold["timestamp"],
                    confidence=pending_threshold.get("confidence"),
                    suspicion_score=pending_threshold.get("suspicion_score"),
                )
            )
            del self.pending_threshold_alerts[src_ip]

        for src_ip, pending_ml in list(self.pending_ml_alerts.items()):
            if (now - pending_ml["timestamp"]) <= expiry_window:
                continue
            events.append(
                HybridCorrelationEvent(
                    src_ip=src_ip,
                    status=pending_ml.get("status", "ml_only"),
                    reason=pending_ml.get("reason", "ml_alert_without_threshold_confirmation"),
                    timestamp=now,
                    correlation_window_seconds=expiry_window,
                    ml_timestamp=pending_ml["timestamp"],
                    confidence=pending_ml.get("confidence"),
                    suspicion_score=pending_ml.get("suspicion_score"),
                )
            )
            del self.pending_ml_alerts[src_ip]

        self._prune_prediction_state(now)
        return events

    def _has_pending_threshold_agreement(self, src_ip, now):
        pending_threshold = self.pending_threshold_alerts.get(src_ip)
        if pending_threshold is None:
            return False
        return self._within_correlation_window(pending_threshold["timestamp"], now)

    def _record_prediction_state(self, prediction, threshold_context=None):
        threshold_context = dict(threshold_context or {})
        self.recent_prediction_state[prediction.src_ip] = {
            "timestamp": prediction.timestamp,
            "is_malicious": bool(prediction.is_malicious),
            "confidence": float(prediction.confidence),
            "suspicion_score": float(prediction.suspicion_score),
            "threshold_context_suspicious": bool(threshold_context.get("recon_suspicious")),
        }

    def _prune_prediction_state(self, now):
        retention_window = self.ml_config.hybrid_correlation_window_seconds * 2
        for src_ip, state in list(self.recent_prediction_state.items()):
            if (now - state.get("timestamp", 0.0)) > retention_window:
                del self.recent_prediction_state[src_ip]
        for src_ip, window in list(self.ml_only_signal_history.items()):
            while window and (now - window[0]) > retention_window:
                window.popleft()
            if not window:
                del self.ml_only_signal_history[src_ip]

    def _reset_runtime_mode_state(self):
        self.pending_threshold_alerts.clear()
        self.pending_ml_alerts.clear()
        self.recent_prediction_state.clear()
        self.last_alert_at.clear()
        self.last_inference_at.clear()
        self.last_inference_observation.clear()
        self.ml_only_signal_history.clear()

    def reset_runtime_session(self):
        self.observed_packets.clear()
        self._reset_runtime_mode_state()
        self.feature_extractor.reset()

    def _within_correlation_window(self, earlier_timestamp, later_timestamp):
        if earlier_timestamp is None or later_timestamp is None:
            return False
        return (later_timestamp - earlier_timestamp) <= self.ml_config.hybrid_correlation_window_seconds

    @staticmethod
    def _rule_family_from_alert(alert):
        if alert is None:
            return ""
        alert_text = "%s %s" % (
            getattr(alert, "alert_type", "") or "",
            getattr(alert, "reason", "") or "",
        )
        normalized = alert_text.strip().lower()
        if any(token in normalized for token in ("scan", "sweep", "unanswered_syn", "failed_connection")):
            return "recon"
        if any(token in normalized for token in ("flood", "packet_rate", "syn_rate")):
            return "volumetric"
        if normalized:
            return "suspicious"
        return ""

    def _build_pending_threshold_state(self, alert, threshold_context=None):
        threshold_context = dict(threshold_context or {})
        return {
            "timestamp": alert.timestamp,
            "alert_type": alert.alert_type,
            "severity": getattr(alert, "severity", "high"),
            "reason": getattr(alert, "reason", ""),
            "threshold_rule_family": threshold_context.get(
                "threshold_rule_family",
                self._rule_family_from_alert(alert),
            ),
            "seen_benign_prediction": False,
            "confidence": None,
            "suspicion_score": None,
        }

    def _record_ml_signal(self, src_ip, now):
        window = self.ml_only_signal_history[src_ip]
        retention_window = self.ml_config.hybrid_correlation_window_seconds * 2
        while window and (now - window[0]) > retention_window:
            window.popleft()
        window.append(now)
        return len(window)

    @staticmethod
    def _validated_mode(mode):
        normalized = normalize_ids_mode_internal(mode, default="threshold_only")
        if normalized not in VALID_ML_MODES:
            return "threshold_only"
        return normalized

    @staticmethod
    def _validated_hybrid_policy(policy):
        normalized = (policy or "alert_only").strip().lower()
        if normalized not in VALID_HYBRID_POLICIES:
            return "alert_only"
        return normalized


def decide(pipeline, packet_metadata, threshold_alerts=None, threshold_context=None):
    """Convenience wrapper for one-shot ML pipeline inspection."""

    return pipeline.inspect(
        packet_metadata,
        threshold_alerts=threshold_alerts,
        threshold_context=threshold_context,
    )
