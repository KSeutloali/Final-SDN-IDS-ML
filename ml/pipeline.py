"""Orchestration for optional ML inference alongside the threshold IDS."""

from collections import defaultdict, deque
from dataclasses import dataclass, field
import ipaddress

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
        self.anomaly_bundle = load_model(
            getattr(ml_config, "anomaly_model_path", ""),
            fallback_feature_names=RUNTIME_FEATURE_NAMES,
            fallback_positive_labels=("anomalous",),
        )
        self.inference_engine = ModelInferenceEngine(
            self.model_bundle,
            ml_config,
            anomaly_bundle=self.anomaly_bundle,
            mode=getattr(ml_config, "inference_mode", "classifier_only"),
        )
        self.observed_packets = {}
        self.last_inference_at = {}
        self.last_inference_observation = {}
        self.last_alert_at = {}
        self.last_alert_state = {}
        self.pending_threshold_alerts = {}
        self.pending_ml_alerts = {}
        self.recent_prediction_state = {}
        self.decision_window_history = defaultdict(deque)

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
            "hybrid_block_enabled": bool(
                getattr(self.ml_config, "hybrid_block_enabled", True)
            ),
            "hybrid_anomaly_block_enabled": bool(
                getattr(self.ml_config, "hybrid_anomaly_block_enabled", True)
            ),
            "require_threshold_for_ml_block": bool(
                getattr(self.ml_config, "require_threshold_for_ml_block", False)
            ),
            "enable_random_forest": bool(
                getattr(self.ml_config, "enable_random_forest", True)
            ),
            "enable_isolation_forest": bool(
                getattr(self.ml_config, "enable_isolation_forest", True)
            ),
            "model_available": self.inference_engine.is_available,
            "classifier_model_available": self.model_bundle.is_available,
            "model_path": self.model_bundle.source_path or self.ml_config.model_path,
            "model_error": self.model_bundle.load_error,
            "inference_mode": getattr(self.inference_engine, "selected_mode", "classifier_only"),
            "effective_inference_mode": getattr(
                self.inference_engine,
                "effective_mode",
                "unavailable",
            ),
            "hybrid_classifier_block_threshold": float(
                getattr(self.ml_config, "hybrid_classifier_block_threshold", 0.0)
            ),
            "hybrid_anomaly_support_threshold": float(
                getattr(self.ml_config, "hybrid_anomaly_support_threshold", 0.0)
            ),
            "hybrid_block_repeat_count": int(
                getattr(self.ml_config, "hybrid_block_repeat_count", 0)
            ),
            "hybrid_threshold_near_miss_repeat_count": int(
                self._hybrid_threshold_near_miss_repeat_count()
            ),
            "hybrid_known_family_block_enabled": bool(
                getattr(self.ml_config, "hybrid_known_family_block_enabled", False)
            ),
            "hybrid_block_eligible_families": tuple(
                getattr(self.ml_config, "hybrid_block_eligible_families", ())
            ),
            "hybrid_anomaly_trend_threshold": float(
                getattr(self.ml_config, "hybrid_anomaly_trend_threshold", 0.0)
            ),
            "hybrid_anomaly_only_block_enabled": bool(
                getattr(self.ml_config, "hybrid_anomaly_only_block_enabled", False)
            ),
            "hybrid_anomaly_only_block_threshold": float(
                getattr(self.ml_config, "hybrid_anomaly_only_block_threshold", 0.0)
            ),
            "hybrid_anomaly_only_required_windows": int(
                self._hybrid_anomaly_only_required_windows()
            ),
            "hybrid_memory_window_seconds": float(self._decision_memory_window_seconds()),
            "anomaly_model_available": bool(
                self.anomaly_bundle.is_available
                and getattr(self.ml_config, "enable_isolation_forest", True)
            ),
            "anomaly_model_path": self.anomaly_bundle.source_path or getattr(
                self.ml_config,
                "anomaly_model_path",
                "",
            ),
            "anomaly_model_error": self.anomaly_bundle.load_error,
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

        decision_memory = self._record_decision_window(
            prediction,
            threshold_context=threshold_context,
        )
        alert = self._build_alert(
            prediction,
            threshold_context=threshold_context,
            decision_memory=decision_memory,
        )
        if alert is None:
            return MLInspectionResult(
                feature_snapshot=feature_snapshot,
                prediction=prediction,
            )
        if self._is_alert_suppressed(alert):
            return MLInspectionResult(
                feature_snapshot=feature_snapshot,
                prediction=prediction,
            )
        self.last_alert_at[prediction.src_ip] = prediction.timestamp
        self.last_alert_state[prediction.src_ip] = {
            "decision": alert.decision,
            "reason": alert.reason,
            "severity": alert.severity,
            "should_mitigate": bool(alert.should_mitigate),
        }
        return MLInspectionResult(
            feature_snapshot=feature_snapshot,
            prediction=prediction,
            alert=alert,
        )

    def _build_alert(self, prediction, threshold_context=None, decision_memory=None):
        threshold_context = dict(threshold_context or {})
        decision_memory = dict(decision_memory or {})
        threshold_triggered = bool(threshold_context.get("threshold_triggered"))
        threshold_suspicious = bool(threshold_context.get("recon_suspicious"))
        agreement = threshold_triggered or self._has_pending_threshold_agreement(
            prediction.src_ip,
            prediction.timestamp,
        )
        explanations = dict(getattr(prediction, "explanations", {}) or {})
        effective_mode = self.effective_mode()
        should_mitigate = False
        severity = "medium"
        decision = "log_only"
        reason = prediction.reason
        correlation_status = "ml_only"
        known_class_match = False
        repeat_count = int(decision_memory.get("signal_window_count", 0) or 0)
        threshold_suspicious_repeat_count = int(
            decision_memory.get("threshold_suspicious_repeat_count", 0) or 0
        )
        threshold_near_miss_count = int(
            decision_memory.get("threshold_near_miss_count", 0) or 0
        )
        anomaly_only_repeat_count = int(
            decision_memory.get("anomaly_only_repeat_count", 0) or 0
        )
        anomalous_window_count = int(
            decision_memory.get("anomalous_window_count", 0) or 0
        )
        anomaly_trend_delta = float(
            decision_memory.get("anomaly_trend_delta", 0.0) or 0.0
        )
        anomaly_trend_rising = bool(decision_memory.get("anomaly_trend_rising", False))
        anomaly_score = float(getattr(prediction, "anomaly_score", 0.0) or 0.0)
        is_anomalous = bool(getattr(prediction, "is_anomalous", False))
        predicted_family = str(getattr(prediction, "predicted_family", "") or "")
        classifier_reason = str(explanations.get("classifier_reason", "") or "")
        classifier_detected = bool(explanations.get("classifier_detected")) or (
            classifier_reason not in ("", "ml_benign_prediction")
        )
        classifier_confidence = float(
            explanations.get("classifier_confidence", prediction.confidence) or 0.0
        )
        classifier_suspicion_score = float(
            explanations.get(
                "classifier_suspicion_score",
                prediction.suspicion_score,
            )
            or 0.0
        )
        anomaly_reason = str(explanations.get("anomaly_reason", "") or "")
        anomaly_high = is_anomalous and (
            anomaly_score >= float(self.ml_config.anomaly_score_threshold)
        )
        hybrid_anomaly_support = is_anomalous and (
            anomaly_score >= float(self.ml_config.hybrid_anomaly_support_threshold)
        )
        classifier_high_confidence = classifier_detected and (
            classifier_suspicion_score >= float(self.ml_config.confidence_threshold)
        )
        anomaly_only_signal = is_anomalous and not classifier_detected
        abnormal_feature_summary = self._summarize_abnormal_features(prediction)
        hybrid_block_support = {"eligible": False, "reason": "", "reasons": []}
        threshold_signal_present = bool(threshold_triggered or threshold_suspicious or agreement)
        classifier_block_signal = bool(
            classifier_detected
            and classifier_suspicion_score
            >= float(getattr(self.ml_config, "hybrid_classifier_block_threshold", 0.0))
        )
        anomaly_block_signal = bool(
            is_anomalous
            and anomaly_score
            >= float(getattr(self.ml_config, "hybrid_anomaly_support_threshold", 0.0))
        )
        anomaly_only_block_signal = bool(
            anomaly_only_signal
            and is_anomalous
            and anomaly_score
            >= float(getattr(self.ml_config, "hybrid_anomaly_only_block_threshold", 0.0))
        )
        low_confidence_suspicious = (
            not prediction.is_malicious
            and float(prediction.suspicion_score) >= float(self.ml_config.alert_only_threshold)
        )

        if effective_mode == "ml_only":
            if anomaly_only_signal:
                correlation_status = "anomaly_only"
                decision = "anomaly_only_alert"
                reason = anomaly_reason or prediction.reason
                if anomaly_only_repeat_count >= self.ml_config.anomaly_only_escalation_count:
                    severity = "high"
                    reason = "repeated_anomaly_pattern_detected"
            else:
                correlation_status = "anomaly_only" if low_confidence_suspicious else "ml_only"
                decision = "anomaly_only_alert" if low_confidence_suspicious else "ml_only_alert"
                reason = (
                    "ml_suspicion_above_alert_only_threshold"
                    if low_confidence_suspicious
                    else prediction.reason
                )
                if classifier_high_confidence and anomaly_high:
                    severity = "critical"
                    reason = (
                        "classifier_family_supported_by_high_anomaly_score"
                        if predicted_family
                        else "classifier_prediction_supported_by_high_anomaly_score"
                    )
            if (
                not anomaly_only_signal
                and prediction.is_malicious
                and classifier_detected
                and classifier_suspicion_score >= self.ml_config.mitigation_threshold
            ):
                should_mitigate = True
                severity = "high"
                decision = "ml_only_block"
                correlation_status = "ml_only"
        elif effective_mode == "hybrid":
            if agreement:
                severity = "critical"
                decision = "threshold_enriched_by_ml"
                reason = (
                    "threshold_triggered_with_classifier_and_anomaly_context"
                    if classifier_high_confidence and anomaly_high
                    else "threshold_triggered_with_ml_context"
                )
                known_class_match = classifier_detected and bool(
                    threshold_context.get("threshold_rule_family")
                )
                correlation_status = (
                    "known_class_match" if known_class_match else "threshold_plus_ml"
                )
            elif threshold_suspicious:
                severity = "critical" if classifier_high_confidence and anomaly_high else "high"
                decision = "threshold_enriched_by_ml"
                if anomaly_only_signal:
                    reason = "subthreshold_recon_pattern_supported_by_anomaly"
                elif classifier_high_confidence and anomaly_high:
                    reason = "subthreshold_recon_pattern_enriched_by_classifier_and_anomaly"
                else:
                    reason = "subthreshold_recon_pattern_enriched_by_ml"
                correlation_status = "threshold_enriched_by_ml"
                hybrid_block_support = self._evaluate_hybrid_block_support(
                    prediction=prediction,
                    threshold_context=threshold_context,
                    threshold_triggered=threshold_triggered,
                    threshold_suspicious=threshold_suspicious,
                    classifier_detected=classifier_detected,
                    classifier_suspicion_score=classifier_suspicion_score,
                    predicted_family=predicted_family,
                    is_anomalous=is_anomalous,
                    anomaly_score=anomaly_score,
                    decision_memory=decision_memory,
                )
                if hybrid_block_support["eligible"]:
                    should_mitigate = True
                    severity = "critical"
                    decision = self._hybrid_block_decision(
                        threshold_signal_present=threshold_signal_present,
                        classifier_block_signal=classifier_block_signal,
                        anomaly_block_signal=anomaly_block_signal,
                        anomaly_only_block_signal=anomaly_only_block_signal,
                    )
                    reason = hybrid_block_support["reason"]
            else:
                if anomaly_only_signal:
                    correlation_status = "anomaly_only"
                    decision = "anomaly_only_alert"
                    reason = anomaly_reason or prediction.reason
                    if anomaly_only_repeat_count >= self.ml_config.anomaly_only_escalation_count:
                        severity = "high"
                        reason = "repeated_anomaly_pattern_detected"
                    hybrid_block_support = self._evaluate_hybrid_block_support(
                        prediction=prediction,
                        threshold_context=threshold_context,
                        threshold_triggered=threshold_triggered,
                        threshold_suspicious=threshold_suspicious,
                        classifier_detected=classifier_detected,
                        classifier_suspicion_score=classifier_suspicion_score,
                        predicted_family=predicted_family,
                        is_anomalous=is_anomalous,
                        anomaly_score=anomaly_score,
                        decision_memory=decision_memory,
                    )
                    if hybrid_block_support["eligible"]:
                        should_mitigate = True
                        severity = "critical"
                        decision = self._hybrid_block_decision(
                            threshold_signal_present=threshold_signal_present,
                            classifier_block_signal=classifier_block_signal,
                            anomaly_block_signal=anomaly_block_signal,
                            anomaly_only_block_signal=anomaly_only_block_signal,
                        )
                        reason = hybrid_block_support["reason"]
                else:
                    correlation_status = "anomaly_only" if low_confidence_suspicious else "ml_only"
                    decision = "anomaly_only_alert" if low_confidence_suspicious else "ml_only_alert"
                    reason = (
                        "ml_suspicion_above_alert_only_threshold"
                        if low_confidence_suspicious
                        else prediction.reason
                    )
                    if (
                        classifier_high_confidence
                        and anomaly_high
                        and (predicted_family or self.hybrid_policy != "alert_only")
                    ):
                        if predicted_family:
                            severity = "critical"
                            reason = "classifier_family_supported_by_high_anomaly_score"
                        else:
                            correlation_status = "ml_anomaly_consensus"
                            severity = "high"
                            reason = "classifier_anomaly_consensus_without_threshold_context"
                    elif (
                        classifier_detected
                        and not predicted_family
                        and self.hybrid_policy != "high_confidence_block"
                    ):
                        return None
                    hybrid_block_support = self._evaluate_hybrid_block_support(
                        prediction=prediction,
                        threshold_context=threshold_context,
                        threshold_triggered=threshold_triggered,
                        threshold_suspicious=threshold_suspicious,
                        classifier_detected=classifier_detected,
                        classifier_suspicion_score=classifier_suspicion_score,
                        predicted_family=predicted_family,
                        is_anomalous=is_anomalous,
                        anomaly_score=anomaly_score,
                        decision_memory=decision_memory,
                    )
                    if hybrid_block_support["eligible"]:
                        should_mitigate = True
                        severity = "critical"
                        decision = self._hybrid_block_decision(
                            threshold_signal_present=threshold_signal_present,
                            classifier_block_signal=classifier_block_signal,
                            anomaly_block_signal=anomaly_block_signal,
                            anomaly_only_block_signal=anomaly_only_block_signal,
                        )
                        reason = hybrid_block_support["reason"]

        if should_mitigate and reason == prediction.reason:
            reason = "ml_confidence_above_mitigation_threshold"

        block_suppression_reason = ""
        if should_mitigate:
            block_suppression_reason = self._block_suppression_reason(
                prediction.src_ip,
                threshold_context=threshold_context,
            )
            if block_suppression_reason:
                should_mitigate = False
                severity = "high" if severity == "critical" else severity
                if anomaly_only_signal:
                    decision = "anomaly_only_alert"
                elif threshold_signal_present:
                    decision = "threshold_enriched_by_ml"
                else:
                    decision = "ml_only_alert"

        detection_sources = []
        if threshold_signal_present:
            detection_sources.append("threshold")
        if classifier_detected:
            detection_sources.append("random_forest")
        if is_anomalous:
            detection_sources.append("isolation_forest")
        final_action = "quarantine" if should_mitigate else (
            "alert_only" if decision != "log_only" else "allow"
        )
        final_decision = decision
        alert_type = self._resolve_alert_type(
            detection_sources=detection_sources,
            decision=final_decision,
        )

        explanation_payload = self._build_alert_explanation(
            prediction,
            threshold_context=threshold_context,
            correlation_status=correlation_status,
            reason=reason,
            agreement=agreement,
            should_mitigate=should_mitigate,
        )
        details = {
            "agreement_with_threshold": agreement,
            "hybrid_status": correlation_status,
            "correlation_status": correlation_status,
            "detection_sources": list(detection_sources),
            "final_decision": final_decision,
            "final_action": final_action,
            "decision_reason": reason,
            "alert_type": alert_type,
            "source_ip": prediction.src_ip,
            "destination_ip": threshold_context.get("dst_ip", ""),
            "source_mac": threshold_context.get("src_mac", ""),
            "destination_mac": threshold_context.get("dst_mac", ""),
            "threshold_triggered": threshold_triggered,
            "threshold_reason": threshold_context.get("threshold_reason", ""),
            "threshold_alert_type": threshold_context.get("threshold_alert_type", ""),
            "threshold_rule_family": threshold_context.get("threshold_rule_family", ""),
            "threshold_severity": threshold_context.get("threshold_severity", ""),
            "threshold_recent_event_count": int(
                threshold_context.get("threshold_recent_event_count", 0) or 0
            ),
            "threshold_context_suspicious": threshold_suspicious,
            "threshold_auto_quarantine_eligible": bool(
                threshold_context.get("threshold_auto_quarantine_eligible", True)
            ),
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
            "repeated_window_count": repeat_count,
            "repeated_threshold_suspicious_windows": threshold_suspicious_repeat_count,
            "repeated_threshold_near_miss_windows": threshold_near_miss_count,
            "repeated_anomaly_only_windows": anomaly_only_repeat_count,
            "repeated_anomalous_windows": anomalous_window_count,
            "anomaly_trend_delta": round(float(anomaly_trend_delta), 6),
            "anomaly_trend_rising": anomaly_trend_rising,
            "hybrid_policy": self.hybrid_policy,
            "hybrid_block_eligible": bool(hybrid_block_support.get("eligible", False)),
            "hybrid_block_reasons": list(hybrid_block_support.get("reasons", [])),
            "hybrid_support_signal_count": int(
                hybrid_block_support.get("support_count", 0) or 0
            ),
            "hybrid_context_signal_count": int(
                hybrid_block_support.get("context_support_count", 0) or 0
            ),
            "block_decision_path": hybrid_block_support.get("decision_path", ""),
            "final_block_reason": reason if should_mitigate else "",
            "block_suppressed": bool(block_suppression_reason),
            "block_suppression_reason": block_suppression_reason,
            "hybrid_block_enabled": bool(
                getattr(self.ml_config, "hybrid_block_enabled", True)
            ),
            "hybrid_anomaly_block_enabled": bool(
                getattr(self.ml_config, "hybrid_anomaly_block_enabled", True)
            ),
            "require_threshold_for_ml_block": bool(
                getattr(self.ml_config, "require_threshold_for_ml_block", False)
            ),
            "hybrid_classifier_block_threshold": round(
                float(self.ml_config.hybrid_classifier_block_threshold),
                6,
            ),
            "hybrid_anomaly_support_threshold": round(
                float(self.ml_config.hybrid_anomaly_support_threshold),
                6,
            ),
            "hybrid_anomaly_trend_threshold": round(
                float(getattr(self.ml_config, "hybrid_anomaly_trend_threshold", 0.0)),
                6,
            ),
            "hybrid_anomaly_only_block_enabled": bool(
                getattr(self.ml_config, "hybrid_anomaly_only_block_enabled", False)
            ),
            "hybrid_anomaly_only_block_threshold": round(
                float(getattr(self.ml_config, "hybrid_anomaly_only_block_threshold", 0.0)),
                6,
            ),
            "hybrid_block_repeat_count": int(self.ml_config.hybrid_block_repeat_count),
            "hybrid_threshold_near_miss_repeat_count": int(
                self._hybrid_threshold_near_miss_repeat_count()
            ),
            "hybrid_anomaly_only_required_windows": int(
                self._hybrid_anomaly_only_required_windows()
            ),
            "hybrid_memory_window_seconds": round(
                float(self._decision_memory_window_seconds()),
                3,
            ),
            "capture_recommended": correlation_status in ("ml_only", "anomaly_only"),
            "watchlist_candidate": correlation_status in (
                "threshold_enriched_by_ml",
                "ml_only",
                "anomaly_only",
            ),
            "confidence": round(float(prediction.confidence), 6),
            "suspicion_score": round(float(prediction.suspicion_score), 6),
            "label": prediction.label,
            "predicted_family": predicted_family,
            "model_mode": getattr(self.inference_engine, "effective_mode", "unavailable"),
            "model_mode_requested": getattr(self.inference_engine, "selected_mode", "classifier_only"),
            "feature_window_size_seconds": int(
                getattr(self.ml_config, "feature_window_seconds", 0) or 0
            ),
            "anomaly_score": round(float(anomaly_score), 6),
            "is_anomalous": is_anomalous,
            "hybrid_anomaly_support": hybrid_anomaly_support,
            "classifier_detected": classifier_detected,
            "classifier_confidence": round(float(classifier_confidence), 6),
            "classifier_suspicion_score": round(float(classifier_suspicion_score), 6),
            "random_forest_prediction": prediction.label,
            "random_forest_confidence": round(float(classifier_confidence), 6),
            "random_forest_suspicion_score": round(
                float(classifier_suspicion_score),
                6,
            ),
            "isolation_forest_anomalous": is_anomalous,
            "isolation_forest_anomaly_score": round(float(anomaly_score), 6),
            "anomaly_reason": anomaly_reason,
            "abnormal_feature_summary": abnormal_feature_summary,
            "abnormal_feature_details": explanation_payload["feature_context"].get(
                "abnormal_features",
                [],
            ),
            "baseline_feature_comparisons": explanation_payload["feature_context"].get(
                "baseline_comparisons",
                [],
            ),
            "top_model_features": explanation_payload["feature_context"].get(
                "top_model_features",
                [],
            ),
            "explanation_version": explanation_payload.get("version", ""),
            "explanation_summary": explanation_payload.get("summary", ""),
            "explanation": explanation_payload,
            "explanations": explanations,
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
            alert_type=alert_type,
            reason=reason,
            severity=severity,
            timestamp=prediction.timestamp,
            confidence=prediction.confidence,
            suspicion_score=prediction.suspicion_score,
            label=prediction.label,
            model_name=prediction.model_name,
            decision=final_decision,
            should_mitigate=should_mitigate,
            details=details,
        )

    @staticmethod
    def _hybrid_block_decision(
        threshold_signal_present,
        classifier_block_signal,
        anomaly_block_signal,
        anomaly_only_block_signal,
    ):
        if threshold_signal_present and classifier_block_signal and anomaly_block_signal:
            return "full_hybrid_block"
        if threshold_signal_present and classifier_block_signal:
            return "threshold_rf_block"
        if threshold_signal_present and anomaly_block_signal:
            return "threshold_if_block"
        if classifier_block_signal and anomaly_block_signal:
            return "rf_if_consensus_block"
        if anomaly_only_block_signal:
            return "anomaly_only_block"
        return "ml_only_block"

    @staticmethod
    def _resolve_alert_type(detection_sources, decision):
        sources = tuple(sorted(set(detection_sources or [])))
        if sources == ("threshold",):
            return "threshold_detected"
        if sources == ("random_forest",):
            return "random_forest_detected"
        if sources == ("isolation_forest",):
            return "isolation_forest_detected"
        if sources == ("random_forest", "threshold"):
            return "hybrid_threshold_rf_detected"
        if sources == ("isolation_forest", "threshold"):
            return "hybrid_threshold_if_detected"
        if sources == ("isolation_forest", "random_forest"):
            return "hybrid_rf_if_detected"
        if sources == ("isolation_forest", "random_forest", "threshold"):
            return "hybrid_full_detected"
        if decision == "anomaly_only_alert" or decision == "anomaly_only_block":
            return "isolation_forest_detected"
        return "random_forest_detected"

    @staticmethod
    def _block_suppression_reason(src_ip, threshold_context=None):
        threshold_context = dict(threshold_context or {})
        address = str(src_ip or "").strip()
        if not address:
            return "missing_source_ip"
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return "invalid_source_ip"
        if parsed.is_unspecified or parsed.is_loopback:
            return "controller_or_unspecified_source_ip"
        if parsed.is_multicast:
            return "multicast_source_ip"
        if parsed == ipaddress.ip_address("255.255.255.255"):
            return "broadcast_source_ip"
        internal_subnet = str(threshold_context.get("internal_subnet", "") or "").strip()
        if internal_subnet:
            try:
                internal_network = ipaddress.ip_network(internal_subnet, strict=False)
            except ValueError:
                internal_network = None
            if internal_network is not None:
                if parsed == internal_network.network_address:
                    return "network_address_source_ip"
                if parsed == internal_network.broadcast_address:
                    return "broadcast_source_ip"
        protected = set(
            item.strip()
            for item in threshold_context.get("protected_source_ips", [])
            if str(item).strip()
        )
        if address in protected:
            return "protected_source_ip"
        return ""

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

    def _is_alert_suppressed(self, alert):
        if alert is None or not alert.src_ip:
            return False
        previous = self.last_alert_at.get(alert.src_ip)
        if previous is None:
            return False
        if (alert.timestamp - previous) >= self.ml_config.alert_suppression_seconds:
            return False

        previous_state = dict(self.last_alert_state.get(alert.src_ip) or {})
        if alert.should_mitigate and not previous_state.get("should_mitigate"):
            return False
        if self._severity_rank(alert.severity) > self._severity_rank(
            previous_state.get("severity", "")
        ):
            return False
        if alert.decision != previous_state.get("decision"):
            return False
        if alert.reason != previous_state.get("reason"):
            return False
        return True

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
        decision_window = self._decision_memory_window_seconds()
        for src_ip, window in list(self.decision_window_history.items()):
            while window and (now - window[0].get("timestamp", 0.0)) > decision_window:
                window.popleft()
            if not window:
                del self.decision_window_history[src_ip]

    def _reset_runtime_mode_state(self):
        self.pending_threshold_alerts.clear()
        self.pending_ml_alerts.clear()
        self.recent_prediction_state.clear()
        self.last_alert_at.clear()
        self.last_alert_state.clear()
        self.last_inference_at.clear()
        self.last_inference_observation.clear()
        self.decision_window_history.clear()

    def reset_runtime_session(self):
        self.observed_packets.clear()
        self._reset_runtime_mode_state()
        self.feature_extractor.reset()

    def _evaluate_hybrid_block_support(
        self,
        prediction,
        threshold_context,
        threshold_triggered,
        threshold_suspicious,
        classifier_detected,
        classifier_suspicion_score,
        predicted_family,
        is_anomalous,
        anomaly_score,
        decision_memory,
    ):
        threshold_context = dict(threshold_context or {})
        decision_memory = dict(decision_memory or {})
        empty = {
            "eligible": False,
            "reason": "",
            "reasons": [],
            "decision_path": "",
            "support_count": 0,
            "context_support_count": 0,
        }
        if not bool(getattr(self.ml_config, "hybrid_block_enabled", True)):
            return empty
        if self.hybrid_policy not in ("high_confidence_block", "layered_consensus"):
            return empty
        if bool(getattr(self.ml_config, "require_threshold_for_ml_block", False)) and not (
            threshold_suspicious or threshold_triggered
        ):
            return empty
        if not bool(getattr(prediction, "is_malicious", False)):
            return empty
        if (
            str(threshold_context.get("threshold_reason", "") or "")
            == "icmp_sweep_threshold_exceeded"
            and not bool(threshold_context.get("threshold_auto_quarantine_eligible", True))
        ):
            return empty

        classifier_threshold = float(self.ml_config.hybrid_classifier_block_threshold)
        anomaly_support_threshold = float(self.ml_config.hybrid_anomaly_support_threshold)
        anomaly_block_threshold = max(
            float(
                getattr(self.ml_config, "hybrid_anomaly_only_block_threshold", 0.0) or 0.0
            ),
            anomaly_support_threshold,
        )
        repeat_threshold = int(max(1, self.ml_config.hybrid_block_repeat_count))
        near_miss_repeat_threshold = int(self._hybrid_threshold_near_miss_repeat_count())
        anomaly_only_required_windows = int(self._hybrid_anomaly_only_required_windows())
        recon_score = int(threshold_context.get("recon_suspicion_score", 0) or 0)
        anomaly_block_enabled = bool(
            getattr(self.ml_config, "hybrid_anomaly_block_enabled", True)
        )
        high_classifier = bool(classifier_detected) and (
            float(classifier_suspicion_score) >= classifier_threshold
        )
        high_anomaly = anomaly_block_enabled and bool(is_anomalous) and (
            float(anomaly_score) >= anomaly_support_threshold
        )
        very_high_anomaly = anomaly_block_enabled and bool(is_anomalous) and (
            float(anomaly_score) >= anomaly_block_threshold
        )
        repeat_count = int(decision_memory.get("signal_window_count", 0) or 0)
        repeated_signal = repeat_count >= repeat_threshold
        threshold_suspicious_repeat_count = int(
            decision_memory.get("threshold_suspicious_repeat_count", 0) or 0
        )
        threshold_near_miss_count = int(
            decision_memory.get("threshold_near_miss_count", 0) or 0
        )
        anomaly_only_repeat_count = int(
            decision_memory.get("anomaly_only_repeat_count", 0) or 0
        )
        anomalous_window_count = int(
            decision_memory.get("anomalous_window_count", 0) or 0
        )
        repeated_threshold_suspicious = threshold_suspicious_repeat_count >= repeat_threshold
        repeated_threshold_near_miss = threshold_near_miss_count >= near_miss_repeat_threshold
        repeated_anomaly_only = anomaly_only_repeat_count >= max(
            repeat_threshold,
            int(getattr(self.ml_config, "anomaly_only_escalation_count", 1) or 1),
        )
        anomaly_trend_rising = bool(decision_memory.get("anomaly_trend_rising", False))
        strong_anomaly_only_persistence = (
            repeated_anomaly_only
            and anomaly_trend_rising
            and repeated_signal
            and anomalous_window_count >= anomaly_only_required_windows
        )
        known_family = self._is_block_eligible_family(predicted_family)
        reasons = []
        if threshold_suspicious:
            reasons.append("threshold_suspicious_context")
        if high_classifier:
            reasons.append("classifier_confidence_support")
        if high_anomaly:
            reasons.append("anomaly_score_support")
        if very_high_anomaly:
            reasons.append("very_high_anomaly_score")
        if repeated_signal:
            reasons.append("repeated_ml_windows")
        if repeated_threshold_suspicious:
            reasons.append("repeated_threshold_suspicious_windows")
        if repeated_threshold_near_miss:
            reasons.append("repeated_threshold_near_miss_windows")
        if repeated_anomaly_only:
            reasons.append("repeated_anomaly_only_windows")
        if anomalous_window_count >= anomaly_only_required_windows:
            reasons.append("repeated_anomalous_windows")
        if anomaly_trend_rising:
            reasons.append("rising_anomaly_trend")
        if recon_score >= 2:
            reasons.append("elevated_threshold_recon_score")
        if known_family:
            reasons.append("known_malicious_family")

        threshold_context_supports_block = sum(
            int(value)
            for value in (
                high_anomaly,
                repeated_signal,
                repeated_threshold_suspicious,
                repeated_threshold_near_miss,
                anomaly_trend_rising,
                known_family,
                recon_score >= 2,
            )
        )
        classifier_context_supports_block = sum(
            int(value)
            for value in (
                high_anomaly,
                repeated_signal,
                repeated_threshold_suspicious,
                repeated_threshold_near_miss,
                anomaly_trend_rising,
            )
        )

        if self.hybrid_policy == "layered_consensus":
            if threshold_suspicious and high_classifier and threshold_context_supports_block:
                return {
                    "eligible": True,
                    "reason": "threshold_suspicion_elevated_by_strong_ml_evidence",
                    "reasons": reasons,
                    "decision_path": "threshold_suspicion_elevated_by_ml",
                    "support_count": len(reasons),
                    "context_support_count": threshold_context_supports_block,
                }
            if threshold_suspicious and high_anomaly and threshold_context_supports_block:
                return {
                    "eligible": True,
                    "reason": "threshold_suspicion_elevated_by_anomaly_evidence",
                    "reasons": reasons,
                    "decision_path": "threshold_suspicion_elevated_by_if",
                    "support_count": len(reasons),
                    "context_support_count": threshold_context_supports_block,
                }
            if (
                known_family
                and high_classifier
                and high_anomaly
                and classifier_context_supports_block >= 2
            ):
                return {
                    "eligible": True,
                    "reason": "known_family_prediction_supported_by_anomaly_context",
                    "reasons": reasons,
                    "decision_path": "classifier_led_known_family_block",
                    "support_count": len(reasons),
                    "context_support_count": classifier_context_supports_block,
                }
            if (
                not threshold_suspicious
                and not threshold_triggered
                and high_classifier
                and high_anomaly
                and repeated_signal
                and repeated_threshold_near_miss
                and anomaly_trend_rising
            ):
                return {
                    "eligible": True,
                    "reason": "repeated_classifier_anomaly_consensus_supported_by_threshold_near_misses",
                    "reasons": reasons,
                    "decision_path": "classifier_anomaly_consensus_block",
                    "support_count": len(reasons),
                    "context_support_count": 4,
                }
            if (
                not threshold_suspicious
                and not threshold_triggered
                and high_classifier
                and high_anomaly
                and repeated_signal
            ):
                return {
                    "eligible": True,
                    "reason": "classifier_and_anomaly_consensus_without_threshold_trigger",
                    "reasons": reasons,
                    "decision_path": "rf_if_consensus_block",
                    "support_count": len(reasons),
                    "context_support_count": max(2, classifier_context_supports_block),
                }
            if (
                getattr(self.ml_config, "hybrid_anomaly_only_block_enabled", False)
                and not classifier_detected
                and very_high_anomaly
                and repeated_anomaly_only
                and anomaly_trend_rising
                and repeated_threshold_near_miss
            ):
                return {
                    "eligible": True,
                    "reason": "repeated_high_anomaly_pattern_supported_by_threshold_near_misses",
                    "reasons": reasons,
                    "decision_path": "anomaly_only_narrow_escalation",
                    "support_count": len(reasons),
                    "context_support_count": 4,
                }
            if (
                getattr(self.ml_config, "hybrid_anomaly_only_block_enabled", False)
                and not threshold_suspicious
                and not threshold_triggered
                and not classifier_detected
                and very_high_anomaly
                and strong_anomaly_only_persistence
            ):
                return {
                    "eligible": True,
                    "reason": "repeated_high_anomaly_pattern_without_threshold_signal",
                    "reasons": reasons,
                    "decision_path": "anomaly_only_strong_persistence_block",
                    "support_count": len(reasons),
                    "context_support_count": 4,
                }
            return empty

        if threshold_suspicious and high_classifier and threshold_context_supports_block:
            return {
                "eligible": True,
                "reason": "threshold_suspicion_elevated_by_high_confidence_classifier",
                "reasons": reasons,
                "decision_path": "threshold_suspicion_elevated_by_ml",
                "support_count": len(reasons),
                "context_support_count": threshold_context_supports_block,
            }
        if threshold_suspicious and high_anomaly and threshold_context_supports_block:
            return {
                "eligible": True,
                "reason": "threshold_suspicion_elevated_by_anomaly_evidence",
                "reasons": reasons,
                "decision_path": "threshold_suspicion_elevated_by_if",
                "support_count": len(reasons),
                "context_support_count": threshold_context_supports_block,
            }
        if (
            known_family
            and high_classifier
            and high_anomaly
            and classifier_context_supports_block
        ):
            return {
                "eligible": True,
                "reason": "known_family_prediction_supported_by_anomaly_context",
                "reasons": reasons,
                "decision_path": "classifier_led_known_family_block",
                "support_count": len(reasons),
                "context_support_count": classifier_context_supports_block,
            }
        if (
            not threshold_suspicious
            and not threshold_triggered
            and high_classifier
            and high_anomaly
            and repeated_signal
        ):
            return {
                "eligible": True,
                "reason": "classifier_and_anomaly_consensus_without_threshold_trigger",
                "reasons": reasons,
                "decision_path": "rf_if_consensus_block",
                "support_count": len(reasons),
                "context_support_count": max(2, classifier_context_supports_block),
            }
        if (
            getattr(self.ml_config, "hybrid_anomaly_only_block_enabled", False)
            and not classifier_detected
            and very_high_anomaly
            and repeated_anomaly_only
            and anomaly_trend_rising
            and repeated_threshold_near_miss
        ):
            return {
                "eligible": True,
                "reason": "repeated_high_anomaly_pattern_supported_by_threshold_near_misses",
                "reasons": reasons,
                "decision_path": "anomaly_only_narrow_escalation",
                "support_count": len(reasons),
                "context_support_count": 4,
            }
        if (
            getattr(self.ml_config, "hybrid_anomaly_only_block_enabled", False)
            and not threshold_suspicious
            and not threshold_triggered
            and not classifier_detected
            and very_high_anomaly
            and strong_anomaly_only_persistence
        ):
            return {
                "eligible": True,
                "reason": "repeated_high_anomaly_pattern_without_threshold_signal",
                "reasons": reasons,
                "decision_path": "anomaly_only_strong_persistence_block",
                "support_count": len(reasons),
                "context_support_count": 4,
            }
        return empty

    def _is_block_eligible_family(self, predicted_family):
        if not self.ml_config.hybrid_known_family_block_enabled:
            return False
        family = str(predicted_family or "").strip().lower()
        if not family:
            return False
        allowlist = tuple(
            str(item or "").strip().lower()
            for item in getattr(self.ml_config, "hybrid_block_eligible_families", ())
        )
        if not allowlist:
            return True
        return family in allowlist

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

    def _record_decision_window(self, prediction, threshold_context=None):
        threshold_context = dict(threshold_context or {})
        if prediction is None or not prediction.src_ip:
            return {
                "signal_window_count": 0,
                "threshold_suspicious_repeat_count": 0,
                "threshold_near_miss_count": 0,
                "anomaly_only_repeat_count": 0,
                "anomalous_window_count": 0,
                "anomaly_trend_delta": 0.0,
                "anomaly_trend_rising": False,
            }

        now = float(getattr(prediction, "timestamp", 0.0) or 0.0)
        explanations = dict(getattr(prediction, "explanations", {}) or {})
        classifier_reason = str(explanations.get("classifier_reason", "") or "")
        classifier_detected = bool(explanations.get("classifier_detected")) or (
            classifier_reason not in ("", "ml_benign_prediction")
        )
        anomaly_only = bool(getattr(prediction, "is_anomalous", False)) and not classifier_detected

        window = self.decision_window_history[prediction.src_ip]
        retention_window = self._decision_memory_window_seconds()
        while window and (now - window[0].get("timestamp", 0.0)) > retention_window:
            window.popleft()
        window.append(
            {
                "timestamp": now,
                "threshold_triggered": bool(threshold_context.get("threshold_triggered")),
                "threshold_suspicious": bool(threshold_context.get("recon_suspicious")),
                "threshold_near_miss": bool(threshold_context.get("recon_suspicious"))
                and not bool(threshold_context.get("threshold_triggered")),
                "classifier_detected": classifier_detected,
                "anomaly_only": anomaly_only,
                "is_anomalous": bool(getattr(prediction, "is_anomalous", False)),
                "anomaly_score": float(getattr(prediction, "anomaly_score", 0.0) or 0.0),
            }
        )

        recent_entries = list(window)
        signal_window_count = len(recent_entries)
        threshold_suspicious_repeat_count = sum(
            1 for item in recent_entries if item.get("threshold_suspicious")
        )
        threshold_near_miss_count = sum(
            1 for item in recent_entries if item.get("threshold_near_miss")
        )
        anomaly_only_repeat_count = sum(
            1 for item in recent_entries if item.get("anomaly_only")
        )
        anomalous_scores = [
            float(item.get("anomaly_score", 0.0) or 0.0)
            for item in recent_entries
            if item.get("is_anomalous")
        ]
        anomaly_trend_delta = 0.0
        if getattr(prediction, "is_anomalous", False) and len(anomalous_scores) >= 2:
            prior_scores = anomalous_scores[:-1]
            anomaly_trend_delta = float(anomalous_scores[-1]) - (
                sum(prior_scores) / float(len(prior_scores))
            )
        anomaly_trend_rising = (
            len(anomalous_scores) >= 2
            and anomaly_trend_delta
            >= float(getattr(self.ml_config, "hybrid_anomaly_trend_threshold", 0.0))
        )
        return {
            "signal_window_count": signal_window_count,
            "threshold_suspicious_repeat_count": threshold_suspicious_repeat_count,
            "threshold_near_miss_count": threshold_near_miss_count,
            "anomaly_only_repeat_count": anomaly_only_repeat_count,
            "anomalous_window_count": len(anomalous_scores),
            "anomaly_trend_delta": anomaly_trend_delta,
            "anomaly_trend_rising": anomaly_trend_rising,
        }

    def _hybrid_threshold_near_miss_repeat_count(self):
        configured = getattr(
            self.ml_config,
            "hybrid_threshold_near_miss_repeat_count",
            self.ml_config.hybrid_block_repeat_count,
        )
        return max(1, int(configured or 0))

    def _hybrid_anomaly_only_required_windows(self):
        repeat_threshold = int(max(1, self.ml_config.hybrid_block_repeat_count))
        anomaly_only_escalation = int(
            max(1, getattr(self.ml_config, "anomaly_only_escalation_count", 1) or 1)
        )
        return max(
            4,
            repeat_threshold + 1,
            anomaly_only_escalation + 1,
        )

    def _decision_memory_window_seconds(self):
        return max(
            float(self.ml_config.hybrid_correlation_window_seconds) * 3.0,
            float(getattr(self.ml_config, "feature_window_seconds", 1) or 1.0)
            * float(max(2, int(self.ml_config.hybrid_block_repeat_count) + 1)),
            float(self.ml_config.alert_suppression_seconds)
            + float(self.ml_config.hybrid_correlation_window_seconds),
        )

    @staticmethod
    def _summarize_abnormal_features(prediction):
        explanations = dict(getattr(prediction, "explanations", {}) or {})
        feature_context = dict(explanations.get("feature_context") or {})
        abnormal_features = list(feature_context.get("abnormal_features") or [])
        if abnormal_features:
            return [
                str(item.get("summary", "")).strip()
                for item in abnormal_features
                if str(item.get("summary", "")).strip()
            ][:4]

        feature_values = dict(getattr(prediction, "feature_values", {}) or {})
        candidate_thresholds = (
            ("unanswered_syn_count", 1.0),
            ("unanswered_syn_ratio", 0.05),
            ("recon_probe_density", 0.2),
            ("unique_destination_ports", 3.0),
            ("unique_destination_ips", 2.0),
            ("destination_port_fanout_ratio", 0.3),
            ("packet_rate_delta", 0.1),
            ("destination_port_fanout_delta", 0.1),
            ("packet_rate_trend", 0.1),
            ("unique_destination_port_trend", 0.1),
            ("host_unique_dest_ip_baseline_ratio", 1.1),
            ("host_unique_dest_port_baseline_ratio", 1.1),
        )
        summaries = []
        for feature_name, minimum_value in candidate_thresholds:
            value = float(feature_values.get(feature_name, 0.0) or 0.0)
            if abs(value) < minimum_value:
                continue
            summaries.append("%s=%.3f" % (feature_name, value))
            if len(summaries) >= 4:
                break
        return summaries

    @staticmethod
    def _build_alert_explanation(
        prediction,
        threshold_context=None,
        correlation_status="ml_only",
        reason="",
        agreement=False,
        should_mitigate=False,
    ):
        threshold_context = dict(threshold_context or {})
        prediction_explanations = dict(getattr(prediction, "explanations", {}) or {})
        feature_context = dict(prediction_explanations.get("feature_context") or {})
        classifier = dict(prediction_explanations.get("classifier") or {})
        anomaly = dict(prediction_explanations.get("anomaly") or {})
        model_metadata = dict(prediction_explanations.get("model_metadata") or {})
        predicted_family = str(getattr(prediction, "predicted_family", "") or "")
        anomaly_score = float(getattr(prediction, "anomaly_score", 0.0) or 0.0)
        is_anomalous = bool(getattr(prediction, "is_anomalous", False))

        if correlation_status == "known_class_match":
            summary = (
                "Threshold and ML agreed on a known attack family '%s'."
                % (predicted_family or str(getattr(prediction, "label", "") or ""))
            )
        elif correlation_status == "threshold_plus_ml":
            summary = (
                "Threshold and ML both flagged the same host within the correlation window."
            )
        elif correlation_status == "threshold_enriched_by_ml":
            if should_mitigate:
                summary = (
                    "Threshold saw a suspicious but sub-threshold pattern, and ML evidence elevated it into a block."
                )
            else:
                summary = (
                    "Threshold saw a suspicious but sub-threshold pattern, and ML added confidence and context."
                )
        elif correlation_status == "anomaly_only":
            if should_mitigate:
                summary = (
                    "Only the anomaly detector repeatedly flagged this behavior, and hybrid escalated it because the anomaly score kept rising alongside threshold near-miss context."
                )
            else:
                summary = (
                    "Only the anomaly detector flagged this behavior, so the system kept it at alert/watchlist level."
                )
        elif correlation_status == "ml_only":
            family_text = (
                " for family '%s'" % predicted_family
                if predicted_family
                else ""
            )
            if should_mitigate:
                summary = (
                    "Only ML flagged this behavior%s, and the configured hybrid block rule was satisfied."
                    % family_text
                )
            else:
                summary = "Only ML flagged this behavior%s." % family_text
        elif correlation_status == "ml_anomaly_consensus":
            if should_mitigate:
                summary = (
                    "Classifier and anomaly evidence repeatedly agreed on this host without a threshold trigger, and the configured hybrid consensus rule escalated it into a block."
                )
            else:
                summary = (
                    "Classifier and anomaly evidence agreed on this host, so hybrid raised an ML-backed alert even without a threshold trigger."
                )
        else:
            summary = str(prediction_explanations.get("summary", "") or "")

        if reason and correlation_status in ("threshold_plus_ml", "threshold_enriched_by_ml"):
            summary = "%s Reason: %s." % (summary.rstrip("."), reason)
        elif not summary:
            summary = str(prediction_explanations.get("summary", "") or reason or "")

        return {
            "version": str(prediction_explanations.get("version", "") or "1"),
            "summary": summary.strip(),
            "agreement_with_threshold": bool(agreement),
            "correlation_status": correlation_status,
            "classifier": classifier,
            "anomaly": {
                **anomaly,
                "score": anomaly_score if anomaly else anomaly_score,
                "detected": bool(anomaly.get("detected", is_anomalous)),
            },
            "threshold": {
                "triggered": bool(threshold_context.get("threshold_triggered", False)),
                "reason": str(threshold_context.get("threshold_reason", "") or ""),
                "rule_family": str(
                    threshold_context.get("threshold_rule_family", "") or ""
                ),
                "severity": str(threshold_context.get("threshold_severity", "") or ""),
                "recent_event_count": int(
                    threshold_context.get("threshold_recent_event_count", 0) or 0
                ),
                "auto_quarantine_eligible": bool(
                    threshold_context.get("threshold_auto_quarantine_eligible", True)
                ),
                "unanswered_syn_count": int(
                    threshold_context.get("unanswered_syn_count", 0) or 0
                ),
                "unique_destination_hosts": int(
                    threshold_context.get("scan_unique_destination_hosts", 0) or 0
                ),
                "unique_destination_ports": int(
                    threshold_context.get("scan_unique_destination_ports", 0) or 0
                ),
                "recon_visible_traffic": bool(
                    threshold_context.get("recon_visible_traffic", False)
                ),
                "forwarding_visibility": str(
                    threshold_context.get("forwarding_visibility", "") or ""
                ),
            },
            "feature_context": {
                "abnormal_features": list(feature_context.get("abnormal_features") or []),
                "baseline_comparisons": list(
                    feature_context.get("baseline_comparisons") or []
                ),
                "top_model_features": list(feature_context.get("top_model_features") or []),
                "observation_window_seconds": float(
                    feature_context.get("observation_window_seconds", 0.0) or 0.0
                ),
            },
            "model_metadata": model_metadata,
        }

    @staticmethod
    def _validated_mode(mode):
        normalized = normalize_ids_mode_internal(mode, default="threshold_only")
        if normalized not in VALID_ML_MODES:
            return "threshold_only"
        return normalized

    @staticmethod
    def _validated_hybrid_policy(policy):
        normalized = (policy or "layered_consensus").strip().lower()
        if normalized not in VALID_HYBRID_POLICIES:
            return "layered_consensus"
        return normalized

    @staticmethod
    def _severity_rank(severity):
        ranks = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        return ranks.get(str(severity or "").strip().lower(), 0)


def decide(pipeline, packet_metadata, threshold_alerts=None, threshold_context=None):
    """Convenience wrapper for one-shot ML pipeline inspection."""

    return pipeline.inspect(
        packet_metadata,
        threshold_alerts=threshold_alerts,
        threshold_context=threshold_context,
    )
