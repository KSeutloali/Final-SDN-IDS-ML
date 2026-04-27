"""Runtime inference helpers for the optional ML IDS path."""

from dataclasses import dataclass, field

from ml.anomaly import AnomalyInferenceEngine
from ml.model_loader import ModelBundle


VALID_INFERENCE_MODES = (
    "classifier_only",
    "anomaly_only",
    "combined",
)

EXPLANATION_VERSION = "2"
TOP_MODEL_FEATURE_LIMIT = 5
BASELINE_COMPARISON_LIMIT = 4
ABNORMAL_FEATURE_LIMIT = 4


@dataclass
class MLPrediction(object):
    """Normalized model output for controller-side decisions and logging."""

    src_ip: str
    timestamp: float
    label: str
    is_malicious: bool
    confidence: float
    suspicion_score: float
    reason: str
    model_name: str
    model_version: str = ""
    predicted_family: str = ""
    anomaly_score: float = 0.0
    is_anomalous: bool = False
    explanations: dict = field(default_factory=dict)
    feature_values: dict = field(default_factory=dict)

    def to_dict(self):
        payload = {
            "src_ip": self.src_ip,
            "timestamp": self.timestamp,
            "label": self.label,
            "is_malicious": self.is_malicious,
            "confidence": round(float(self.confidence), 6),
            "suspicion_score": round(float(self.suspicion_score), 6),
            "reason": self.reason,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "predicted_family": self.predicted_family,
            "anomaly_score": round(float(self.anomaly_score), 6),
            "is_anomalous": bool(self.is_anomalous),
            "explanations": dict(self.explanations or {}),
        }
        payload.update(self.feature_values)
        return payload


class ModelInferenceEngine(object):
    """Perform runtime inference against classifier and/or anomaly models."""

    def __init__(self, model_bundle, ml_config, anomaly_bundle=None, mode=None):
        self.model_bundle = model_bundle or ModelBundle(
            load_error="classifier_model_not_configured"
        )
        self.ml_config = ml_config
        self.anomaly_bundle = anomaly_bundle or ModelBundle(
            load_error="anomaly_model_not_configured"
        )
        self.anomaly_engine = AnomalyInferenceEngine(self.anomaly_bundle)
        self.positive_labels = set(
            value.strip().lower()
            for value in (self.model_bundle.positive_labels or ml_config.positive_labels)
            if value
        )
        self.mode = self._validated_mode(mode or self._default_mode())

    @property
    def is_available(self):
        return self.effective_mode != "unavailable"

    @property
    def selected_mode(self):
        return self.mode

    @property
    def effective_mode(self):
        classifier_available = self.model_bundle.is_available
        anomaly_available = self.anomaly_bundle.is_available

        if self.mode == "classifier_only":
            return "classifier_only" if classifier_available else "unavailable"
        if self.mode == "anomaly_only":
            return "anomaly_only" if anomaly_available else "unavailable"
        if classifier_available and anomaly_available:
            return "combined"
        if classifier_available:
            return "classifier_only"
        if anomaly_available:
            return "anomaly_only"
        return "unavailable"

    def predict(self, feature_snapshot):
        if feature_snapshot is None or not self.is_available:
            return None

        effective_mode = self.effective_mode
        if effective_mode == "classifier_only":
            return self._predict_classifier(feature_snapshot)
        if effective_mode == "anomaly_only":
            return self._predict_anomaly_only(feature_snapshot)
        if effective_mode == "combined":
            return self._predict_combined(feature_snapshot)
        return None

    def _predict_classifier(self, feature_snapshot):
        if not self.model_bundle.is_available:
            return None

        feature_vector = feature_snapshot.to_vector(self.model_bundle.feature_names)
        model = self.model_bundle.model
        label = str(model.predict([feature_vector])[0])
        label_normalized = label.strip().lower()

        malicious_score = self._malicious_score(model, feature_vector, label, label_normalized)
        has_probability = malicious_score is not None
        if malicious_score is None:
            malicious_score = 1.0 if label_normalized in self.positive_labels else 0.0

        is_malicious = (
            malicious_score >= self.ml_config.confidence_threshold
            if has_probability
            else label_normalized in self.positive_labels
        )

        reason = (
            "ml_confidence_threshold_exceeded"
            if is_malicious and has_probability
            else "ml_positive_label_predicted"
            if is_malicious
            else "ml_benign_prediction"
        )
        confidence = malicious_score if is_malicious else (1.0 - malicious_score)

        metadata = self.model_bundle.metadata
        explanations = self._build_explanations(
            feature_snapshot,
            metadata=metadata,
            label=label,
            predicted_family=self._predicted_family(metadata, label, label_normalized),
            classifier_detected=bool(is_malicious),
            classifier_confidence=float(confidence),
            classifier_suspicion_score=float(malicious_score),
            classifier_reason=reason,
        )
        return MLPrediction(
            src_ip=feature_snapshot.src_ip,
            timestamp=feature_snapshot.timestamp,
            label=label,
            is_malicious=is_malicious,
            confidence=confidence,
            suspicion_score=malicious_score,
            reason=reason,
            model_name=str(metadata.get("model_name") or "random_forest"),
            model_version=str(metadata.get("model_version") or ""),
            predicted_family=explanations["classifier"]["predicted_family"],
            anomaly_score=0.0,
            is_anomalous=False,
            explanations=explanations,
            feature_values=feature_snapshot.feature_values,
        )

    def _predict_anomaly_only(self, feature_snapshot):
        anomaly_prediction = self.anomaly_engine.predict(feature_snapshot)
        if anomaly_prediction is None:
            return None

        anomaly_score = float(anomaly_prediction.anomaly_score)
        confidence = anomaly_score if anomaly_prediction.is_anomalous else (1.0 - anomaly_score)
        explanations = self._build_explanations(
            feature_snapshot,
            metadata=dict(self.anomaly_bundle.metadata or {}),
            label=anomaly_prediction.label,
            predicted_family="",
            classifier_detected=False,
            classifier_confidence=0.0,
            classifier_suspicion_score=0.0,
            classifier_reason="",
            anomaly_detected=bool(anomaly_prediction.is_anomalous),
            anomaly_score=anomaly_score,
            anomaly_threshold=float(anomaly_prediction.threshold),
            anomaly_reason=anomaly_prediction.reason,
            anomaly_model_name=anomaly_prediction.model_name,
            anomaly_model_version=anomaly_prediction.model_version,
        )
        return MLPrediction(
            src_ip=anomaly_prediction.src_ip,
            timestamp=anomaly_prediction.timestamp,
            label=anomaly_prediction.label,
            is_malicious=bool(anomaly_prediction.is_anomalous),
            confidence=confidence,
            suspicion_score=anomaly_score,
            reason=anomaly_prediction.reason,
            model_name=anomaly_prediction.model_name,
            model_version=anomaly_prediction.model_version,
            predicted_family="",
            anomaly_score=anomaly_score,
            is_anomalous=bool(anomaly_prediction.is_anomalous),
            explanations=explanations,
            feature_values=feature_snapshot.feature_values,
        )

    def _predict_combined(self, feature_snapshot):
        classifier_prediction = self._predict_classifier(feature_snapshot)
        anomaly_prediction = self.anomaly_engine.predict(feature_snapshot)

        if classifier_prediction is None:
            return self._predict_anomaly_only(feature_snapshot)
        if anomaly_prediction is None:
            return classifier_prediction

        anomaly_score = float(anomaly_prediction.anomaly_score)
        is_anomalous = bool(anomaly_prediction.is_anomalous)
        is_malicious = bool(classifier_prediction.is_malicious or is_anomalous)
        suspicion_score = max(float(classifier_prediction.suspicion_score), anomaly_score)

        if classifier_prediction.is_malicious:
            confidence = float(classifier_prediction.confidence)
        elif is_anomalous:
            confidence = anomaly_score
        else:
            confidence = max(float(classifier_prediction.confidence), 1.0 - anomaly_score)

        if classifier_prediction.is_malicious and is_anomalous:
            reason = "classifier_and_anomaly_agree"
        elif classifier_prediction.is_malicious:
            reason = classifier_prediction.reason
        elif is_anomalous:
            reason = anomaly_prediction.reason
        else:
            reason = classifier_prediction.reason

        combined_metadata = dict(self.model_bundle.metadata or {})
        if not combined_metadata.get("explainability"):
            combined_metadata["explainability"] = dict(
                self.anomaly_bundle.metadata.get("explainability", {})
            )
        explanations = self._build_explanations(
            feature_snapshot,
            metadata=combined_metadata,
            label=classifier_prediction.label,
            predicted_family=classifier_prediction.predicted_family,
            classifier_detected=bool(classifier_prediction.is_malicious),
            classifier_confidence=float(classifier_prediction.confidence),
            classifier_suspicion_score=float(classifier_prediction.suspicion_score),
            classifier_reason=classifier_prediction.reason,
            anomaly_detected=bool(is_anomalous),
            anomaly_score=anomaly_score,
            anomaly_threshold=float(anomaly_prediction.threshold),
            anomaly_reason=anomaly_prediction.reason,
            anomaly_model_name=anomaly_prediction.model_name,
            anomaly_model_version=anomaly_prediction.model_version,
        )
        return MLPrediction(
            src_ip=classifier_prediction.src_ip,
            timestamp=classifier_prediction.timestamp,
            label=classifier_prediction.label,
            is_malicious=is_malicious,
            confidence=confidence,
            suspicion_score=suspicion_score,
            reason=reason,
            model_name=classifier_prediction.model_name,
            model_version=classifier_prediction.model_version,
            predicted_family=classifier_prediction.predicted_family,
            anomaly_score=anomaly_score,
            is_anomalous=is_anomalous,
            explanations=explanations,
            feature_values=feature_snapshot.feature_values,
        )

    def _malicious_score(self, model, feature_vector, label, label_normalized):
        if not hasattr(model, "predict_proba"):
            return None

        probabilities = model.predict_proba([feature_vector])[0]
        classes = getattr(model, "classes_", None)
        if classes is None:
            return None

        positive_probabilities = []
        for index, class_value in enumerate(classes):
            class_name = str(class_value).strip().lower()
            if class_name in self.positive_labels:
                positive_probabilities.append(float(probabilities[index]))

        if positive_probabilities:
            return max(positive_probabilities)

        if label_normalized in self.positive_labels:
            return max(float(probability) for probability in probabilities)
        return 0.0

    def _default_mode(self):
        classifier_available = self.model_bundle.is_available
        anomaly_available = self.anomaly_bundle.is_available
        if classifier_available and anomaly_available:
            return "combined"
        if anomaly_available and not classifier_available:
            return "anomaly_only"
        return "classifier_only"

    @staticmethod
    def _validated_mode(mode):
        normalized = str(mode or "classifier_only").strip().lower()
        if normalized not in VALID_INFERENCE_MODES:
            return "classifier_only"
        return normalized

    def _predicted_family(self, metadata, label, label_normalized):
        benign_labels = {"benign", "normal", "0", "false"}
        if label_normalized in benign_labels:
            return ""

        label_mode = str(metadata.get("label_mode") or "binary").strip().lower()
        if label_mode in ("family", "scenario"):
            return label
        if label_normalized in self.positive_labels:
            return ""
        return label

    def _build_explanations(
        self,
        feature_snapshot,
        metadata,
        label,
        predicted_family,
        classifier_detected,
        classifier_confidence,
        classifier_suspicion_score,
        classifier_reason,
        anomaly_detected=False,
        anomaly_score=0.0,
        anomaly_threshold=0.0,
        anomaly_reason="",
        anomaly_model_name="",
        anomaly_model_version="",
    ):
        metadata = dict(metadata or {})
        feature_values = dict(getattr(feature_snapshot, "feature_values", {}) or {})
        feature_context = self._feature_context(feature_values, metadata)
        model_metadata = self._explainability_metadata(metadata)
        summary = self._explanation_summary(
            label=label,
            predicted_family=predicted_family,
            classifier_detected=classifier_detected,
            classifier_confidence=classifier_confidence,
            anomaly_detected=anomaly_detected,
            anomaly_score=anomaly_score,
            anomaly_threshold=anomaly_threshold,
            top_abnormal_features=feature_context.get("abnormal_features", ()),
        )
        payload = {
            "version": EXPLANATION_VERSION,
            "summary": summary,
            "selected_mode": self.mode,
            "effective_mode": self.effective_mode,
            "classifier_detected": bool(classifier_detected),
            "classifier_confidence": float(classifier_confidence),
            "classifier_suspicion_score": float(classifier_suspicion_score),
            "classifier_reason": classifier_reason,
            "anomaly_detected": bool(anomaly_detected),
            "anomaly_threshold": float(anomaly_threshold),
            "anomaly_reason": anomaly_reason,
            "classifier": {
                "detected": bool(classifier_detected),
                "label": str(label or ""),
                "predicted_family": str(predicted_family or ""),
                "confidence": float(classifier_confidence),
                "suspicion_score": float(classifier_suspicion_score),
                "reason": str(classifier_reason or ""),
            },
            "anomaly": {
                "detected": bool(anomaly_detected),
                "score": float(anomaly_score),
                "threshold": float(anomaly_threshold),
                "reason": str(anomaly_reason or ""),
                "model_name": str(anomaly_model_name or ""),
                "model_version": str(anomaly_model_version or ""),
            },
            "feature_context": feature_context,
            "model_metadata": model_metadata,
        }
        if anomaly_model_name:
            payload["anomaly_model_name"] = str(anomaly_model_name)
        if anomaly_model_version:
            payload["anomaly_model_version"] = str(anomaly_model_version)
        return payload

    def _feature_context(self, feature_values, metadata):
        top_model_features = self._top_model_features(feature_values, metadata)
        baseline_comparisons = self._baseline_comparisons(feature_values)
        abnormal_features = self._abnormal_feature_details(
            feature_values,
            top_model_features,
            baseline_comparisons,
        )
        return {
            "observation_window_seconds": float(
                feature_values.get("observation_window_seconds", 0.0) or 0.0
            ),
            "top_model_features": top_model_features,
            "baseline_comparisons": baseline_comparisons,
            "abnormal_features": abnormal_features,
        }

    def _top_model_features(self, feature_values, metadata):
        explainability = self._explainability_metadata(metadata)
        top_global_features = explainability.get("top_global_features", []) or []
        entries = []
        for item in top_global_features[:TOP_MODEL_FEATURE_LIMIT]:
            feature_name = str(item.get("feature", "")).strip()
            if not feature_name:
                continue
            entries.append(
                {
                    "feature": feature_name,
                    "importance": float(item.get("importance", 0.0) or 0.0),
                    "current_value": float(feature_values.get(feature_name, 0.0) or 0.0),
                }
            )
        return entries

    @staticmethod
    def _baseline_comparisons(feature_values):
        comparison_specs = (
            (
                "host_packet_rate_baseline_ratio",
                "packet_rate",
                "baseline_ratio",
                "packet_rate_vs_baseline",
                0.05,
            ),
            (
                "host_unique_dest_ip_baseline_ratio",
                "unique_destination_ips",
                "baseline_ratio",
                "destination_ip_diversity_vs_baseline",
                0.05,
            ),
            (
                "host_unique_dest_port_baseline_ratio",
                "unique_destination_ports",
                "baseline_ratio",
                "destination_port_diversity_vs_baseline",
                0.05,
            ),
            (
                "host_unanswered_syn_ratio_baseline_ratio",
                "unanswered_syn_ratio",
                "baseline_ratio",
                "unanswered_syn_ratio_vs_baseline",
                0.05,
            ),
            (
                "packet_rate_delta",
                "packet_rate",
                "delta",
                "packet_rate_delta",
                0.1,
            ),
            (
                "destination_port_fanout_delta",
                "destination_port_fanout_ratio",
                "delta",
                "port_fanout_delta",
                0.05,
            ),
            (
                "unique_destination_ips_delta",
                "unique_destination_ips",
                "delta",
                "destination_ip_delta",
                0.5,
            ),
            (
                "unique_destination_ports_delta",
                "unique_destination_ports",
                "delta",
                "destination_port_delta",
                0.5,
            ),
            (
                "packet_rate_trend",
                "packet_rate",
                "trend",
                "packet_rate_trend",
                0.05,
            ),
            (
                "unique_destination_port_trend",
                "unique_destination_ports",
                "trend",
                "destination_port_trend",
                0.05,
            ),
            (
                "unanswered_syn_ratio_trend",
                "unanswered_syn_ratio",
                "trend",
                "unanswered_syn_ratio_trend",
                0.05,
            ),
        )
        comparisons = []
        for comparison_feature, current_feature, comparison_type, label, minimum_value in comparison_specs:
            value = float(feature_values.get(comparison_feature, 0.0) or 0.0)
            if comparison_type == "baseline_ratio":
                if value <= 0.0:
                    continue
                deviation = abs(value - 1.0)
            else:
                deviation = abs(value)
            if deviation < float(minimum_value):
                continue
            comparisons.append(
                {
                    "feature": current_feature,
                    "comparison_feature": comparison_feature,
                    "comparison_type": comparison_type,
                    "current_value": float(feature_values.get(current_feature, 0.0) or 0.0),
                    "comparison_value": value,
                    "score": deviation,
                    "label": label,
                    "summary": ModelInferenceEngine._comparison_summary(
                        current_feature,
                        comparison_feature,
                        comparison_type,
                        value,
                    ),
                }
            )
        comparisons.sort(
            key=lambda item: (-float(item["score"]), str(item["comparison_feature"]))
        )
        return comparisons[:BASELINE_COMPARISON_LIMIT]

    @staticmethod
    def _abnormal_feature_details(feature_values, top_model_features, baseline_comparisons):
        seen = set()
        details = []
        for comparison in baseline_comparisons:
            feature_name = str(comparison.get("comparison_feature", "")).strip()
            if not feature_name or feature_name in seen:
                continue
            details.append(
                {
                    "feature": feature_name,
                    "value": float(feature_values.get(feature_name, 0.0) or 0.0),
                    "summary": str(comparison.get("summary", "")),
                    "source": "baseline_comparison",
                }
            )
            seen.add(feature_name)
            if len(details) >= ABNORMAL_FEATURE_LIMIT:
                return details

        for entry in top_model_features:
            feature_name = str(entry.get("feature", "")).strip()
            current_value = float(entry.get("current_value", 0.0) or 0.0)
            if not feature_name or feature_name in seen or abs(current_value) <= 0.0:
                continue
            details.append(
                {
                    "feature": feature_name,
                    "value": current_value,
                    "summary": "%s=%.3f (important model feature)" % (
                        feature_name,
                        current_value,
                    ),
                    "source": "global_feature_importance",
                }
            )
            seen.add(feature_name)
            if len(details) >= ABNORMAL_FEATURE_LIMIT:
                break
        return details

    @staticmethod
    def _comparison_summary(current_feature, comparison_feature, comparison_type, value):
        if comparison_type == "baseline_ratio":
            return "%s=%.2fx host baseline" % (current_feature, float(value))
        if comparison_type == "trend":
            return "%s trend=%.3f" % (current_feature, float(value))
        return "%s delta=%.3f" % (current_feature, float(value))

    @staticmethod
    def _explainability_metadata(metadata):
        metadata = dict(metadata or {})
        explainability = dict(metadata.get("explainability") or {})
        top_global_features = explainability.get("top_global_features")
        if top_global_features is None:
            feature_importance_summary = dict(metadata.get("feature_importance_summary") or {})
            top_global_features = feature_importance_summary.get("top_global_features", [])
        return {
            "feature_importance_available": bool(
                explainability.get(
                    "feature_importance_available",
                    dict(metadata.get("feature_importance_summary") or {}).get(
                        "feature_importance_available",
                        False,
                    ),
                )
            ),
            "feature_importance_source": str(
                explainability.get(
                    "feature_importance_source",
                    dict(metadata.get("feature_importance_summary") or {}).get(
                        "feature_importance_source",
                        "",
                    ),
                )
                or ""
            ),
            "top_global_features": list(top_global_features or []),
        }

    @staticmethod
    def _explanation_summary(
        label,
        predicted_family,
        classifier_detected,
        classifier_confidence,
        anomaly_detected,
        anomaly_score,
        anomaly_threshold,
        top_abnormal_features,
    ):
        evidence = []
        if top_abnormal_features:
            evidence = [
                str(item.get("feature", "")).strip()
                for item in top_abnormal_features[:2]
                if str(item.get("feature", "")).strip()
            ]
        evidence_text = ""
        if evidence:
            evidence_text = " Key signals: %s." % ", ".join(evidence)

        if classifier_detected and anomaly_detected:
            family_text = (
                " for family '%s'" % predicted_family
                if predicted_family
                else ""
            )
            return (
                "Classifier and anomaly detector both flagged the host%s. "
                "Classifier confidence %.3f and anomaly score %.3f exceeded the anomaly threshold %.3f.%s"
                % (
                    family_text,
                    float(classifier_confidence),
                    float(anomaly_score),
                    float(anomaly_threshold),
                    evidence_text,
                )
            ).strip()
        if classifier_detected:
            family_text = (
                " for family '%s'" % predicted_family
                if predicted_family
                else ""
            )
            return (
                "Classifier flagged the host%s with confidence %.3f.%s"
                % (
                    family_text,
                    float(classifier_confidence),
                    evidence_text,
                )
            ).strip()
        if anomaly_detected:
            return (
                "Anomaly detector flagged the host with score %.3f above threshold %.3f.%s"
                % (
                    float(anomaly_score),
                    float(anomaly_threshold),
                    evidence_text,
                )
            ).strip()
        return (
            "No malicious label was predicted for '%s'.%s"
            % (str(label or "benign"), evidence_text)
        ).strip()


def predict(inference_engine, feature_snapshot):
    """Convenience wrapper for one-off runtime predictions."""

    return inference_engine.predict(feature_snapshot)
