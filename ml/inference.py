"""Runtime inference helpers for the optional ML IDS path."""

from dataclasses import dataclass, field


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
        }
        payload.update(self.feature_values)
        return payload


class ModelInferenceEngine(object):
    """Perform lightweight inference against a pre-trained classifier."""

    def __init__(self, model_bundle, ml_config):
        self.model_bundle = model_bundle
        self.ml_config = ml_config
        self.positive_labels = set(
            value.strip().lower()
            for value in (model_bundle.positive_labels or ml_config.positive_labels)
            if value
        )

    @property
    def is_available(self):
        return self.model_bundle.is_available

    def predict(self, feature_snapshot):
        if not self.is_available or feature_snapshot is None:
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


def predict(inference_engine, feature_snapshot):
    """Convenience wrapper for one-off runtime predictions."""

    return inference_engine.predict(feature_snapshot)
