"""Portable anomaly detection helpers for runtime deployment."""

from dataclasses import dataclass, field
import math


EULER_GAMMA = 0.5772156649015329
LEAF_NODE = -1


def average_path_length(sample_count):
    sample_count = int(sample_count or 0)
    if sample_count <= 1:
        return 0.0
    if sample_count == 2:
        return 1.0
    return (2.0 * (math.log(sample_count - 1.0) + EULER_GAMMA)) - (
        2.0 * (sample_count - 1.0) / float(sample_count)
    )


@dataclass
class RuntimeIsolationTree(object):
    """Serialized decision tree arrays exported from sklearn IsolationForest."""

    children_left: list
    children_right: list
    feature: list
    threshold: list
    n_node_samples: list

    def path_length(self, feature_vector):
        """Traverse the tree and return the adjusted isolation path length."""

        node_index = 0
        depth = 0.0
        while True:
            left_index = self.children_left[node_index]
            right_index = self.children_right[node_index]
            if left_index == LEAF_NODE and right_index == LEAF_NODE:
                return depth + average_path_length(self.n_node_samples[node_index])

            feature_index = self.feature[node_index]
            threshold_value = float(self.threshold[node_index])
            feature_value = (
                float(feature_vector[feature_index])
                if 0 <= feature_index < len(feature_vector)
                else 0.0
            )
            if feature_value <= threshold_value:
                node_index = left_index
            else:
                node_index = right_index
            depth += 1.0


@dataclass
class RuntimeIsolationForestModel(object):
    """Pure-Python Isolation Forest model used at runtime."""

    trees: list = field(default_factory=list)
    max_samples: int = 0
    anomaly_threshold: float = 0.5
    contamination: object = "auto"

    def anomaly_scores(self, rows):
        return [self._anomaly_score_row(row) for row in rows]

    def score_samples(self, rows):
        return [-score for score in self.anomaly_scores(rows)]

    def decision_function(self, rows):
        return [self.anomaly_threshold - score for score in self.anomaly_scores(rows)]

    def predict(self, rows):
        predictions = []
        for score in self.anomaly_scores(rows):
            predictions.append(-1 if score >= float(self.anomaly_threshold) else 1)
        return predictions

    def _anomaly_score_row(self, feature_vector):
        if not self.trees:
            return 0.0
        normalizer = average_path_length(self.max_samples)
        if normalizer <= 0.0:
            return 0.0
        path_lengths = [tree.path_length(feature_vector) for tree in self.trees]
        average_depth = sum(path_lengths) / float(len(path_lengths))
        return math.pow(2.0, (-1.0 * average_depth) / normalizer)


@dataclass
class AnomalyPrediction(object):
    """Normalized anomaly prediction for runtime consumers."""

    src_ip: str
    timestamp: float
    label: str
    is_anomalous: bool
    anomaly_score: float
    threshold: float
    reason: str
    model_name: str
    model_version: str = ""
    feature_values: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)

    def to_dict(self):
        payload = {
            "src_ip": self.src_ip,
            "timestamp": self.timestamp,
            "label": self.label,
            "is_anomalous": self.is_anomalous,
            "anomaly_score": round(float(self.anomaly_score), 6),
            "threshold": round(float(self.threshold), 6),
            "reason": self.reason,
            "model_name": self.model_name,
            "model_version": self.model_version,
        }
        payload.update(self.feature_values)
        payload.update(self.details)
        return payload


class AnomalyInferenceEngine(object):
    """Perform runtime anomaly scoring with a portable or sklearn-like model."""

    def __init__(self, model_bundle):
        self.model_bundle = model_bundle

    @property
    def is_available(self):
        return self.model_bundle.is_available

    def predict(self, feature_snapshot):
        if not self.is_available or feature_snapshot is None:
            return None

        feature_names = tuple(self.model_bundle.feature_names or ())
        missing_features = [
            feature_name
            for feature_name in feature_names
            if feature_name not in feature_snapshot.feature_values
        ]
        if missing_features:
            raise ValueError(
                "anomaly_feature_schema_mismatch: missing features %s"
                % ", ".join(sorted(missing_features))
            )

        model = self.model_bundle.model
        feature_vector = feature_snapshot.to_vector(feature_names)
        metadata = dict(self.model_bundle.metadata or {})
        threshold = float(metadata.get("anomaly_threshold", 0.5))

        if hasattr(model, "anomaly_scores"):
            anomaly_score = float(model.anomaly_scores([feature_vector])[0])
            raw_prediction = model.predict([feature_vector])[0]
            is_anomalous = int(raw_prediction) == -1
        elif hasattr(model, "score_samples") and hasattr(model, "predict"):
            anomaly_score = float(-model.score_samples([feature_vector])[0])
            raw_prediction = model.predict([feature_vector])[0]
            is_anomalous = int(raw_prediction) == -1
        else:
            raise ValueError("unsupported_anomaly_model")

        label = "anomalous" if is_anomalous else "benign"
        reason = (
            "anomaly_score_above_threshold"
            if is_anomalous
            else "anomaly_model_inlier"
        )
        return AnomalyPrediction(
            src_ip=feature_snapshot.src_ip,
            timestamp=feature_snapshot.timestamp,
            label=label,
            is_anomalous=is_anomalous,
            anomaly_score=anomaly_score,
            threshold=threshold,
            reason=reason,
            model_name=str(metadata.get("model_name") or "isolation_forest"),
            model_version=str(metadata.get("model_version") or ""),
            feature_values=feature_snapshot.feature_values,
            details={
                "contamination": metadata.get("contamination"),
                "max_samples": metadata.get("max_samples"),
            },
        )


def export_isolation_forest_model(detector):
    """Convert a fitted sklearn IsolationForest into a portable runtime model."""

    estimators = list(getattr(detector, "estimators_", []) or [])
    trees = []
    for estimator in estimators:
        tree = estimator.tree_
        trees.append(
            RuntimeIsolationTree(
                children_left=tree.children_left.tolist(),
                children_right=tree.children_right.tolist(),
                feature=tree.feature.tolist(),
                threshold=[float(value) for value in tree.threshold.tolist()],
                n_node_samples=tree.n_node_samples.tolist(),
            )
        )

    contamination = getattr(detector, "contamination", "auto")
    threshold = float(-getattr(detector, "offset_", -0.5))
    return RuntimeIsolationForestModel(
        trees=trees,
        max_samples=int(getattr(detector, "max_samples_", 0) or 0),
        anomaly_threshold=threshold,
        contamination=contamination,
    )
