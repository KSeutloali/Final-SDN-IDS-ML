"""Tests for runtime inference composition across classifier and anomaly models."""

from types import SimpleNamespace
import unittest

from ml.anomaly import RuntimeIsolationForestModel, RuntimeIsolationTree
from ml.feature_extractor import FeatureSnapshot
from ml.inference import ModelInferenceEngine
from ml.model_loader import ModelBundle
from monitoring.metrics import MetricsStore


class FakeClassifierModel(object):
    classes_ = ["benign", "malicious", "tcp_scan"]

    def __init__(self, label="malicious", malicious_probability=0.95):
        self.label = label
        self.malicious_probability = malicious_probability

    def predict(self, rows):
        return [self.label for _ in rows]

    def predict_proba(self, rows):
        if self.label == "tcp_scan":
            benign_probability = 1.0 - self.malicious_probability
            return [[benign_probability, 0.0, self.malicious_probability] for _ in rows]
        benign_probability = 1.0 - self.malicious_probability
        if self.label == "malicious":
            return [[benign_probability, self.malicious_probability, 0.0] for _ in rows]
        return [[self.malicious_probability, benign_probability, 0.0] for _ in rows]


def _portable_runtime_model():
    return RuntimeIsolationForestModel(
        trees=[
            RuntimeIsolationTree(
                children_left=[1, -1, -1],
                children_right=[2, -1, -1],
                feature=[0, -2, -2],
                threshold=[0.5, -2.0, -2.0],
                n_node_samples=[9, 8, 1],
            )
        ],
        max_samples=8,
        anomaly_threshold=0.6,
        contamination=0.2,
    )


class RuntimeInferenceTests(unittest.TestCase):
    @staticmethod
    def _ml_config(**overrides):
        defaults = {
            "confidence_threshold": 0.75,
            "positive_labels": ("malicious", "tcp_scan"),
        }
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    @staticmethod
    def _snapshot(packet_count=0.1):
        return FeatureSnapshot(
            src_ip="10.0.0.3",
            timestamp=1.0,
            feature_values={"packet_count": packet_count},
            sample_count=1,
        )

    @staticmethod
    def _classifier_bundle(label="malicious", malicious_probability=0.95, label_mode="binary"):
        return ModelBundle(
            model=FakeClassifierModel(
                label=label,
                malicious_probability=malicious_probability,
            ),
            feature_names=("packet_count",),
            positive_labels=("malicious", "tcp_scan"),
            metadata={
                "model_name": "random_forest",
                "model_version": "1",
                "label_mode": label_mode,
                "explainability": {
                    "feature_importance_available": True,
                    "feature_importance_source": "random_forest_global_importance",
                    "top_global_features": [
                        {"feature": "packet_count", "importance": 0.82},
                    ],
                },
            },
        )

    @staticmethod
    def _anomaly_bundle():
        return ModelBundle(
            model=_portable_runtime_model(),
            feature_names=("packet_count",),
            positive_labels=("anomalous",),
            metadata={
                "model_name": "isolation_forest",
                "model_version": "1",
                "anomaly_threshold": 0.6,
                "contamination": 0.2,
                "max_samples": 8,
            },
        )

    def test_classifier_only_mode_preserves_legacy_prediction_fields(self):
        engine = ModelInferenceEngine(
            self._classifier_bundle(),
            self._ml_config(),
            mode="classifier_only",
        )

        prediction = engine.predict(self._snapshot(packet_count=0.2))

        self.assertTrue(prediction.is_malicious)
        self.assertEqual(prediction.label, "malicious")
        self.assertEqual(prediction.predicted_family, "")
        self.assertEqual(prediction.anomaly_score, 0.0)
        self.assertFalse(prediction.is_anomalous)
        self.assertEqual(prediction.explanations["effective_mode"], "classifier_only")
        self.assertEqual(prediction.explanations["version"], "2")
        self.assertIn("classifier", prediction.explanations)
        self.assertIn("feature_context", prediction.explanations)
        self.assertEqual(
            prediction.explanations["feature_context"]["top_model_features"][0]["feature"],
            "packet_count",
        )
        payload = prediction.to_dict()
        for field_name in (
            "src_ip",
            "label",
            "is_malicious",
            "confidence",
            "suspicion_score",
            "reason",
            "model_name",
            "model_version",
        ):
            self.assertIn(field_name, payload)

    def test_classifier_prediction_populates_predicted_family_for_multiclass_models(self):
        engine = ModelInferenceEngine(
            self._classifier_bundle(
                label="tcp_scan",
                malicious_probability=0.88,
                label_mode="family",
            ),
            self._ml_config(),
            mode="classifier_only",
        )

        prediction = engine.predict(self._snapshot(packet_count=0.4))

        self.assertEqual(prediction.label, "tcp_scan")
        self.assertEqual(prediction.predicted_family, "tcp_scan")
        self.assertTrue(prediction.is_malicious)

    def test_anomaly_only_mode_uses_anomaly_detector(self):
        engine = ModelInferenceEngine(
            None,
            self._ml_config(),
            anomaly_bundle=self._anomaly_bundle(),
            mode="anomaly_only",
        )

        prediction = engine.predict(self._snapshot(packet_count=0.9))

        self.assertEqual(engine.effective_mode, "anomaly_only")
        self.assertTrue(prediction.is_malicious)
        self.assertTrue(prediction.is_anomalous)
        self.assertEqual(prediction.label, "anomalous")
        self.assertGreater(prediction.anomaly_score, 0.6)
        self.assertEqual(prediction.explanations["anomaly_reason"], "anomaly_score_above_threshold")
        self.assertIn("anomaly", prediction.explanations)
        self.assertEqual(
            prediction.explanations["feature_context"]["baseline_comparisons"],
            [],
        )

    def test_combined_mode_uses_anomaly_signal_when_classifier_is_benign(self):
        engine = ModelInferenceEngine(
            self._classifier_bundle(label="benign", malicious_probability=0.8),
            self._ml_config(),
            anomaly_bundle=self._anomaly_bundle(),
            mode="combined",
        )

        prediction = engine.predict(self._snapshot(packet_count=0.9))

        self.assertEqual(engine.effective_mode, "combined")
        self.assertTrue(prediction.is_anomalous)
        self.assertTrue(prediction.is_malicious)
        self.assertEqual(prediction.reason, "anomaly_score_above_threshold")
        self.assertGreaterEqual(
            prediction.suspicion_score,
            prediction.anomaly_score,
        )
        self.assertEqual(prediction.explanations["classifier_reason"], "ml_benign_prediction")

    def test_combined_mode_falls_back_to_anomaly_only_when_classifier_model_is_missing(self):
        engine = ModelInferenceEngine(
            ModelBundle(
                feature_names=("packet_count",),
                positive_labels=("malicious",),
                metadata={"model_name": "random_forest"},
                load_error="ml_model_file_not_found",
            ),
            self._ml_config(),
            anomaly_bundle=self._anomaly_bundle(),
            mode="combined",
        )

        prediction = engine.predict(self._snapshot(packet_count=0.9))

        self.assertEqual(engine.selected_mode, "combined")
        self.assertEqual(engine.effective_mode, "anomaly_only")
        self.assertTrue(prediction.is_anomalous)
        self.assertTrue(prediction.is_malicious)

    def test_prediction_remains_compatible_with_existing_metrics_consumer(self):
        engine = ModelInferenceEngine(
            self._classifier_bundle(),
            self._ml_config(),
            mode="classifier_only",
        )
        prediction = engine.predict(self._snapshot(packet_count=0.2))

        metrics = MetricsStore()
        metrics.record_ml_prediction(prediction)

        self.assertEqual(metrics.ml_predictions_total, 1)
        self.assertEqual(metrics.ml_malicious_predictions_total, 1)
        self.assertEqual(metrics.recent_ml_predictions[0]["model_name"], "random_forest")
        self.assertEqual(metrics.recent_ml_predictions[0]["explanation_version"], "2")

    def test_explanations_fall_back_cleanly_when_metadata_is_missing(self):
        engine = ModelInferenceEngine(
            ModelBundle(
                model=FakeClassifierModel(),
                feature_names=("packet_count",),
                positive_labels=("malicious",),
                metadata={"model_name": "random_forest"},
            ),
            self._ml_config(),
            mode="classifier_only",
        )

        prediction = engine.predict(self._snapshot(packet_count=0.2))

        self.assertEqual(
            prediction.explanations["model_metadata"]["top_global_features"],
            [],
        )
        self.assertEqual(
            prediction.explanations["feature_context"]["baseline_comparisons"],
            [],
        )


if __name__ == "__main__":
    unittest.main()
