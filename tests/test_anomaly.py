"""Tests for portable anomaly-model runtime helpers."""

import os
import tempfile
import unittest

from ml.anomaly import (
    AnomalyInferenceEngine,
    RuntimeIsolationForestModel,
    RuntimeIsolationTree,
)
from ml.feature_extractor import FeatureSnapshot
from ml.model_loader import load_model, save_model_bundle


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


class AnomalyRuntimeTests(unittest.TestCase):
    def _snapshot(self, packet_count=0.1, **overrides):
        feature_values = {"packet_count": packet_count}
        feature_values.update(overrides)
        return FeatureSnapshot(
            src_ip="10.0.0.3",
            timestamp=1.0,
            feature_values=feature_values,
            sample_count=1,
        )

    def test_bundle_save_and_load_round_trip_preserves_runtime_model(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "anomaly.joblib")
            runtime_model = _portable_runtime_model()
            save_model_bundle(
                model_path,
                {
                    "model": runtime_model,
                    "feature_names": ("packet_count",),
                    "positive_labels": ("anomalous",),
                    "metadata": {
                        "model_name": "isolation_forest",
                        "model_version": "1",
                        "trained_at": "2026-04-17T00:00:00+00:00",
                        "contamination": 0.2,
                        "anomaly_threshold": 0.6,
                    },
                },
            )

            bundle = load_model(model_path)

        self.assertTrue(bundle.is_available)
        self.assertEqual(bundle.feature_names, ("packet_count",))
        self.assertEqual(bundle.metadata["model_name"], "isolation_forest")
        self.assertIsInstance(bundle.model, RuntimeIsolationForestModel)
        self.assertEqual(bundle.model.contamination, 0.2)

    def test_prediction_path_supports_inlier_and_anomalous_rows(self):
        bundle = load_model(
            "",
            fallback_feature_names=("packet_count",),
            fallback_positive_labels=("anomalous",),
        )
        bundle.model = _portable_runtime_model()
        bundle.metadata = {
            "model_name": "isolation_forest",
            "model_version": "1",
            "contamination": 0.2,
            "max_samples": 8,
            "anomaly_threshold": 0.6,
        }
        bundle.load_error = None

        engine = AnomalyInferenceEngine(bundle)
        benign_prediction = engine.predict(self._snapshot(packet_count=0.1))
        anomaly_prediction = engine.predict(self._snapshot(packet_count=0.9))

        self.assertFalse(benign_prediction.is_anomalous)
        self.assertEqual(benign_prediction.label, "benign")
        self.assertTrue(anomaly_prediction.is_anomalous)
        self.assertEqual(anomaly_prediction.label, "anomalous")
        self.assertGreater(anomaly_prediction.anomaly_score, anomaly_prediction.threshold)

    def test_feature_schema_mismatch_raises_clear_error(self):
        bundle = load_model(
            "",
            fallback_feature_names=("packet_count", "byte_count"),
            fallback_positive_labels=("anomalous",),
        )
        bundle.model = _portable_runtime_model()
        bundle.metadata = {"anomaly_threshold": 0.6}
        bundle.load_error = None

        engine = AnomalyInferenceEngine(bundle)

        with self.assertRaisesRegex(ValueError, "anomaly_feature_schema_mismatch"):
            engine.predict(self._snapshot(packet_count=0.2))


if __name__ == "__main__":
    unittest.main()
