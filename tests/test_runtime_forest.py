"""Unit tests for the portable Random Forest runtime."""

import unittest

from ml.runtime_forest import RuntimeDecisionTree, RuntimeRandomForestModel


class RuntimeForestTests(unittest.TestCase):
    def test_runtime_forest_predicts_malicious_probability(self):
        # A single-split tree:
        # if packet_count <= 5 -> benign
        # else -> malicious
        tree = RuntimeDecisionTree(
            children_left=[1, -1, -1],
            children_right=[2, -1, -1],
            feature=[0, -2, -2],
            threshold=[5.0, -2.0, -2.0],
            values=[
                [0.0, 0.0],
                [8.0, 0.0],
                [0.0, 12.0],
            ],
        )
        model = RuntimeRandomForestModel(
            classes_=["benign", "malicious"],
            trees=[tree],
        )

        probabilities = model.predict_proba([[10.0]])[0]
        prediction = model.predict([[10.0]])[0]

        self.assertEqual(prediction, "malicious")
        self.assertAlmostEqual(probabilities[1], 1.0)


if __name__ == "__main__":
    unittest.main()
