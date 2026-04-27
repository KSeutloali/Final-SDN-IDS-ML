"""Tests for shared ML feature-engineering helpers."""

import unittest

from ml.feature_engineering import (
    baseline_ratio,
    burstiness,
    entropy,
    inter_arrival_stats,
    new_value_ratio,
    standard_deviation,
    trend_delta,
)


class FeatureEngineeringTests(unittest.TestCase):
    def test_inter_arrival_stats_are_deterministic(self):
        mean_value, std_value = inter_arrival_stats([1.0, 2.0, 4.0])

        self.assertAlmostEqual(mean_value, 1.5)
        self.assertAlmostEqual(std_value, 0.5)

    def test_entropy_and_standard_deviation_handle_simple_inputs(self):
        self.assertAlmostEqual(entropy(["a", "b"]), 1.0)
        self.assertAlmostEqual(standard_deviation([100.0, 140.0, 180.0]), 32.65986324, places=6)

    def test_ratio_and_trend_helpers_use_safe_defaults(self):
        self.assertEqual(new_value_ratio(["10.0.0.2"], []), 1.0)
        self.assertEqual(new_value_ratio([], ["10.0.0.2"]), 0.0)
        self.assertEqual(baseline_ratio(0.0, None), 0.0)
        self.assertEqual(baseline_ratio(5.0, None), 1.0)
        self.assertEqual(baseline_ratio(5.0, 0.0), 1.0)
        self.assertEqual(baseline_ratio(6.0, 3.0), 2.0)
        self.assertAlmostEqual(burstiness(1.5, 0.5), -0.5)
        self.assertEqual(trend_delta(4.0, 1.5), 2.5)


if __name__ == "__main__":
    unittest.main()
