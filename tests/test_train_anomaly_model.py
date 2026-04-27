"""Tests for offline anomaly-model training helpers."""

import unittest

try:
    import pandas as pd
except ImportError:  # pragma: no cover - optional test dependency
    pd = None

from scripts.train_anomaly_model import (
    evaluate_anomaly_model,
    summarize_benign_diversity,
    select_benign_training_rows,
)


class FakeAnomalyModel(object):
    def predict(self, rows):
        return [-1 if float(row[0]) >= 0.5 else 1 for row in rows]

    def anomaly_scores(self, rows):
        return [float(row[0]) for row in rows]


@unittest.skipIf(pd is None, "pandas is required for anomaly trainer helper tests")
class TrainAnomalyModelTests(unittest.TestCase):
    def test_select_benign_training_rows_rejects_small_benign_corpus(self):
        feature_frame = pd.DataFrame({"packet_count": [1.0, 2.0, 3.0]})
        label_series = pd.Series(["benign", "malicious", "malicious"], dtype="object")

        def fake_split(rows, test_size, random_state):
            self.fail("train_test_split should not be called when benign rows are insufficient")

        with self.assertRaisesRegex(ValueError, "Need at least 2 benign rows"):
            select_benign_training_rows(
                feature_frame,
                label_series,
                benign_label="benign",
                test_size=0.25,
                random_state=42,
                train_test_split_fn=fake_split,
                minimum_benign_rows=2,
            )

    def test_select_benign_training_rows_uses_only_benign_examples(self):
        feature_frame = pd.DataFrame({"packet_count": [0.1, 0.2, 0.3, 0.9]})
        label_series = pd.Series(
            ["benign", "benign", "benign", "malicious"],
            dtype="object",
        )

        def fake_split(rows, test_size, random_state):
            return rows.iloc[:2], rows.iloc[2:]

        train_rows, holdout_rows = select_benign_training_rows(
            feature_frame,
            label_series,
            benign_label="benign",
            test_size=0.34,
            random_state=42,
            train_test_split_fn=fake_split,
            minimum_benign_rows=2,
        )

        self.assertEqual(len(train_rows), 2)
        self.assertEqual(len(holdout_rows), 1)
        self.assertLess(train_rows["packet_count"].max(), 0.5)
        self.assertLess(holdout_rows["packet_count"].max(), 0.5)

    def test_select_benign_training_rows_can_subsample_large_training_split(self):
        feature_frame = pd.DataFrame({"packet_count": [0.1, 0.2, 0.3, 0.4, 0.5, 0.9]})
        label_series = pd.Series(
            ["benign", "benign", "benign", "benign", "benign", "malicious"],
            dtype="object",
        )

        def fake_split(rows, test_size, random_state):
            return rows.iloc[:4], rows.iloc[4:]

        train_rows, holdout_rows = select_benign_training_rows(
            feature_frame,
            label_series,
            benign_label="benign",
            test_size=0.2,
            random_state=7,
            train_test_split_fn=fake_split,
            minimum_benign_rows=2,
            max_benign_training_rows=2,
        )

        self.assertEqual(len(train_rows), 2)
        self.assertEqual(len(holdout_rows), 1)

    def test_evaluate_anomaly_model_reports_family_grouping(self):
        model = FakeAnomalyModel()
        feature_frame = pd.DataFrame({"packet_count": [0.1, 0.7, 0.9]})
        label_series = pd.Series(["benign", "malicious", "malicious"], dtype="object")
        family_series = pd.Series(["benign", "tcp_scan", "udp_scan"], dtype="object")

        metrics = evaluate_anomaly_model(
            model,
            feature_frame,
            label_series,
            family_series=family_series,
            benign_label="benign",
        )

        self.assertEqual(metrics["benign_false_positive_rate"], 0.0)
        self.assertEqual(metrics["anomaly_detection_rate"], 1.0)
        self.assertIn("per_family_detection", metrics)
        self.assertEqual(metrics["per_family_detection"]["tcp_scan"]["detection_rate"], 1.0)
        self.assertEqual(metrics["per_family_detection"]["udp_scan"]["detection_rate"], 1.0)
        self.assertIn("benign_score_summary", metrics)
        self.assertEqual(metrics["benign_score_summary"]["count"], 1)
        self.assertIn("malicious_score_summary", metrics)
        self.assertEqual(metrics["malicious_score_summary"]["count"], 2)

    def test_summarize_benign_diversity_counts_families_and_scenarios(self):
        dataframe = pd.DataFrame(
            {
                "Label": ["benign", "benign", "malicious", "benign"],
                "Scenario Family": [
                    "benign_http_repeated",
                    "benign_udp_request_response",
                    "tcp_port_scan",
                    "benign_http_repeated",
                ],
                "Scenario ID": [
                    "http_a",
                    "udp_a",
                    "scan_a",
                    "http_b",
                ],
            }
        )

        class Schema(object):
            label_column = "Label"
            scenario_family_column = "Scenario Family"
            scenario_id_column = "Scenario ID"
            scenario_column = None

        summary = summarize_benign_diversity(dataframe, Schema(), "benign")

        self.assertEqual(summary["benign_source_rows"], 3)
        self.assertEqual(summary["benign_family_count"], 2)
        self.assertEqual(summary["benign_family_distribution"]["benign_http_repeated"], 2)
        self.assertEqual(summary["benign_scenario_count"], 3)


if __name__ == "__main__":
    unittest.main()
