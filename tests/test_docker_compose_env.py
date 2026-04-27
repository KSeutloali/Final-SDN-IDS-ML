"""Regression checks for controller env passthroughs in docker-compose."""

from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DockerComposeEnvTests(unittest.TestCase):
    def test_controller_passes_experiment_runtime_envs(self):
        compose_text = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")

        required_entries = (
            'SDN_IDS_ENABLED: "${SDN_IDS_ENABLED:-true}"',
            'SDN_IDS_MODE_STATE_PATH: "${SDN_IDS_MODE_STATE_PATH:-runtime/ids_mode_state.json}"',
            'SDN_MITIGATION_ENABLED: "${SDN_MITIGATION_ENABLED:-true}"',
            'SDN_ML_ANOMALY_MODEL_PATH: "${SDN_ML_ANOMALY_MODEL_PATH:-}"',
            'SDN_ML_INFERENCE_MODE: "${SDN_ML_INFERENCE_MODE:-classifier_only}"',
        )
        for entry in required_entries:
            self.assertIn(entry, compose_text)

    def test_repo_env_defaults_to_operational_hybrid_mode(self):
        env_text = (PROJECT_ROOT / ".env").read_text(encoding="utf-8")

        required_entries = (
            "SDN_ML_ENABLED=true",
            "SDN_IDS_MODE=hybrid",
            "SDN_ML_MODE=hybrid",
            "SDN_ML_HYBRID_POLICY=layered_consensus",
            "SDN_ML_MODEL_PATH=models/random_forest_runtime_final.joblib",
            "SDN_ML_ANOMALY_MODEL_PATH=models/isolation_forest_benign_heavy_20260417b.joblib",
            "SDN_ML_INFERENCE_MODE=combined",
        )
        for entry in required_entries:
            self.assertIn(entry, env_text)


if __name__ == "__main__":
    unittest.main()
