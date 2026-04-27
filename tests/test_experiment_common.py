"""Tests for experiment scenario and connectivity helpers."""

import tempfile
from pathlib import Path
import unittest

from core.ids_mode import IDSModeStateStore
from experiments.common import (
    _restart_controller_service,
    clear_switch_flow_state,
    clear_pending_controller_commands,
    ensure_controller_mode,
    EvaluationMode,
    EvaluationScenario,
    default_modes,
    default_scenarios,
    expected_public_mode,
    sync_controller_mode_state,
    wait_for_host_connectivity,
    warmup_scenario_connectivity,
)


class _Result(object):
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _Queue(object):
    def __init__(self):
        self.commands = []

    def enqueue(self, action, payload):
        command = {
            "command_id": "cmd-%s" % (len(self.commands) + 1),
            "action": action,
            "payload": dict(payload),
        }
        self.commands.append(command)
        return command


class ExperimentCommonTests(unittest.TestCase):
    def test_default_scenarios_include_layered_validation_cases(self):
        scenarios = default_scenarios()

        self.assertIn("threshold_syn_flood_h4", scenarios)
        self.assertIn("stealth_scan_h1", scenarios)
        self.assertIn("blended_stealth_scan_h1", scenarios)
        self.assertIn("periodic_beacon_h4", scenarios)
        self.assertTrue(
            scenarios["benign"].command.startswith(
                "sh /workspace/ryu-apps/traffic/benign_traffic.sh"
            )
        )
        self.assertEqual(
            scenarios["stealth_scan_h1"].expected_detection_target,
            "classifier",
        )
        self.assertTrue(scenarios["blended_stealth_scan_h1"].blended_with_benign)
        self.assertTrue(scenarios["periodic_beacon_h4"].threshold_evasive)
        self.assertEqual(
            scenarios["threshold_syn_flood_h4"].warmup_targets,
            ("10.0.0.5",),
        )

    def test_default_modes_include_mitigation_enabled_hybrid_blocking_mode(self):
        modes = default_modes(
            "models/random_forest_runtime_final.joblib",
            "models/isolation_forest_benign_heavy_20260417b.joblib",
        )

        self.assertIn("hybrid", modes)
        self.assertIn("hybrid_blocking", modes)
        self.assertFalse(modes["hybrid"].mitigation_enabled)
        self.assertTrue(modes["hybrid_blocking"].mitigation_enabled)
        self.assertEqual(
            modes["ml_enhanced_ids"].env["SDN_ML_HYBRID_POLICY"],
            "layered_consensus",
        )
        self.assertEqual(
            modes["hybrid"].env["SDN_ML_HYBRID_POLICY"],
            "layered_consensus",
        )
        self.assertEqual(
            modes["hybrid_blocking"].env["SDN_ML_HYBRID_POLICY"],
            "layered_consensus",
        )
        self.assertEqual(
            modes["hybrid_blocking"].env["SDN_ML_HYBRID_ANOMALY_ONLY_BLOCK_ENABLED"],
            "true",
        )
        self.assertEqual(
            modes["hybrid_blocking"].env["SDN_ML_HYBRID_ANOMALY_ONLY_BLOCK_THRESHOLD"],
            "0.75",
        )

    def test_wait_for_host_connectivity_retries_until_success(self):
        attempts = []

        def runner(host_name, command, capture_output=True, check=False):
            attempts.append((host_name, command, capture_output, check))
            return _Result(0 if len(attempts) >= 3 else 1)

        success = wait_for_host_connectivity(
            "h1",
            "10.0.0.2",
            timeout_seconds=2.0,
            runner=runner,
            sleep_fn=lambda _seconds: None,
        )

        self.assertTrue(success)
        self.assertEqual(len(attempts), 3)
        self.assertIn("ping -c 1 -W 1 10.0.0.2", attempts[0][1])

    def test_warmup_scenario_connectivity_raises_when_target_never_becomes_reachable(self):
        scenario = EvaluationScenario(
            name="benign",
            title="Benign",
            label="benign",
            host="h1",
            command="echo ok",
            description="warmup test",
            source_ip="10.0.0.1",
            warmup_targets=("10.0.0.2",),
        )

        def runner(_host_name, _command, capture_output=True, check=False):
            return _Result(1)

        with self.assertRaises(SystemExit):
            warmup_scenario_connectivity(
                scenario,
                timeout_seconds=1.0,
                runner=runner,
                sleep_fn=lambda _seconds: None,
            )

    def test_sync_controller_mode_state_persists_requested_public_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "ids_mode_state_eval.json"
            store = IDSModeStateStore(state_path)
            mode = EvaluationMode(
                name="anomaly_only",
                title="Anomaly Only",
                description="test",
                env={
                    "SDN_IDS_MODE": "ml",
                    "SDN_IDS_MODE_STATE_PATH": str(state_path.relative_to(Path(temp_dir))),
                },
                mitigation_enabled=False,
            )

            payload = sync_controller_mode_state(mode, state_store=store)

            self.assertEqual(payload["mode"], "ml")
            persisted = store.read()
            self.assertEqual(persisted["mode"], "ml")
            self.assertEqual(persisted["requested_by"], "evaluation_runner")

    def test_clear_pending_controller_commands_removes_stale_json_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pending_dir = Path(temp_dir) / "pending"
            pending_dir.mkdir(parents=True, exist_ok=True)
            (pending_dir / "stale-one.json").write_text("{}", encoding="utf-8")
            (pending_dir / "stale-two.json").write_text("{}", encoding="utf-8")

            removed = clear_pending_controller_commands(temp_dir)

            self.assertEqual(removed, 2)
            self.assertEqual(list(pending_dir.glob("*.json")), [])

    def test_expected_public_mode_uses_mode_env(self):
        mode = EvaluationMode(
            name="hybrid",
            title="Hybrid",
            description="test",
            env={"SDN_IDS_MODE": "hybrid"},
            mitigation_enabled=False,
        )

        self.assertEqual(expected_public_mode(mode), "hybrid")

    def test_ensure_controller_mode_enqueues_mode_change_until_selected(self):
        queue = _Queue()
        states = iter(
            [
                {"ml_status": {"selected_mode_api": "threshold"}},
                {"ml_status": {"selected_mode_api": "ml"}},
            ]
        )
        mode = EvaluationMode(
            name="classifier_only",
            title="Classifier Only",
            description="test",
            env={"SDN_IDS_MODE": "ml"},
            mitigation_enabled=False,
        )

        payload = ensure_controller_mode(
            mode,
            timeout_seconds=2.0,
            state_reader=lambda: next(states),
            command_queue=queue,
            sleep_fn=lambda _seconds: None,
        )

        self.assertEqual(payload["ml_status"]["selected_mode_api"], "ml")
        self.assertEqual(len(queue.commands), 1)
        self.assertEqual(queue.commands[0]["action"], "set_ids_mode")
        self.assertEqual(queue.commands[0]["payload"]["mode"], "ml")

    def test_restart_controller_service_retries_on_container_name_conflict(self):
        attempts = []
        mode = EvaluationMode(
            name="hybrid_blocking",
            title="Hybrid Blocking",
            description="test",
            env={"SDN_IDS_MODE": "hybrid"},
            mitigation_enabled=True,
        )

        def compose_runner(command, env=None, capture_output=True, check=False):
            attempts.append((tuple(command), dict(env or {}), capture_output, check))
            if len(attempts) == 1:
                return _Result(
                    1,
                    stderr=(
                        "Error response from daemon: Error when allocating new name: "
                        "Conflict. The container name \"/sdn-security-controller\" is already in use."
                    ),
                )
            return _Result(0)

        result = _restart_controller_service(
            mode,
            compose_runner=compose_runner,
            sleep_fn=lambda _seconds: None,
            max_attempts=2,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(attempts), 2)

    def test_clear_switch_flow_state_invokes_flow_flush_command(self):
        calls = []

        def compose_runner(command, capture_output=True, check=False):
            calls.append((tuple(command), capture_output, check))
            return _Result(0)

        result = clear_switch_flow_state(compose_runner=compose_runner)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][:3], ("exec", "mininet", "sh"))
        self.assertIn("ovs-ofctl -O OpenFlow13 del-flows", calls[0][0][-1])


if __name__ == "__main__":
    unittest.main()
