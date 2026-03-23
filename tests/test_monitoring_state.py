"""Tests for the shared dashboard state writer and reader."""

import json
from pathlib import Path
import tempfile
import time
import unittest

from config.settings import DashboardConfig
from monitoring.metrics import MetricsStore
from monitoring.state import DashboardDataAdapter, DashboardStateReader, DashboardStateWriter
from security.firewall import TemporaryBlock


class _ControllerStateStub(object):
    def __init__(self):
        self.datapaths = {1: object()}
        self.hosts = {}


class _FirewallStub(object):
    def __init__(self):
        self.quarantined_hosts = {}
        self.temporary_blocks = self.quarantined_hosts


class DashboardStateTests(unittest.TestCase):
    def test_writer_and_reader_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_file_path = temp_dir + "/dashboard_state.json"
            dashboard_config = DashboardConfig(
                state_file_path=state_file_path,
                persist_interval_seconds=0.0,
                timeseries_points=4,
            )
            writer = DashboardStateWriter(dashboard_config)
            reader = DashboardStateReader(dashboard_config)

            metrics = MetricsStore()
            controller_state = _ControllerStateStub()
            firewall = _FirewallStub()
            firewall.quarantined_hosts["10.0.0.3"] = TemporaryBlock(
                src_ip="10.0.0.3",
                reason="ids_port_scan_detected",
                expires_at=9999999999.0,
                detector="threshold",
                alert_type="port_scan_detected",
            )

            metrics.record_controller_event("datapath_up", {"dpid": "0000000000000001"})
            metrics.record_flow_event(
                "flow_rule_installed",
                {
                    "dpid": "0000000000000001",
                    "reason": "table_miss",
                    "priority": 0,
                },
            )
            payload = writer.publish(
                metrics,
                controller_state,
                firewall,
                force=True,
                ml_status={
                    "configured_mode": "hybrid",
                    "effective_mode": "hybrid",
                    "hybrid_policy": "alert_only",
                    "model_available": True,
                    "model_path": "models/test.joblib",
                },
                config_snapshot={"ids": {"enabled": True}},
            )
            loaded = reader.read()
            adapter = DashboardDataAdapter(
                type(
                    "Config",
                    (),
                    {
                        "dashboard": dashboard_config,
                        "ml": type(
                            "ML",
                            (),
                            {
                                "mode": "threshold_only",
                                "hybrid_policy": "alert_only",
                                "model_path": "models/random_forest_ids.joblib",
                            },
                        )(),
                    },
                )()
            )
            adapter.state_reader = reader
            enriched = adapter.read()

            self.assertEqual(payload["summary"]["active_switches"], 1)
            self.assertEqual(loaded["summary"]["active_blocks"], 1)
            self.assertEqual(len(loaded["blocked_hosts"]), 1)
            self.assertEqual(loaded["blocked_hosts"][0]["src_ip"], "10.0.0.3")
            self.assertEqual(loaded["blocked_hosts"][0]["detector"], "threshold")
            self.assertTrue(isinstance(loaded["timeseries"], list))
            self.assertEqual(loaded["ml_status"]["effective_mode"], "hybrid")
            self.assertEqual(enriched["ml"]["effective_mode"], "hybrid")
            self.assertEqual(enriched["ml"]["selected_mode_api"], "hybrid")
            self.assertEqual(enriched["ml"]["effective_mode_api"], "hybrid")
            self.assertEqual(enriched["performance"]["flow_installs_total"], 1)
            self.assertTrue("captures" in enriched)
            self.assertEqual(
                enriched["settings"]["ids_runtime"]["effective_mode"],
                "Hybrid",
            )
            self.assertEqual(enriched["summary"]["active_threshold_blocks"], 1)
            self.assertEqual(enriched["summary"]["active_ml_blocks"], 0)

    def test_writer_preserves_existing_state_until_real_publish(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_file_path = temp_dir + "/dashboard_state.json"
            dashboard_config = DashboardConfig(
                state_file_path=state_file_path,
                persist_interval_seconds=60.0,
                timeseries_points=4,
            )
            with open(state_file_path, "w") as handle:
                handle.write(
                    '{"generated_at_epoch": 10, "summary": {"total_packets": 123}, "timeseries": []}'
                )

            writer = DashboardStateWriter(dashboard_config)
            reader = DashboardStateReader(dashboard_config)
            loaded = reader.read()

            self.assertEqual(loaded["summary"]["total_packets"], 123)
            self.assertEqual(writer._last_persist_at, 10.0)

    def test_stale_continuous_capture_state_is_marked_inactive(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_file_path = temp_dir + "/dashboard_state.json"
            dashboard_config = DashboardConfig(
                state_file_path=state_file_path,
                persist_interval_seconds=0.0,
                timeseries_points=4,
            )
            reader = DashboardStateReader(dashboard_config)
            adapter = DashboardDataAdapter(
                type(
                    "Config",
                    (),
                    {
                        "dashboard": dashboard_config,
                        "ml": type(
                            "ML",
                            (),
                            {
                                "mode": "threshold_only",
                                "hybrid_policy": "alert_only",
                                "model_path": "models/random_forest_ids.joblib",
                            },
                        )(),
                    },
                )()
            )
            adapter.state_reader = reader
            adapter.capture_root = Path(temp_dir) / "captures"
            adapter.active_capture_file = adapter.capture_root / ".active_capture_session"
            adapter.continuous_capture_state_file = (
                adapter.capture_root / "continuous" / "continuous_capture_state.json"
            )
            adapter.continuous_capture_state_file.parent.mkdir(parents=True, exist_ok=True)
            adapter.continuous_capture_state_file.write_text(
                json.dumps(
                    {
                        "active": True,
                        "enabled": True,
                        "updated_at_epoch": time.time() - 600.0,
                        "stale_after_seconds": 75.0,
                        "interfaces": [{"interface": "s2-eth3", "status": "active"}],
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

            enriched = adapter.read()

            self.assertFalse(enriched["captures"]["continuous"]["active"])
            self.assertTrue(enriched["captures"]["continuous"]["stale"])
            self.assertEqual(
                enriched["captures"]["continuous"]["reason"],
                "capture_state_stale",
            )


if __name__ == "__main__":
    unittest.main()
