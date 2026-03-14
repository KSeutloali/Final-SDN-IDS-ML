"""Tests for the shared dashboard state writer and reader."""

import tempfile
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
            self.assertEqual(enriched["performance"]["flow_installs_total"], 1)
            self.assertTrue("captures" in enriched)


if __name__ == "__main__":
    unittest.main()
