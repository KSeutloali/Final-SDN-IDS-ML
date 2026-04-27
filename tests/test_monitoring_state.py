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

    def test_alert_rows_use_stable_row_ids_and_deduplicate(self):
        adapter = DashboardDataAdapter(
            type(
                "Config",
                (),
                {
                    "dashboard": DashboardConfig(state_file_path="runtime/test_dashboard_state.json"),
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
        events = [
            {
                "timestamp": "2026-04-26T12:00:00+00:00",
                "category": "ids_alert",
                "alert_type": "port_scan_detected",
                "src_ip": "10.0.0.3",
                "reason": "tcp_scan_threshold_exceeded",
            },
            {
                "timestamp": "2026-04-26T12:00:00+00:00",
                "category": "ids_alert",
                "alert_type": "port_scan_detected",
                "src_ip": "10.0.0.3",
                "reason": "tcp_scan_threshold_exceeded",
            },
            {
                "timestamp": "2026-04-26T12:00:01+00:00",
                "category": "ml_alert",
                "alert_type": "ml_detected",
                "src_ip": "10.0.0.7",
                "reason": "model_confidence_high",
            },
        ]

        rows = adapter._alert_rows(events)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["src_ip"], "10.0.0.7")
        self.assertTrue(all("row_id" in row and len(row["row_id"]) == 16 for row in rows))
        self.assertNotEqual(rows[0]["row_id"], rows[1]["row_id"])

    def test_capture_delete_selected_removes_snapshot_and_ring_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard_config = DashboardConfig(
                state_file_path=temp_dir + "/dashboard_state.json",
                persist_interval_seconds=0.0,
                timeseries_points=4,
            )
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
                        "capture": type(
                            "Capture",
                            (),
                            {"output_directory": temp_dir + "/captures"},
                        )(),
                    },
                )()
            )
            adapter.capture_root = Path(temp_dir) / "captures"
            adapter.capture_root.mkdir(parents=True, exist_ok=True)
            snapshots_dir = adapter.capture_root / "snapshots" / "snapshot_a"
            snapshots_dir.mkdir(parents=True, exist_ok=True)
            (snapshots_dir / "capture-a.pcap").write_bytes(b"pcap-a")
            (snapshots_dir / "snapshot.json").write_text("{}", encoding="utf-8")

            ring_dir = adapter.capture_root / "continuous" / "ring" / "s2-eth3"
            ring_dir.mkdir(parents=True, exist_ok=True)
            ring_file = ring_dir / "ring-1.pcap"
            ring_file.write_bytes(b"pcap-b")

            result = adapter.delete_selected_captures(
                snapshot_names=["snapshot_a"],
                file_paths=["continuous/ring/s2-eth3/ring-1.pcap"],
            )

            self.assertEqual(result["deleted_snapshot_count"], 1)
            self.assertEqual(result["deleted_file_count"], 2)
            self.assertFalse((adapter.capture_root / "snapshots" / "snapshot_a").exists())
            self.assertFalse(ring_file.exists())

    def test_build_report_returns_downloadable_content(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_file_path = temp_dir + "/dashboard_state.json"
            dashboard_config = DashboardConfig(
                state_file_path=state_file_path,
                persist_interval_seconds=0.0,
                timeseries_points=4,
            )
            Path(state_file_path).write_text(
                json.dumps(
                    {
                        "generated_at": "2026-04-26T12:34:56+00:00",
                        "summary": {
                            "alerts_total": 4,
                            "threshold_alerts_total": 3,
                            "ml_alerts_total": 1,
                            "active_blocks": 2,
                        },
                        "ml_status": {
                            "configured_mode": "hybrid",
                            "selected_mode": "hybrid",
                            "effective_mode": "hybrid",
                            "model_available": True,
                            "model_path": "models/test.joblib",
                        },
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

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

            report = adapter.build_report("hybrid-summary")

            self.assertEqual(report["format"], "json")
            self.assertTrue(report["filename"].endswith(".json"))
            self.assertIn("application/json", report["mime_type"])
            self.assertIn("detector_totals", report["content"].decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
