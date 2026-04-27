"""Tests for dashboard API command handling."""

import tempfile
import unittest

try:
    from flask import Flask
    from monitoring.api import create_api_blueprint
except ImportError:  # pragma: no cover - depends on local test environment
    Flask = None
    create_api_blueprint = None

from core.command_queue import ControllerCommandQueue


class _AdapterStub(object):
    def __init__(self):
        self.payload = {
            "summary": {},
            "traffic": {},
            "alerts": {"rows": []},
            "blocked_hosts": [],
            "performance": {},
            "captures": {},
            "ml": {
                "selected_mode_api": "threshold",
                "effective_mode_api": "threshold",
                "model_available": False,
            },
            "settings": {},
        }
        self.delete_selected_requests = []
        self.delete_all_invocations = 0

    def health_payload(self):
        return {"status": "ok", "generated_at": "now"}

    def payload_for(self, page_name):
        payload = dict(self.payload)
        payload["page"] = page_name
        return payload

    def read(self):
        return dict(self.payload)

    def delete_selected_captures(self, snapshot_names=None, file_paths=None):
        request_payload = {
            "snapshot_names": list(snapshot_names or []),
            "file_paths": list(file_paths or []),
        }
        self.delete_selected_requests.append(request_payload)
        return {
            "deleted_snapshot_count": len(request_payload["snapshot_names"]),
            "deleted_file_count": len(request_payload["file_paths"]),
            "failed": [],
        }

    def delete_all_captures(self):
        self.delete_all_invocations += 1
        return {
            "deleted_snapshot_count": 3,
            "deleted_file_count": 9,
            "failed": [],
        }

    @staticmethod
    def available_reports():
        return [
            {
                "key": "hybrid-summary",
                "title": "Hybrid IDS Summary",
                "default_format": "json",
                "formats": ["json"],
            }
        ]

    @staticmethod
    def build_report(report_key, requested_format=None):
        if report_key != "hybrid-summary":
            raise KeyError(report_key)
        if requested_format not in (None, "json"):
            raise ValueError(requested_format)
        return {
            "content": b'{"status":"ok"}\n',
            "filename": "hybrid_summary_test.json",
            "mime_type": "application/json",
        }


@unittest.skipIf(Flask is None, "Flask is not installed in this interpreter")
class MonitoringAPITests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.command_queue = ControllerCommandQueue(root_path=self.temp_dir.name)
        app = Flask(__name__)
        self.adapter = _AdapterStub()
        app.register_blueprint(
            create_api_blueprint(self.adapter, self.command_queue),
            url_prefix="/sdn-security",
        )
        self.client = app.test_client()

    def test_set_ids_mode_queues_command_without_stale_model_gate(self):
        response = self.client.post(
            "/sdn-security/api/set-ids-mode",
            json={"mode": "ml"},
        )

        self.assertEqual(response.status_code, 202)
        payload = response.get_json()
        self.assertTrue(payload["accepted"])
        queued = self.command_queue.get_status(payload["command_id"])
        self.assertEqual(queued["action"], "set_ids_mode")
        self.assertEqual(queued["payload"]["mode"], "ml")

    def test_unblock_host_queues_command_without_snapshot_precheck(self):
        response = self.client.post("/sdn-security/api/blocked-hosts/10.0.0.3/unblock")

        self.assertEqual(response.status_code, 202)
        payload = response.get_json()
        self.assertTrue(payload["accepted"])
        queued = self.command_queue.get_status(payload["command_id"])
        self.assertEqual(queued["action"], "unblock_host")
        self.assertEqual(queued["payload"]["src_ip"], "10.0.0.3")

    def test_command_status_endpoint_reports_processed_commands(self):
        command = self.command_queue.enqueue("set_ids_mode", {"mode": "hybrid"})
        self.command_queue.mark_processed(
            command,
            status="completed",
            result={"selected_mode": "hybrid"},
        )

        response = self.client.get(
            "/sdn-security/api/commands/%s" % command["command_id"]
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["found"])
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["result"]["selected_mode"], "hybrid")

    def test_capture_delete_selected_requires_non_empty_selection(self):
        response = self.client.post(
            "/sdn-security/api/captures/delete-selected",
            json={"snapshot_names": [], "file_paths": []},
        )

        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertFalse(payload["accepted"])
        self.assertEqual(payload["reason"], "empty_selection")

    def test_capture_delete_selected_calls_adapter(self):
        response = self.client.post(
            "/sdn-security/api/captures/delete-selected",
            json={
                "snapshot_names": ["snapshot-1"],
                "file_paths": ["continuous/ring/s2-eth3/file-1.pcap"],
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["accepted"])
        self.assertEqual(payload["result"]["deleted_snapshot_count"], 1)
        self.assertEqual(payload["result"]["deleted_file_count"], 1)
        self.assertEqual(len(self.adapter.delete_selected_requests), 1)

    def test_capture_delete_all_requires_explicit_confirmation(self):
        rejected = self.client.post(
            "/sdn-security/api/captures/delete-all",
            json={},
        )
        self.assertEqual(rejected.status_code, 400)

        accepted = self.client.post(
            "/sdn-security/api/captures/delete-all",
            json={"confirm": True},
        )
        self.assertEqual(accepted.status_code, 200)
        payload = accepted.get_json()
        self.assertTrue(payload["accepted"])
        self.assertEqual(payload["result"]["deleted_snapshot_count"], 3)
        self.assertEqual(self.adapter.delete_all_invocations, 1)

    def test_report_download_returns_attachment(self):
        response = self.client.get("/sdn-security/api/reports/hybrid-summary")

        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment; filename=", response.headers.get("Content-Disposition", ""))
        self.assertEqual(response.get_data(as_text=True).strip(), '{"status":"ok"}')

    def test_report_download_rejects_unsupported_format(self):
        response = self.client.get(
            "/sdn-security/api/reports/hybrid-summary?format=csv",
        )

        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertEqual(payload["reason"], "unsupported_format")


if __name__ == "__main__":
    unittest.main()
