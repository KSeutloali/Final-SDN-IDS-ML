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

    def health_payload(self):
        return {"status": "ok", "generated_at": "now"}

    def payload_for(self, page_name):
        payload = dict(self.payload)
        payload["page"] = page_name
        return payload

    def read(self):
        return dict(self.payload)


@unittest.skipIf(Flask is None, "Flask is not installed in this interpreter")
class MonitoringAPITests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.command_queue = ControllerCommandQueue(root_path=self.temp_dir.name)
        app = Flask(__name__)
        app.register_blueprint(
            create_api_blueprint(_AdapterStub(), self.command_queue),
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


if __name__ == "__main__":
    unittest.main()
