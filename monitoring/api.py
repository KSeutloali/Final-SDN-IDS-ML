"""Flask JSON API endpoints for the SDN monitoring dashboard."""

from flask import Blueprint, jsonify, request

from core.ids_mode import normalize_ids_mode_public


def create_api_blueprint(data_adapter, command_queue):
    """Create dashboard polling endpoints backed by the shared state adapter."""

    blueprint = Blueprint("monitoring_api", __name__)

    @blueprint.route("/api/health", methods=["GET"])
    def health():
        return jsonify(data_adapter.health_payload())

    @blueprint.route("/api/dashboard", methods=["GET"])
    @blueprint.route("/api/overview", methods=["GET"])
    def overview():
        return jsonify(data_adapter.payload_for("dashboard"))

    @blueprint.route("/api/traffic", methods=["GET"])
    def traffic():
        return jsonify(data_adapter.payload_for("traffic"))

    @blueprint.route("/api/alerts", methods=["GET"])
    def alerts():
        return jsonify(data_adapter.payload_for("alerts"))

    @blueprint.route("/api/blocked-hosts", methods=["GET"])
    def blocked_hosts():
        return jsonify(data_adapter.payload_for("blocked_hosts"))

    @blueprint.route("/api/blocked-hosts/<path:src_ip>/unblock", methods=["POST"])
    def unblock_host(src_ip):
        if not src_ip:
            return (
                jsonify(
                    {
                        "accepted": False,
                        "status": "invalid_request",
                        "reason": "missing_src_ip",
                    }
                ),
                400,
            )

        command = command_queue.enqueue(
            "unblock_host",
            {
                "src_ip": src_ip,
                "requested_by": "dashboard",
            },
        )
        return jsonify(
            {
                "accepted": True,
                "status": "queued",
                "src_ip": src_ip,
                "command_id": command.get("command_id"),
            }
        ), 202

    @blueprint.route("/api/set_ids_mode", methods=["POST"])
    @blueprint.route("/api/set-ids-mode", methods=["POST"])
    def set_ids_mode():
        payload = request.get_json(silent=True) or {}
        raw_mode = payload.get("mode")
        if raw_mode is None:
            return (
                jsonify(
                    {
                        "accepted": False,
                        "status": "invalid_request",
                        "reason": "missing_mode",
                    }
                ),
                400,
            )

        raw_mode_normalized = str(raw_mode).strip().lower()
        if raw_mode_normalized not in (
            "threshold",
            "threshold_only",
            "ml",
            "ml_only",
            "hybrid",
        ):
            return (
                jsonify(
                    {
                        "accepted": False,
                        "status": "invalid_mode",
                        "reason": "unsupported_mode",
                        "allowed_modes": ["threshold", "ml", "hybrid"],
                    }
                ),
                400,
            )

        normalized_mode = normalize_ids_mode_public(raw_mode)

        command = command_queue.enqueue(
            "set_ids_mode",
            {
                "mode": normalized_mode,
                "requested_by": "dashboard",
            },
        )
        return jsonify(
            {
                "accepted": True,
                "status": "queued",
                "mode": normalized_mode,
                "command_id": command.get("command_id"),
            }
        ), 202

    @blueprint.route("/api/commands/<path:command_id>", methods=["GET"])
    def command_status(command_id):
        command = command_queue.get_status(command_id)
        if command is None:
            return (
                jsonify(
                    {
                        "found": False,
                        "command_id": command_id,
                    }
                ),
                404,
            )

        return jsonify(
            {
                "found": True,
                "command_id": command.get("command_id"),
                "action": command.get("action"),
                "status": command.get("status"),
                "requested_at": command.get("requested_at"),
                "processed_at": command.get("processed_at"),
                "payload": command.get("payload") or {},
                "result": command.get("result") or {},
            }
        )

    @blueprint.route("/api/performance", methods=["GET"])
    def performance():
        return jsonify(data_adapter.payload_for("performance"))

    @blueprint.route("/api/captures", methods=["GET"])
    def captures():
        return jsonify(data_adapter.payload_for("captures"))

    @blueprint.route("/api/ml-ids", methods=["GET"])
    def ml_ids():
        return jsonify(data_adapter.payload_for("ml_ids"))

    @blueprint.route("/api/settings", methods=["GET"])
    def settings():
        return jsonify(data_adapter.payload_for("settings"))

    @blueprint.route("/api/summary", methods=["GET"])
    def summary():
        return jsonify(data_adapter.read().get("summary", {}))

    @blueprint.route("/api/events", methods=["GET"])
    def events():
        payload = data_adapter.read()
        return jsonify(
            {
                "alerts": payload.get("alerts", {}).get("rows", []),
                "controller_activity": payload.get("controller_activity", []),
                "recent_ml_predictions": payload.get("recent_ml_predictions", []),
                "recent_hybrid_events": payload.get("recent_hybrid_events", []),
            }
        )

    @blueprint.route("/api/timeseries", methods=["GET"])
    def timeseries():
        payload = data_adapter.read()
        return jsonify({"timeseries": payload.get("timeseries", [])})

    return blueprint
