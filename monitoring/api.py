"""Flask JSON API endpoints for the SDN monitoring dashboard."""

from flask import Blueprint, jsonify


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
        payload = data_adapter.payload_for("blocked_hosts")
        active_sources = {row.get("src_ip") for row in payload.get("blocked_hosts", [])}
        if src_ip not in active_sources:
            return (
                jsonify(
                    {
                        "accepted": False,
                        "status": "not_blocked",
                        "src_ip": src_ip,
                    }
                ),
                404,
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
