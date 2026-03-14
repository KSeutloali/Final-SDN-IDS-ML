"""Lightweight Flask dashboard for SDN controller monitoring."""

from flask import Flask, abort, redirect, render_template, send_file

from config.settings import load_config
from core.command_queue import ControllerCommandQueue
from monitoring.api import create_api_blueprint
from monitoring.state import DashboardDataAdapter


PAGE_DEFINITIONS = (
    {
        "name": "dashboard",
        "label": "Overview",
        "description": "Live controller status and security posture.",
        "template": "dashboard.html",
        "suffix": "",
        "api_suffix": "/api/dashboard",
    },
    {
        "name": "traffic",
        "label": "Traffic Analytics",
        "description": "Protocol mix, top talkers, and traffic trends.",
        "template": "traffic.html",
        "suffix": "/traffic",
        "api_suffix": "/api/traffic",
    },
    {
        "name": "alerts",
        "label": "Security Alerts",
        "description": "Live IDS and mitigation events with severity context.",
        "template": "alerts.html",
        "suffix": "/alerts",
        "api_suffix": "/api/alerts",
    },
    {
        "name": "blocked_hosts",
        "label": "Blocked Hosts",
        "description": "Indefinite analyst-held quarantines with forensic evidence links.",
        "template": "blocked_hosts.html",
        "suffix": "/blocked-hosts",
        "api_suffix": "/api/blocked-hosts",
    },
    {
        "name": "performance",
        "label": "Controller Performance",
        "description": "PacketIn activity, flow installs, and controller events.",
        "template": "performance.html",
        "suffix": "/performance",
        "api_suffix": "/api/performance",
    },
    {
        "name": "captures",
        "label": "Packet Capture",
        "description": "Continuous rolling capture plus preserved forensic alert snapshots.",
        "template": "captures.html",
        "suffix": "/captures",
        "api_suffix": "/api/captures",
    },
    {
        "name": "ml_ids",
        "label": "ML IDS",
        "description": "Model status, predictions, and hybrid detection signals.",
        "template": "ml_ids.html",
        "suffix": "/ml-ids",
        "api_suffix": "/api/ml-ids",
    },
    {
        "name": "settings",
        "label": "Settings",
        "description": "Active IDS, firewall, dashboard, and ML configuration.",
        "template": "settings.html",
        "suffix": "/settings",
        "api_suffix": "/api/settings",
    },
)


def _build_navigation(base_path):
    items = []
    for page in PAGE_DEFINITIONS:
        href = base_path + page["suffix"] if page["suffix"] else base_path
        items.append(
            {
                "name": page["name"],
                "label": page["label"],
                "href": href,
            }
        )
    return items


def create_app():
    """Build the Flask monitoring application."""

    app_config = load_config()
    dashboard_config = app_config.dashboard
    data_adapter = DashboardDataAdapter(app_config)
    command_queue = ControllerCommandQueue()
    navigation_items = _build_navigation(dashboard_config.base_path)

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["dashboard_config"] = dashboard_config
    app.register_blueprint(
        create_api_blueprint(data_adapter, command_queue),
        url_prefix=dashboard_config.base_path,
    )

    @app.context_processor
    def inject_dashboard_context():
        return {
            "dashboard_title": "SDN Security Monitor",
            "base_path": dashboard_config.base_path,
            "poll_interval_ms": int(dashboard_config.poll_interval_seconds * 1000),
            "navigation_items": navigation_items,
        }

    @app.route("/")
    def root():
        return redirect(dashboard_config.base_path)

    def _render_page(page_definition):
        return render_template(
            page_definition["template"],
            page_name=page_definition["name"],
            page_title=page_definition["label"],
            page_description=page_definition["description"],
            page_api=dashboard_config.base_path + page_definition["api_suffix"],
        )

    for page_definition in PAGE_DEFINITIONS:
        route_path = dashboard_config.base_path + page_definition["suffix"]
        endpoint_name = "page_%s" % page_definition["name"]
        app.add_url_rule(
            route_path,
            endpoint_name,
            (lambda definition=page_definition: _render_page(definition)),
        )
        if page_definition["suffix"] == "":
            app.add_url_rule(
                dashboard_config.base_path + "/",
                endpoint_name + "_slash",
                (lambda definition=page_definition: _render_page(definition)),
            )

    @app.route(dashboard_config.base_path + "/captures/download/<path:relative_path>")
    def download_capture(relative_path):
        resolved_path = data_adapter.resolve_capture_path(relative_path)
        if resolved_path is None:
            abort(404)
        return send_file(
            str(resolved_path),
            as_attachment=True,
            download_name=resolved_path.name,
        )

    return app


if __name__ == "__main__":
    config = load_config()
    app = create_app()
    app.run(
        host=config.dashboard.host,
        port=config.dashboard.port,
        debug=False,
        threaded=True,
        use_reloader=False,
    )
