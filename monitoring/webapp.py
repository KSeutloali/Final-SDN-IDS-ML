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
        "description": "Live security posture and controller health.",
        "template": "dashboard.html",
        "suffix": "",
        "api_suffix": "/api/dashboard",
    },
    {
        "name": "traffic",
        "label": "Traffic",
        "description": "Rates, protocols, and top talkers.",
        "template": "traffic.html",
        "suffix": "/traffic",
        "api_suffix": "/api/traffic",
    },
    {
        "name": "alerts",
        "label": "Alerts",
        "description": "Detections, severity, and evidence.",
        "template": "alerts.html",
        "suffix": "/alerts",
        "api_suffix": "/api/alerts",
    },
    {
        "name": "blocked_hosts",
        "label": "Blocks",
        "description": "Current quarantines and analyst release actions.",
        "template": "blocked_hosts.html",
        "suffix": "/blocked-hosts",
        "api_suffix": "/api/blocked-hosts",
    },
    {
        "name": "performance",
        "label": "Performance",
        "description": "PacketIn pace, flow activity, and controller events.",
        "template": "performance.html",
        "suffix": "/performance",
        "api_suffix": "/api/performance",
    },
    {
        "name": "captures",
        "label": "Captures",
        "description": "Rolling PCAPs and preserved alert evidence.",
        "template": "captures.html",
        "suffix": "/captures",
        "api_suffix": "/api/captures",
    },
    {
        "name": "ml_ids",
        "label": "ML IDS",
        "description": "Runtime model health and prediction activity.",
        "template": "ml_ids.html",
        "suffix": "/ml-ids",
        "api_suffix": "/api/ml-ids",
    },
    {
        "name": "settings",
        "label": "Settings",
        "description": "Live IDS, firewall, and dashboard config.",
        "template": "settings.html",
        "suffix": "/settings",
        "api_suffix": "/api/settings",
    },
)

NAV_ICON_PATHS = {
    "dashboard": (
        '<path d="M4 12.5 12 5l8 7.5" />'
        '<path d="M6.5 10.5V20h11V10.5" />'
    ),
    "traffic": (
        '<path d="M4 16h4l3-5 3 3 6-8" />'
        '<path d="M20 10V6h-4" />'
    ),
    "alerts": (
        '<path d="M12 4 20 18H4L12 4Z" />'
        '<path d="M12 9v4" />'
        '<path d="M12 16h.01" />'
    ),
    "blocked_hosts": (
        '<path d="M12 4 18 6.5V12c0 4-2.6 6.8-6 8-3.4-1.2-6-4-6-8V6.5L12 4Z" />'
        '<path d="m9 15 6-6" />'
    ),
    "performance": (
        '<path d="M4 16h3l2.2-6 3.1 9 2.6-5H20" />'
    ),
    "captures": (
        '<path d="M4 8h6l2 2h8v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8Z" />'
        '<path d="M9 13h6" />'
    ),
    "ml_ids": (
        '<path d="M9 4v3M15 4v3M9 17v3M15 17v3M4 9h3M17 9h3M4 15h3M17 15h3" />'
        '<rect x="7" y="7" width="10" height="10" rx="2" />'
        '<path d="M10 10h4v4h-4z" />'
    ),
    "settings": (
        '<path d="M12 8.5a3.5 3.5 0 1 1 0 7 3.5 3.5 0 0 1 0-7Z" />'
        '<path d="M19 12a7 7 0 0 0-.08-1l2.08-1.62-2-3.46-2.5 1a7 7 0 0 0-1.73-1L14.5 3h-5l-.27 2.92a7 7 0 0 0-1.73 1l-2.5-1-2 3.46L5.08 11a7 7 0 0 0 0 2L3 14.62l2 3.46 2.5-1a7 7 0 0 0 1.73 1L9.5 21h5l.27-2.92a7 7 0 0 0 1.73-1l2.5 1 2-3.46L18.92 13c.05-.33.08-.66.08-1Z" />'
    ),
}


def _nav_icon_svg(page_name):
    paths = NAV_ICON_PATHS.get(page_name, '<circle cx="12" cy="12" r="7" />')
    return (
        '<svg class="nav-link__svg" viewBox="0 0 24 24" fill="none" '
        'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
        'stroke-linejoin="round" aria-hidden="true">%s</svg>'
    ) % paths


def _build_navigation(base_path):
    items = []
    for page in PAGE_DEFINITIONS:
        href = base_path + page["suffix"] if page["suffix"] else base_path
        items.append(
            {
                "name": page["name"],
                "label": page["label"],
                "href": href,
                "icon_svg": _nav_icon_svg(page["name"]),
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
