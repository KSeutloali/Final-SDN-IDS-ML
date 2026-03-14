"""Compatibility wrapper for the Flask monitoring dashboard."""

from monitoring.webapp import create_app

__all__ = ["create_app"]
