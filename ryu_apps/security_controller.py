"""Compatibility Ryu entry point for the first-phase firewall controller."""

from controller.main import SecurityController as BaseSecurityController


class SecurityController(BaseSecurityController):
    """Thin wrapper so ryu-manager can discover the app from this module path."""


__all__ = ["SecurityController"]
