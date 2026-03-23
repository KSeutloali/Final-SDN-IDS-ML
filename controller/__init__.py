"""Controller package exports.

Keep imports lazy so test discovery does not require Ryu to be installed.
"""

__all__ = ["SecurityController"]


def __getattr__(name):
    if name == "SecurityController":
        from controller.main import SecurityController

        return SecurityController
    raise AttributeError(name)
