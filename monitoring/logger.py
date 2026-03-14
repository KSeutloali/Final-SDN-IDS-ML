"""Structured logging helpers for the modular firewall controller."""

import logging
from pathlib import Path


def configure_logger(logging_config):
    """Create the shared controller logger."""

    logger = logging.getLogger("sdn_security")
    logger.setLevel(getattr(logging, logging_config.level.upper(), logging.INFO))

    if logger.handlers:
        return logger

    formatter = logging.Formatter(logging_config.format_string)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    if logging_config.file_path:
        log_path = Path(logging_config.file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_path))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger


class StructuredLogger(object):
    """Emit compact key=value log messages for controller events."""

    def __init__(self, logger, log_allowed_traffic=False):
        self.logger = logger
        self.log_allowed_traffic = log_allowed_traffic

    def controller_event(self, action, dpid=None, reason=None, **fields):
        self._emit(
            self.logger.info,
            "controller",
            action=action,
            dpid=dpid,
            reason=reason,
            **fields
        )

    def flow_event(self, action, dpid=None, reason=None, priority=None, **fields):
        self._emit(
            self.logger.info,
            "flow",
            action=action,
            dpid=dpid,
            priority=priority,
            reason=reason,
            **fields
        )

    def traffic_event(self, packet_metadata, action, reason, dpid=None, out_port=None):
        if action == "allow" and not self.log_allowed_traffic:
            return

        log_method = self.logger.warning if action == "block" else self.logger.info
        self._emit(
            log_method,
            "traffic",
            action=action,
            dpid=dpid or packet_metadata.dpid,
            src_mac=packet_metadata.eth_src,
            dst_mac=packet_metadata.eth_dst,
            src_ip=packet_metadata.src_ip,
            dst_ip=packet_metadata.dst_ip,
            proto=packet_metadata.protocol_label(),
            src_port=packet_metadata.src_port,
            dst_port=packet_metadata.dst_port,
            in_port=packet_metadata.in_port,
            out_port=out_port,
            reason=reason,
        )

    def security_event(self, action, src_ip, reason, duration_seconds=None, dpid=None, **fields):
        self._emit(
            self.logger.warning,
            "security",
            action=action,
            dpid=dpid,
            src_ip=src_ip,
            duration_seconds=duration_seconds,
            reason=reason,
            **fields
        )

    def ml_event(self, action, src_ip=None, reason=None, **fields):
        self._emit(
            self.logger.warning,
            "ml",
            action=action,
            src_ip=src_ip,
            reason=reason,
            **fields
        )

    def _emit(self, log_method, event, **fields):
        parts = ["event=%s" % event]
        for key in sorted(fields):
            value = fields[key]
            if value is None or value == "":
                continue
            parts.append("%s=%s" % (key, self._sanitize(value)))
        log_method(" ".join(parts))

    @staticmethod
    def _sanitize(value):
        return str(value).replace(" ", "_")
