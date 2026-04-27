"""Quarantine-oriented IDS response actions built on top of firewall block flows."""

from dataclasses import dataclass


@dataclass
class MitigationResult(object):
    """Outcome of one mitigation request."""

    src_ip: str
    reason: str
    status: str
    alert_type: str = None
    detector: str = None
    created_at: float = None
    related_capture: dict = None


def should_auto_quarantine_threshold_alert(alert):
    """Return whether one threshold IDS alert should auto-quarantine the source.

    Threshold detections remain authoritative. The only narrow exception is
    ICMP sweep alerts that do not exceed the unique-host coverage threshold:
    those are treated as alert-only because benign reachability checks can
    generate the same repeated-probe pattern in compact lab topologies.
    """

    if alert is None:
        return False

    if getattr(alert, "reason", "") != "icmp_sweep_threshold_exceeded":
        return True

    details = dict(getattr(alert, "details", {}) or {})
    exceeds_host_coverage = details.get("exceeds_host_coverage_threshold")
    if exceeds_host_coverage is None:
        return True
    return bool(exceeds_host_coverage)


def clear_quarantines_for_topology_idle(firewall):
    """Release in-memory quarantine records when the lab topology is reset.

    This helper is intentionally state-only: when all switches are disconnected
    there are no active datapaths to program, so removing stale records here
    prevents old quarantine state from being re-applied on the next topology run.
    """

    if firewall is None:
        return []

    quarantined_hosts = getattr(firewall, "quarantined_hosts", None)
    if not quarantined_hosts:
        return []

    released_records = list(quarantined_hosts.values())
    quarantined_hosts.clear()
    return released_records


class MitigationService(object):
    """Apply indefinite quarantine rules and manual release operations."""

    def __init__(self, firewall, metrics, event_logger, default_block_seconds=None):
        self.firewall = firewall
        self.metrics = metrics
        self.event_logger = event_logger
        self.default_block_seconds = default_block_seconds

    def handle_alert(self, alert, datapaths, related_capture=None):
        """Convert one IDS alert into an indefinite quarantine action."""

        if alert is None or not alert.src_ip:
            return None

        detector = getattr(alert, "detector", "threshold")
        block_prefix = "ids" if detector == "threshold" else detector
        block_reason = "%s_%s" % (block_prefix, alert.alert_type)
        return self.quarantine_source_ip(
            src_ip=alert.src_ip,
            reason=block_reason,
            datapaths=datapaths,
            alert_type=alert.alert_type,
            source=detector,
            related_capture=related_capture,
        )

    def quarantine_source_ip(
        self,
        src_ip,
        reason,
        datapaths,
        alert_type=None,
        source=None,
        related_capture=None,
    ):
        """Install or confirm an indefinite quarantine through the firewall layer."""

        if not src_ip:
            return None

        current_record = self.firewall.quarantined_hosts.get(src_ip)
        block_record, changed = self.firewall.add_quarantine(
            src_ip=src_ip,
            reason=reason,
            datapaths=datapaths,
            detector=source,
            alert_type=alert_type,
            related_capture=related_capture,
        )
        if block_record is None:
            return None

        status = "created" if changed and current_record is None else "duplicate"
        self.metrics.record_quarantine(
            src_ip=block_record.src_ip,
            reason=block_record.reason,
            status=status,
            alert_type=alert_type,
            source=source,
            related_capture=block_record.related_capture,
        )
        return MitigationResult(
            src_ip=block_record.src_ip,
            reason=block_record.reason,
            status=status,
            alert_type=alert_type,
            detector=source,
            created_at=block_record.created_at,
            related_capture=block_record.related_capture,
        )

    def manual_unblock(self, src_ip, datapaths, released_by="dashboard"):
        """Remove an active quarantine only when requested by an analyst."""

        record, changed = self.firewall.remove_quarantine(
            src_ip=src_ip,
            datapaths=datapaths,
            released_by=released_by,
        )
        if record is None:
            return None

        self.metrics.record_manual_unblock(
            src_ip=record.src_ip,
            reason=record.reason,
            detector=record.detector,
            released_by=released_by,
            related_capture=record.related_capture,
        )
        return MitigationResult(
            src_ip=record.src_ip,
            reason=record.reason,
            status="released" if changed else "noop",
            alert_type=record.alert_type,
            detector=record.detector,
            created_at=record.created_at,
            related_capture=record.related_capture,
        )

    def expire_blocks(self):
        """Compatibility shim: indefinite quarantine means there are no expirations."""

        return []
