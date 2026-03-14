"""Parse per-run controller logs and dashboard snapshots into report-ready metrics."""

from __future__ import print_function

import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from statistics import mean


LOG_LINE_RE = re.compile(
    r"^(?:[^|]+\|\s+)?(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) \| "
    r"(?P<level>[A-Z]+) \| (?P<logger>[^|]+) \| (?P<message>.*)$"
)
KEY_VALUE_RE = re.compile(r"\b([a-zA-Z_]+)=([^\s]+)")
PING_RTT_RE = re.compile(
    r"rtt min/avg/max/mdev = [0-9.]+/(?P<avg>[0-9.]+)/[0-9.]+/[0-9.]+ ms"
)
HTTP_STATUS_RE = re.compile(r"HTTP/\d\.\d (?P<status>\d{3})")
HPING_RE = re.compile(
    r"(?P<tx>\d+) packets transmitted, (?P<rx>\d+) packets received, (?P<loss>[0-9]+)% packet loss"
)


def _parse_log_timestamp(value):
    naive = datetime.strptime(value, "%Y-%m-%d %H:%M:%S,%f")
    return naive.replace(tzinfo=timezone.utc).timestamp()


def _safe_delta(before_summary, after_summary, key):
    return float(after_summary.get(key, 0) or 0) - float(before_summary.get(key, 0) or 0)


def _safe_text(value):
    return "" if value is None else str(value)


def _mean_or_none(values):
    filtered = [value for value in values if value is not None]
    if not filtered:
        return None
    return mean(filtered)


def _parse_controller_log(log_text, source_ip):
    parsed = {
        "threshold_alert_times": [],
        "ml_alert_times": [],
        "hybrid_agreement_times": [],
        "hybrid_disagreement_times": [],
        "mitigation_times": [],
        "traffic_block_count": 0,
        "static_policy_block_times": [],
    }
    for raw_line in (log_text or "").splitlines():
        match = LOG_LINE_RE.match(raw_line.strip())
        if not match:
            continue
        timestamp = _parse_log_timestamp(match.group("timestamp"))
        message = match.group("message")
        fields = dict(KEY_VALUE_RE.findall(message))
        event_src_ip = fields.get("src_ip")

        if "event=security action=ids_alert" in message:
            if source_ip and event_src_ip and event_src_ip != source_ip:
                continue
            parsed["threshold_alert_times"].append(timestamp)
        elif "event=ml action=ml_alert" in message:
            if source_ip and event_src_ip and event_src_ip != source_ip:
                continue
            parsed["ml_alert_times"].append(timestamp)
        elif "event=ml action=hybrid_correlation" in message:
            status = fields.get("status", "")
            if source_ip and event_src_ip and event_src_ip != source_ip:
                continue
            if status == "agreement":
                parsed["hybrid_agreement_times"].append(timestamp)
            elif status == "disagreement":
                parsed["hybrid_disagreement_times"].append(timestamp)
        elif "action=temporary_block_added" in message or "action=ml_block_added" in message:
            if source_ip and event_src_ip and event_src_ip != source_ip:
                continue
            parsed["mitigation_times"].append(timestamp)
        elif "event=traffic action=block" in message:
            if source_ip and event_src_ip and event_src_ip != source_ip:
                continue
            parsed["traffic_block_count"] += 1
            reason = fields.get("reason", "")
            if reason.startswith("restricted_") or reason.startswith("static_"):
                parsed["static_policy_block_times"].append(timestamp)
        elif "event=flow action=flow_rule_installed" in message:
            reason = fields.get("reason", "")
            if reason.startswith("restricted_") or reason.startswith("static_"):
                parsed["static_policy_block_times"].append(timestamp)
    return parsed


def _parse_command_output(stdout_text):
    payload = {
        "ping_avg_rtt_ms": None,
        "http_status": "",
        "hping_transmitted": None,
        "hping_received": None,
        "hping_packet_loss_percent": None,
    }
    ping_match = PING_RTT_RE.search(stdout_text or "")
    if ping_match:
        payload["ping_avg_rtt_ms"] = float(ping_match.group("avg"))

    http_match = HTTP_STATUS_RE.search(stdout_text or "")
    if http_match:
        payload["http_status"] = http_match.group("status")

    hping_match = HPING_RE.search(stdout_text or "")
    if hping_match:
        payload["hping_transmitted"] = int(hping_match.group("tx"))
        payload["hping_received"] = int(hping_match.group("rx"))
        payload["hping_packet_loss_percent"] = int(hping_match.group("loss"))
    return payload


def extract_run_result(
    mode,
    scenario,
    repeat_index,
    start_epoch,
    end_epoch,
    before_payload,
    after_payload,
    controller_log_text,
    command_stdout,
    command_returncode,
    capture_metadata,
):
    before_summary = (before_payload or {}).get("summary", {})
    after_summary = (after_payload or {}).get("summary", {})
    parsed_log = _parse_controller_log(controller_log_text, scenario.source_ip)
    command_metrics = _parse_command_output(command_stdout)
    duration_seconds = max(0.001, float(end_epoch) - float(start_epoch))

    first_threshold = min(parsed_log["threshold_alert_times"] or [None])
    first_ml = min(parsed_log["ml_alert_times"] or [None])
    first_hybrid_agreement = min(parsed_log["hybrid_agreement_times"] or [None])
    detection_candidates = [
        value for value in (first_threshold, first_ml, first_hybrid_agreement) if value is not None
    ]
    first_detection = min(detection_candidates) if detection_candidates else None

    mitigation_candidates = [
        value
        for value in (
            min(parsed_log["mitigation_times"] or [None]),
            min(parsed_log["static_policy_block_times"] or [None]),
        )
        if value is not None
    ]
    first_mitigation = min(mitigation_candidates) if mitigation_candidates else None

    threshold_alerts = len(parsed_log["threshold_alert_times"])
    ml_alerts = len(parsed_log["ml_alert_times"])
    hybrid_agreements = len(parsed_log["hybrid_agreement_times"])
    hybrid_disagreements = len(parsed_log["hybrid_disagreement_times"])
    attack_detected = bool(threshold_alerts or ml_alerts or hybrid_agreements)
    mitigation_observed = bool(mitigation_candidates or parsed_log["traffic_block_count"])

    false_positive_estimate = int(scenario.label == "benign" and attack_detected)
    false_negative_estimate = int(scenario.label == "malicious" and not attack_detected)

    return {
        "mode": mode.name,
        "mode_title": mode.title,
        "scenario": scenario.name,
        "scenario_title": scenario.title,
        "scenario_label": scenario.label,
        "repeat": repeat_index,
        "start_epoch": start_epoch,
        "end_epoch": end_epoch,
        "duration_seconds": round(duration_seconds, 3),
        "attack_detected": attack_detected,
        "mitigation_observed": mitigation_observed,
        "attack_detection_time_seconds": (
            round(first_detection - start_epoch, 6) if first_detection is not None else None
        ),
        "mitigation_time_seconds": (
            round(first_mitigation - start_epoch, 6) if first_mitigation is not None else None
        ),
        "threshold_alert_count": threshold_alerts,
        "ml_alert_count": ml_alerts,
        "hybrid_agreement_count": hybrid_agreements,
        "hybrid_disagreement_count": hybrid_disagreements,
        "packet_drop_count_observed": parsed_log["traffic_block_count"],
        "packets_processed_delta": int(_safe_delta(before_summary, after_summary, "total_packets")),
        "bytes_processed_delta": int(_safe_delta(before_summary, after_summary, "total_bytes")),
        "alerts_total_delta": int(_safe_delta(before_summary, after_summary, "alerts_total")),
        "blocks_total_delta": int(_safe_delta(before_summary, after_summary, "blocks_total")),
        "flow_installs_delta": int(_safe_delta(before_summary, after_summary, "flow_installs_total")),
        "flow_removals_delta": int(_safe_delta(before_summary, after_summary, "flow_removals_total")),
        "controller_events_delta": int(
            _safe_delta(before_summary, after_summary, "controller_events_total")
        ),
        "active_blocks_after": int(after_summary.get("active_blocks", 0) or 0),
        "active_security_flows_after": int(
            after_summary.get("active_security_flows_total", 0) or 0
        ),
        "active_flows_after": int(after_summary.get("active_flows_total", 0) or 0),
        "packets_per_second_observed": round(
            _safe_delta(before_summary, after_summary, "total_packets") / duration_seconds,
            3,
        ),
        "bytes_per_second_observed": round(
            _safe_delta(before_summary, after_summary, "total_bytes") / duration_seconds,
            3,
        ),
        "false_positive_estimate": false_positive_estimate,
        "false_negative_estimate": false_negative_estimate,
        "ping_avg_rtt_ms": command_metrics["ping_avg_rtt_ms"],
        "http_status": command_metrics["http_status"],
        "hping_transmitted": command_metrics["hping_transmitted"],
        "hping_received": command_metrics["hping_received"],
        "hping_packet_loss_percent": command_metrics["hping_packet_loss_percent"],
        "command_returncode": command_returncode,
        "capture_session": _safe_text(capture_metadata.get("session_name")),
        "capture_file_count": int(capture_metadata.get("file_count", 0) or 0),
        "capture_total_size_bytes": int(capture_metadata.get("total_size_bytes", 0) or 0),
    }


def aggregate_results(run_rows):
    grouped = {}
    for row in run_rows:
        key = (row["mode"], row["scenario"])
        grouped.setdefault(key, []).append(row)

    summary_rows = []
    for key in sorted(grouped):
        rows = grouped[key]
        mode_name, scenario_name = key
        summary_rows.append(
            {
                "mode": mode_name,
                "scenario": scenario_name,
                "runs": len(rows),
                "attack_detection_time_mean_seconds": _mean_or_none(
                    [row["attack_detection_time_seconds"] for row in rows]
                ),
                "mitigation_time_mean_seconds": _mean_or_none(
                    [row["mitigation_time_seconds"] for row in rows]
                ),
                "packets_processed_mean": _mean_or_none(
                    [row["packets_processed_delta"] for row in rows]
                ),
                "packet_drop_count_mean": _mean_or_none(
                    [row["packet_drop_count_observed"] for row in rows]
                ),
                "flow_installs_mean": _mean_or_none(
                    [row["flow_installs_delta"] for row in rows]
                ),
                "flow_removals_mean": _mean_or_none(
                    [row["flow_removals_delta"] for row in rows]
                ),
                "controller_events_mean": _mean_or_none(
                    [row["controller_events_delta"] for row in rows]
                ),
                "bytes_per_second_mean": _mean_or_none(
                    [row["bytes_per_second_observed"] for row in rows]
                ),
                "ping_avg_rtt_mean_ms": _mean_or_none(
                    [row["ping_avg_rtt_ms"] for row in rows]
                ),
                "false_positive_rate": (
                    sum(row["false_positive_estimate"] for row in rows) / float(len(rows))
                ),
                "false_negative_rate": (
                    sum(row["false_negative_estimate"] for row in rows) / float(len(rows))
                ),
                "attack_detection_rate": (
                    sum(1 for row in rows if row["attack_detected"]) / float(len(rows))
                ),
                "mitigation_observation_rate": (
                    sum(1 for row in rows if row["mitigation_observed"]) / float(len(rows))
                ),
            }
        )
    return summary_rows


def write_json(path, payload):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def write_csv(path, rows):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        target.write_text("", encoding="utf-8")
        return

    fieldnames = sorted(rows[0].keys())
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

