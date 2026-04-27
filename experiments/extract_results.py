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
CONSENSUS_STATUSES = (
    "agreement",
    "threshold_plus_ml",
    "threshold_enriched_by_ml",
    "known_class_match",
)
DETECTION_RELEVANT_HYBRID_STATUSES = CONSENSUS_STATUSES + (
    "threshold_only",
    "ml_only",
    "anomaly_only",
)
HYBRID_STATUSES = DETECTION_RELEVANT_HYBRID_STATUSES + ("disagreement",)
MODE_SLOT_ALIASES = {
    "threshold": ("threshold_only", "threshold_ids", "dynamic_enforcement"),
    "classifier": ("classifier_only",),
    "anomaly": ("anomaly_only",),
    "hybrid": ("hybrid_blocking", "hybrid", "ml_enhanced_ids"),
}


def _parse_log_timestamp(value):
    naive = datetime.strptime(value, "%Y-%m-%d %H:%M:%S,%f")
    return naive.replace(tzinfo=timezone.utc).timestamp()


def _safe_delta(before_summary, after_summary, key):
    return float(after_summary.get(key, 0) or 0) - float(before_summary.get(key, 0) or 0)


def _safe_text(value):
    return "" if value is None else str(value)


def _safe_float(value):
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _mean_or_none(values):
    filtered = [value for value in values if value is not None]
    if not filtered:
        return None
    return mean(filtered)


def _ratio_or_none(numerator, denominator):
    if not denominator:
        return None
    return float(numerator) / float(denominator)


def _f1_or_none(precision, recall):
    if precision is None or recall is None:
        return None
    if precision + recall <= 0:
        return 0.0
    return 2.0 * precision * recall / (precision + recall)


def _distinct_text(rows, key):
    values = sorted({_safe_text(row.get(key)) for row in rows if _safe_text(row.get(key))})
    return ",".join(values)


def _latest_by_timestamp(rows, timestamp_key="timestamp"):
    if not rows:
        return {}
    return sorted(
        rows,
        key=lambda row: _safe_text(row.get(timestamp_key)),
        reverse=True,
    )[0]


def _extract_latest_prediction(after_payload, source_ip):
    predictions = list((after_payload or {}).get("recent_ml_predictions") or [])
    if source_ip:
        predictions = [
            row for row in predictions if _safe_text(row.get("src_ip")) == _safe_text(source_ip)
        ]
    return _latest_by_timestamp(predictions)


def _truthy_detection_target(rows, target):
    return [row for row in rows if _safe_text(row.get("expected_detection_target")) == target]


def _truthy_flag(rows, key):
    return [row for row in rows if bool(row.get(key))]


def _classification_counts(rows):
    malicious_rows = [row for row in rows if row.get("scenario_label") != "benign"]
    benign_rows = [row for row in rows if row.get("scenario_label") == "benign"]
    true_positive_count = sum(1 for row in malicious_rows if row.get("attack_detected"))
    false_negative_count = sum(1 for row in malicious_rows if not row.get("attack_detected"))
    false_positive_count = sum(1 for row in benign_rows if row.get("attack_detected"))
    true_negative_count = sum(1 for row in benign_rows if not row.get("attack_detected"))
    return {
        "malicious_rows": malicious_rows,
        "benign_rows": benign_rows,
        "true_positive_count": true_positive_count,
        "false_negative_count": false_negative_count,
        "false_positive_count": false_positive_count,
        "true_negative_count": true_negative_count,
    }


def _summarize_detection_metrics(rows):
    counts = _classification_counts(rows)
    precision = _ratio_or_none(
        counts["true_positive_count"],
        counts["true_positive_count"] + counts["false_positive_count"],
    )
    recall = _ratio_or_none(
        counts["true_positive_count"],
        counts["true_positive_count"] + counts["false_negative_count"],
    )
    false_positive_rate = _ratio_or_none(
        counts["false_positive_count"],
        counts["false_positive_count"] + counts["true_negative_count"],
    )
    return {
        "malicious_runs": len(counts["malicious_rows"]),
        "benign_runs": len(counts["benign_rows"]),
        "true_positive_count": counts["true_positive_count"],
        "false_negative_count": counts["false_negative_count"],
        "false_positive_count": counts["false_positive_count"],
        "true_negative_count": counts["true_negative_count"],
        "precision": precision,
        "recall": recall,
        "f1": _f1_or_none(precision, recall),
        "false_positive_rate": false_positive_rate,
    }


def _parse_controller_log(log_text, source_ip):
    parsed = {
        "threshold_alert_events": [],
        "threshold_alert_times": [],
        "ml_alert_events": [],
        "ml_alert_times": [],
        "hybrid_status_times": {status: [] for status in HYBRID_STATUSES},
        "mitigation_events": [],
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
            parsed["threshold_alert_events"].append(
                {
                    "timestamp": timestamp,
                    "alert_type": _safe_text(fields.get("alert_type")),
                    "reason": _safe_text(fields.get("reason")),
                    "severity": _safe_text(fields.get("severity")),
                }
            )
            parsed["threshold_alert_times"].append(timestamp)
        elif "event=ml action=ml_alert" in message:
            if source_ip and event_src_ip and event_src_ip != source_ip:
                continue
            parsed["ml_alert_events"].append(
                {
                    "timestamp": timestamp,
                    "decision": _safe_text(fields.get("decision")),
                    "reason": _safe_text(fields.get("reason")),
                    "label": _safe_text(fields.get("label")),
                    "confidence": _safe_float(fields.get("confidence")),
                    "suspicion_score": _safe_float(fields.get("suspicion_score")),
                    "quarantine_status": _safe_text(fields.get("quarantine_status")),
                    "correlation_status": _safe_text(fields.get("correlation_status")),
                    "predicted_family": _safe_text(fields.get("predicted_family")),
                    "classifier_confidence": _safe_float(fields.get("classifier_confidence")),
                    "anomaly_score": _safe_float(fields.get("anomaly_score")),
                    "threshold_reason": _safe_text(fields.get("threshold_reason")),
                    "repeated_window_count": int(
                        _safe_float(fields.get("repeated_window_count"))
                    ),
                    "block_decision_path": _safe_text(fields.get("block_decision_path")),
                    "final_block_reason": _safe_text(fields.get("final_block_reason")),
                }
            )
            parsed["ml_alert_times"].append(timestamp)
        elif "event=ml action=hybrid_correlation" in message:
            status = fields.get("status", "")
            if source_ip and event_src_ip and event_src_ip != source_ip:
                continue
            parsed["hybrid_status_times"].setdefault(status, []).append(timestamp)
        elif "event=security action=host_quarantined" in message:
            if source_ip and event_src_ip and event_src_ip != source_ip:
                continue
            parsed["mitigation_events"].append(
                {
                    "timestamp": timestamp,
                    "src_ip": _safe_text(event_src_ip),
                    "detector": _safe_text(fields.get("detector")),
                    "reason": _safe_text(fields.get("reason")),
                    "alert_type": _safe_text(fields.get("alert_type")),
                    "status": _safe_text(fields.get("status")),
                }
            )
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
    after_ml_status = (after_payload or {}).get("ml_status", {})
    parsed_log = _parse_controller_log(controller_log_text, scenario.source_ip)
    command_metrics = _parse_command_output(command_stdout)
    latest_prediction = _extract_latest_prediction(after_payload, scenario.source_ip)
    latest_ml_alert = _latest_by_timestamp(parsed_log["ml_alert_events"])
    latest_threshold_alert = _latest_by_timestamp(parsed_log["threshold_alert_events"])
    latest_mitigation = _latest_by_timestamp(parsed_log["mitigation_events"])
    duration_seconds = max(0.001, float(end_epoch) - float(start_epoch))

    first_threshold = min(parsed_log["threshold_alert_times"] or [None])
    first_ml = min(parsed_log["ml_alert_times"] or [None])
    first_hybrid_signal = min(
        [
            timestamp
            for status in DETECTION_RELEVANT_HYBRID_STATUSES
            for timestamp in parsed_log["hybrid_status_times"].get(status, [])
        ]
        or [None]
    )
    detection_candidates = [
        value for value in (first_threshold, first_ml, first_hybrid_signal) if value is not None
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
    hybrid_agreements = len(parsed_log["hybrid_status_times"].get("agreement", []))
    hybrid_consensus_count = sum(
        len(parsed_log["hybrid_status_times"].get(status, []))
        for status in CONSENSUS_STATUSES
    )
    hybrid_disagreements = len(parsed_log["hybrid_status_times"].get("disagreement", []))
    threshold_only_correlations = len(parsed_log["hybrid_status_times"].get("threshold_only", []))
    ml_only_correlations = len(parsed_log["hybrid_status_times"].get("ml_only", []))
    anomaly_only_correlations = len(parsed_log["hybrid_status_times"].get("anomaly_only", []))
    threshold_plus_ml = len(parsed_log["hybrid_status_times"].get("threshold_plus_ml", []))
    threshold_enriched_by_ml = len(
        parsed_log["hybrid_status_times"].get("threshold_enriched_by_ml", [])
    )
    known_class_match = len(parsed_log["hybrid_status_times"].get("known_class_match", []))
    effective_runtime_mode = _safe_text(after_ml_status.get("effective_mode_api"))
    selected_runtime_mode = _safe_text(after_ml_status.get("selected_mode_api"))
    configured_runtime_mode = _safe_text(after_ml_status.get("configured_mode_api"))
    hybrid_detection_signal = bool(
        hybrid_consensus_count
        or threshold_only_correlations
        or ml_only_correlations
        or anomaly_only_correlations
    )
    attack_detected = bool(
        threshold_alerts
        or ml_alerts
        or (
            effective_runtime_mode == "hybrid"
            and hybrid_detection_signal
        )
    )
    mitigation_observed = bool(mitigation_candidates or parsed_log["traffic_block_count"])

    false_positive_estimate = int(scenario.label == "benign" and attack_detected)
    false_negative_estimate = int(scenario.label == "malicious" and not attack_detected)

    return {
        "mode": mode.name,
        "mode_title": mode.title,
        "scenario": scenario.name,
        "scenario_title": scenario.title,
        "scenario_label": scenario.label,
        "scenario_source_ip": scenario.source_ip,
        "scenario_family": _safe_text(getattr(scenario, "scenario_family", "")),
        "expected_detection_target": _safe_text(
            getattr(scenario, "expected_detection_target", "")
        ),
        "threshold_evasive": bool(getattr(scenario, "threshold_evasive", False)),
        "known_family": bool(getattr(scenario, "known_family", False)),
        "blended_with_benign": bool(getattr(scenario, "blended_with_benign", False)),
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
        "hybrid_consensus_count": hybrid_consensus_count,
        "hybrid_disagreement_count": hybrid_disagreements,
        "threshold_plus_ml_count": threshold_plus_ml,
        "threshold_enriched_by_ml_count": threshold_enriched_by_ml,
        "known_class_match_count": known_class_match,
        "threshold_only_correlation_count": threshold_only_correlations,
        "ml_only_correlation_count": ml_only_correlations,
        "anomaly_only_correlation_count": anomaly_only_correlations,
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
        "configured_runtime_mode": configured_runtime_mode,
        "selected_runtime_mode": selected_runtime_mode,
        "effective_runtime_mode": effective_runtime_mode,
        "configured_inference_mode": _safe_text(after_ml_status.get("inference_mode")),
        "effective_inference_mode": _safe_text(after_ml_status.get("effective_inference_mode")),
        "supervised_model_available": bool(after_ml_status.get("model_available", False)),
        "anomaly_model_available": bool(after_ml_status.get("anomaly_model_available", False)),
        "latest_threshold_alert_type": _safe_text(latest_threshold_alert.get("alert_type")),
        "latest_threshold_reason": _safe_text(latest_threshold_alert.get("reason")),
        "latest_ml_alert_decision": _safe_text(latest_ml_alert.get("decision")),
        "latest_ml_alert_reason": _safe_text(latest_ml_alert.get("reason")),
        "latest_ml_alert_label": _safe_text(latest_ml_alert.get("label")),
        "latest_ml_alert_correlation_status": _safe_text(
            latest_ml_alert.get("correlation_status")
        ),
        "latest_ml_alert_predicted_family": _safe_text(
            latest_ml_alert.get("predicted_family")
        ),
        "latest_ml_alert_classifier_confidence": _safe_float(
            latest_ml_alert.get("classifier_confidence")
        ),
        "latest_ml_alert_anomaly_score": _safe_float(latest_ml_alert.get("anomaly_score")),
        "latest_ml_alert_threshold_reason": _safe_text(
            latest_ml_alert.get("threshold_reason")
        ),
        "latest_ml_alert_repeated_window_count": int(
            latest_ml_alert.get("repeated_window_count", 0) or 0
        ),
        "latest_ml_alert_block_decision_path": _safe_text(
            latest_ml_alert.get("block_decision_path")
        ),
        "latest_ml_alert_final_block_reason": _safe_text(
            latest_ml_alert.get("final_block_reason")
        ),
        "mitigation_src_ip": _safe_text(latest_mitigation.get("src_ip")),
        "mitigation_detector": _safe_text(latest_mitigation.get("detector")),
        "mitigation_reason": _safe_text(latest_mitigation.get("reason")),
        "prediction_label": _safe_text(latest_prediction.get("label")),
        "prediction_reason": _safe_text(latest_prediction.get("reason")),
        "prediction_confidence": _safe_float(latest_prediction.get("confidence")),
        "prediction_anomaly_score": _safe_float(latest_prediction.get("anomaly_score")),
        "prediction_is_anomalous": (
            bool(latest_prediction.get("is_anomalous"))
            if latest_prediction
            else None
        ),
        "predicted_family": _safe_text(latest_prediction.get("predicted_family")),
        "prediction_summary": _safe_text(latest_prediction.get("explanation_summary")),
        "capture_session": _safe_text(capture_metadata.get("session_name")),
        "capture_file_count": int(capture_metadata.get("file_count", 0) or 0),
        "capture_total_size_bytes": int(capture_metadata.get("total_size_bytes", 0) or 0),
    }


def _select_mode_slot_rows(rows, slot_name):
    for mode_name in MODE_SLOT_ALIASES[slot_name]:
        mode_rows = [row for row in rows if row.get("mode") == mode_name]
        if mode_rows:
            return mode_name, mode_rows
    return "", []


def _representative_row(rows):
    if not rows:
        return {}

    def _sort_key(row):
        return (
            1 if row.get("mitigation_observed") else 0,
            1 if row.get("attack_detected") else 0,
            _safe_float(row.get("prediction_confidence")) or 0.0,
            _safe_float(row.get("prediction_anomaly_score")) or 0.0,
            int(row.get("repeat", 0) or 0),
        )

    return sorted(rows, key=_sort_key, reverse=True)[0]


def _derive_hybrid_run_outcome(row):
    if not row:
        return {"decision": "", "reason": ""}

    if row.get("mitigation_observed") and int(row.get("threshold_alert_count", 0) or 0) > 0:
        if int(row.get("threshold_plus_ml_count", 0) or 0) > 0 or int(
            row.get("known_class_match_count", 0) or 0
        ) > 0:
            decision = "threshold_block_with_ml_consensus"
        elif int(row.get("threshold_enriched_by_ml_count", 0) or 0) > 0:
            decision = "threshold_block_with_ml_enrichment"
        else:
            decision = "threshold_block"
        return {
            "decision": decision,
            "reason": _safe_text(row.get("latest_threshold_reason")),
        }

    ml_decision = _safe_text(row.get("latest_ml_alert_decision"))
    if ml_decision:
        return {
            "decision": ml_decision,
            "reason": _safe_text(row.get("latest_ml_alert_final_block_reason"))
            or _safe_text(row.get("latest_ml_alert_reason")),
        }

    if row.get("mitigation_observed") and int(row.get("ml_alert_count", 0) or 0) > 0:
        return {
            "decision": "hybrid_ml_block",
            "reason": _safe_text(row.get("latest_ml_alert_reason")),
        }

    if row.get("attack_detected") and int(row.get("anomaly_only_correlation_count", 0) or 0) > 0:
        return {
            "decision": "anomaly_only_alert",
            "reason": _safe_text(row.get("latest_ml_alert_reason")) or "anomaly_score_above_threshold",
        }

    if row.get("attack_detected") and int(row.get("ml_only_correlation_count", 0) or 0) > 0:
        return {
            "decision": "ml_only_alert",
            "reason": _safe_text(row.get("latest_ml_alert_reason")) or _safe_text(row.get("prediction_reason")),
        }

    return {"decision": "", "reason": ""}


def _derive_ml_added_value(row):
    if not row.get("hybrid_detected"):
        return "none"
    if row.get("hybrid_final_decision") == "anomaly_only_alert" and not row.get("threshold_detected"):
        return "anomaly_alert_on_threshold_miss"
    if row.get("hybrid_blocked") and row.get("hybrid_block_detector") == "ml":
        return "hybrid_ml_assisted_block"
    if row.get("hybrid_blocked") and row.get("hybrid_block_detector") == "threshold":
        if (row.get("hybrid_threshold_plus_ml_count", 0) or 0) > 0 or (
            row.get("hybrid_threshold_enriched_by_ml_count", 0) or 0
        ) > 0:
            return "threshold_owned_block_with_ml_enrichment"
    if not row.get("threshold_detected") and row.get("hybrid_detected"):
        if row.get("anomaly_detected"):
            return "anomaly_alert_on_threshold_miss"
        if row.get("classifier_detected"):
            return "classifier_alert_on_threshold_miss"
    return "none"


def build_scenario_comparison(run_rows):
    grouped = {}
    for row in run_rows:
        grouped.setdefault(row["scenario"], []).append(row)

    comparison_rows = []
    for scenario_name in sorted(grouped):
        rows = grouped[scenario_name]
        threshold_mode, threshold_rows = _select_mode_slot_rows(rows, "threshold")
        classifier_mode, classifier_rows = _select_mode_slot_rows(rows, "classifier")
        anomaly_mode, anomaly_rows = _select_mode_slot_rows(rows, "anomaly")
        hybrid_mode, hybrid_rows = _select_mode_slot_rows(rows, "hybrid")

        threshold_rep = _representative_row(threshold_rows)
        classifier_rep = _representative_row(classifier_rows)
        anomaly_rep = _representative_row(anomaly_rows)
        hybrid_rep = _representative_row(hybrid_rows)
        hybrid_outcome = _derive_hybrid_run_outcome(hybrid_rep)

        comparison_row = {
            "scenario": scenario_name,
            "scenario_family": _safe_text(rows[0].get("scenario_family")),
            "expected_detection_target": _safe_text(rows[0].get("expected_detection_target")),
            "threshold_mode": threshold_mode,
            "classifier_mode": classifier_mode,
            "anomaly_mode": anomaly_mode,
            "hybrid_mode": hybrid_mode,
            "threshold_detected": bool(
                threshold_rows and any(row.get("attack_detected") for row in threshold_rows)
            ),
            "classifier_detected": bool(
                classifier_rows and any(row.get("attack_detected") for row in classifier_rows)
            ),
            "anomaly_detected": bool(
                anomaly_rows and any(row.get("attack_detected") for row in anomaly_rows)
            ),
            "hybrid_detected": bool(
                hybrid_rows and any(row.get("attack_detected") for row in hybrid_rows)
            ),
            "hybrid_blocked": bool(
                hybrid_rows and any(row.get("mitigation_observed") for row in hybrid_rows)
            ),
            "threshold_detection_rate": _ratio_or_none(
                sum(1 for row in threshold_rows if row.get("attack_detected")),
                len(threshold_rows),
            ),
            "classifier_detection_rate": _ratio_or_none(
                sum(1 for row in classifier_rows if row.get("attack_detected")),
                len(classifier_rows),
            ),
            "anomaly_detection_rate": _ratio_or_none(
                sum(1 for row in anomaly_rows if row.get("attack_detected")),
                len(anomaly_rows),
            ),
            "hybrid_detection_rate": _ratio_or_none(
                sum(1 for row in hybrid_rows if row.get("attack_detected")),
                len(hybrid_rows),
            ),
            "hybrid_block_rate": _ratio_or_none(
                sum(1 for row in hybrid_rows if row.get("mitigation_observed")),
                len(hybrid_rows),
            ),
            "hybrid_blocked_host": (
                _distinct_text(hybrid_rows, "mitigation_src_ip")
                or (
                    _safe_text(hybrid_rep.get("scenario_source_ip"))
                    if any(row.get("mitigation_observed") for row in hybrid_rows)
                    else ""
                )
            ),
            "hybrid_block_detector": (
                _distinct_text(hybrid_rows, "mitigation_detector")
                or (
                    "ml"
                    if _safe_text(hybrid_outcome.get("decision")) == "hybrid_ml_block"
                    else (
                        "threshold"
                        if any(row.get("mitigation_observed") for row in hybrid_rows)
                        and any(int(row.get("threshold_alert_count", 0) or 0) > 0 for row in hybrid_rows)
                        else ""
                    )
                )
            ),
            "hybrid_final_decision": _safe_text(hybrid_outcome.get("decision")),
            "hybrid_reason": _safe_text(hybrid_outcome.get("reason")),
            "hybrid_correlation_status": _safe_text(
                hybrid_rep.get("latest_ml_alert_correlation_status")
            ),
            "hybrid_threshold_reason": _safe_text(
                hybrid_rep.get("latest_ml_alert_threshold_reason")
            )
            or _safe_text(hybrid_rep.get("latest_threshold_reason")),
            "hybrid_classifier_confidence": (
                round(float(hybrid_rep["latest_ml_alert_classifier_confidence"]), 6)
                if hybrid_rep.get("latest_ml_alert_classifier_confidence") is not None
                else ""
            ),
            "hybrid_latest_anomaly_score": (
                round(float(hybrid_rep["latest_ml_alert_anomaly_score"]), 6)
                if hybrid_rep.get("latest_ml_alert_anomaly_score") is not None
                else ""
            ),
            "hybrid_repeated_window_count": int(
                hybrid_rep.get("latest_ml_alert_repeated_window_count", 0) or 0
            ),
            "hybrid_block_decision_path": _safe_text(
                hybrid_rep.get("latest_ml_alert_block_decision_path")
            ),
            "hybrid_threshold_alert_count": sum(
                int(row.get("threshold_alert_count", 0) or 0) for row in hybrid_rows
            ),
            "hybrid_ml_alert_count": sum(
                int(row.get("ml_alert_count", 0) or 0) for row in hybrid_rows
            ),
            "hybrid_consensus_count": sum(
                int(row.get("hybrid_consensus_count", 0) or 0) for row in hybrid_rows
            ),
            "hybrid_threshold_plus_ml_count": sum(
                int(row.get("threshold_plus_ml_count", 0) or 0) for row in hybrid_rows
            ),
            "hybrid_threshold_enriched_by_ml_count": sum(
                int(row.get("threshold_enriched_by_ml_count", 0) or 0)
                for row in hybrid_rows
            ),
            "hybrid_anomaly_only_count": sum(
                int(row.get("anomaly_only_correlation_count", 0) or 0) for row in hybrid_rows
            ),
            "predicted_family": _safe_text(hybrid_rep.get("predicted_family")),
            "prediction_label": _safe_text(hybrid_rep.get("prediction_label")),
            "prediction_reason": _safe_text(hybrid_rep.get("prediction_reason")),
            "prediction_confidence": (
                round(float(hybrid_rep["prediction_confidence"]), 6)
                if hybrid_rep.get("prediction_confidence") is not None
                else ""
            ),
            "prediction_anomaly_score": (
                round(float(hybrid_rep["prediction_anomaly_score"]), 6)
                if hybrid_rep.get("prediction_anomaly_score") is not None
                else ""
            ),
            "prediction_is_anomalous": (
                bool(hybrid_rep.get("prediction_is_anomalous"))
                if hybrid_rep.get("prediction_is_anomalous") is not None
                else ""
            ),
            "prediction_summary": _safe_text(hybrid_rep.get("prediction_summary")),
        }
        comparison_row["ml_added_value"] = _derive_ml_added_value(comparison_row)
        comparison_rows.append(comparison_row)
    return comparison_rows


def aggregate_results(run_rows):
    grouped = {}
    for row in run_rows:
        key = (row["mode"], row["scenario"])
        grouped.setdefault(key, []).append(row)

    summary_rows = []
    for key in sorted(grouped):
        rows = grouped[key]
        mode_name, scenario_name = key
        detection_metrics = _summarize_detection_metrics(rows)
        summary_rows.append(
            {
                "mode": mode_name,
                "scenario": scenario_name,
                "mode_title": _safe_text(rows[0].get("mode_title")),
                "scenario_title": _safe_text(rows[0].get("scenario_title")),
                "scenario_family": _safe_text(rows[0].get("scenario_family")),
                "expected_detection_target": _safe_text(
                    rows[0].get("expected_detection_target")
                ),
                "threshold_evasive": bool(rows[0].get("threshold_evasive")),
                "known_family": bool(rows[0].get("known_family")),
                "blended_with_benign": bool(rows[0].get("blended_with_benign")),
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
                "precision": detection_metrics["precision"],
                "recall": detection_metrics["recall"],
                "f1": detection_metrics["f1"],
                "attack_detection_rate": (
                    sum(1 for row in rows if row["attack_detected"]) / float(len(rows))
                ),
                "mitigation_observation_rate": (
                    sum(1 for row in rows if row["mitigation_observed"]) / float(len(rows))
                ),
                "hybrid_consensus_rate": _ratio_or_none(
                    sum(1 for row in rows if row["hybrid_consensus_count"] > 0),
                    len(rows),
                ),
                "threshold_plus_ml_rate": _ratio_or_none(
                    sum(1 for row in rows if row["threshold_plus_ml_count"] > 0),
                    len(rows),
                ),
                "anomaly_only_rate": _ratio_or_none(
                    sum(1 for row in rows if row["anomaly_only_correlation_count"] > 0),
                    len(rows),
                ),
                "effective_runtime_modes": _distinct_text(rows, "effective_runtime_mode"),
                "effective_inference_modes": _distinct_text(rows, "effective_inference_mode"),
            }
        )
    return summary_rows


def build_mode_comparison(run_rows):
    grouped = {}
    for row in run_rows:
        grouped.setdefault(row["mode"], []).append(row)

    comparison_rows = []
    for mode_name in sorted(grouped):
        rows = grouped[mode_name]
        detection_metrics = _summarize_detection_metrics(rows)
        comparison_rows.append(
            {
                "mode": mode_name,
                "mode_title": _safe_text(rows[0].get("mode_title")),
                "runs": len(rows),
                "scenario_family_count": len(
                    {row["scenario_family"] for row in rows if _safe_text(row.get("scenario_family"))}
                ),
                "attack_detection_rate": _ratio_or_none(
                    sum(1 for row in rows if row["attack_detected"]),
                    len(rows),
                ),
                "mitigation_observation_rate": _ratio_or_none(
                    sum(1 for row in rows if row["mitigation_observed"]),
                    len(rows),
                ),
                "precision": detection_metrics["precision"],
                "recall": detection_metrics["recall"],
                "f1": detection_metrics["f1"],
                "false_positive_rate": detection_metrics["false_positive_rate"],
                "malicious_runs": detection_metrics["malicious_runs"],
                "benign_runs": detection_metrics["benign_runs"],
                "true_positive_count": detection_metrics["true_positive_count"],
                "false_negative_count": detection_metrics["false_negative_count"],
                "false_positive_count": detection_metrics["false_positive_count"],
                "true_negative_count": detection_metrics["true_negative_count"],
                "threshold_target_detection_rate": _ratio_or_none(
                    sum(1 for row in _truthy_detection_target(rows, "threshold") if row["attack_detected"]),
                    len(_truthy_detection_target(rows, "threshold")),
                ),
                "classifier_target_detection_rate": _ratio_or_none(
                    sum(1 for row in _truthy_detection_target(rows, "classifier") if row["attack_detected"]),
                    len(_truthy_detection_target(rows, "classifier")),
                ),
                "anomaly_target_detection_rate": _ratio_or_none(
                    sum(1 for row in _truthy_detection_target(rows, "anomaly") if row["attack_detected"]),
                    len(_truthy_detection_target(rows, "anomaly")),
                ),
                "hybrid_target_detection_rate": _ratio_or_none(
                    sum(1 for row in _truthy_detection_target(rows, "hybrid") if row["attack_detected"]),
                    len(_truthy_detection_target(rows, "hybrid")),
                ),
                "threshold_evasive_detection_rate": _ratio_or_none(
                    sum(1 for row in _truthy_flag(rows, "threshold_evasive") if row["attack_detected"]),
                    len(_truthy_flag(rows, "threshold_evasive")),
                ),
                "hybrid_consensus_frequency": _ratio_or_none(
                    sum(1 for row in rows if row["hybrid_consensus_count"] > 0),
                    len(rows),
                ),
                "threshold_plus_ml_frequency": _ratio_or_none(
                    sum(1 for row in rows if row["threshold_plus_ml_count"] > 0),
                    len(rows),
                ),
                "threshold_enriched_by_ml_frequency": _ratio_or_none(
                    sum(1 for row in rows if row["threshold_enriched_by_ml_count"] > 0),
                    len(rows),
                ),
                "known_class_match_frequency": _ratio_or_none(
                    sum(1 for row in rows if row["known_class_match_count"] > 0),
                    len(rows),
                ),
                "threshold_only_frequency": _ratio_or_none(
                    sum(1 for row in rows if row["threshold_only_correlation_count"] > 0),
                    len(rows),
                ),
                "ml_only_frequency": _ratio_or_none(
                    sum(1 for row in rows if row["ml_only_correlation_count"] > 0),
                    len(rows),
                ),
                "anomaly_only_frequency": _ratio_or_none(
                    sum(1 for row in rows if row["anomaly_only_correlation_count"] > 0),
                    len(rows),
                ),
                "effective_runtime_modes": _distinct_text(rows, "effective_runtime_mode"),
                "effective_inference_modes": _distinct_text(rows, "effective_inference_mode"),
            }
        )
    return comparison_rows


def build_family_summary(run_rows):
    grouped = {}
    for row in run_rows:
        scenario_family = _safe_text(row.get("scenario_family"))
        if not scenario_family:
            continue
        key = (row["mode"], scenario_family)
        grouped.setdefault(key, []).append(row)

    family_rows = []
    for key in sorted(grouped):
        rows = grouped[key]
        mode_name, scenario_family = key
        detection_metrics = _summarize_detection_metrics(rows)
        family_rows.append(
            {
                "mode": mode_name,
                "mode_title": _safe_text(rows[0].get("mode_title")),
                "scenario_family": scenario_family,
                "runs": len(rows),
                "expected_detection_target": _safe_text(
                    rows[0].get("expected_detection_target")
                ),
                "threshold_evasive": bool(rows[0].get("threshold_evasive")),
                "known_family": bool(rows[0].get("known_family")),
                "blended_with_benign": bool(rows[0].get("blended_with_benign")),
                "attack_detection_rate": _ratio_or_none(
                    sum(1 for row in rows if row["attack_detected"]),
                    len(rows),
                ),
                "precision": detection_metrics["precision"],
                "recall": detection_metrics["recall"],
                "f1": detection_metrics["f1"],
                "false_positive_rate": detection_metrics["false_positive_rate"],
                "hybrid_consensus_frequency": _ratio_or_none(
                    sum(1 for row in rows if row["hybrid_consensus_count"] > 0),
                    len(rows),
                ),
                "anomaly_only_frequency": _ratio_or_none(
                    sum(1 for row in rows if row["anomaly_only_correlation_count"] > 0),
                    len(rows),
                ),
            }
        )
    return family_rows


def build_intent_summary(run_rows):
    grouped = {}
    for row in run_rows:
        intents = []
        target = _safe_text(row.get("expected_detection_target"))
        if target:
            intents.append("%s_target" % target)
        if row.get("threshold_evasive"):
            intents.append("threshold_evasive")
        if row.get("blended_with_benign"):
            intents.append("blended_with_benign")
        for intent_name in intents:
            grouped.setdefault((row["mode"], intent_name), []).append(row)

    intent_rows = []
    for key in sorted(grouped):
        rows = grouped[key]
        mode_name, intent_name = key
        detection_metrics = _summarize_detection_metrics(rows)
        intent_rows.append(
            {
                "mode": mode_name,
                "mode_title": _safe_text(rows[0].get("mode_title")),
                "intent_name": intent_name,
                "runs": len(rows),
                "attack_detection_rate": _ratio_or_none(
                    sum(1 for row in rows if row["attack_detected"]),
                    len(rows),
                ),
                "precision": detection_metrics["precision"],
                "recall": detection_metrics["recall"],
                "f1": detection_metrics["f1"],
                "false_positive_rate": detection_metrics["false_positive_rate"],
                "hybrid_consensus_frequency": _ratio_or_none(
                    sum(1 for row in rows if row["hybrid_consensus_count"] > 0),
                    len(rows),
                ),
                "anomaly_only_frequency": _ratio_or_none(
                    sum(1 for row in rows if row["anomaly_only_correlation_count"] > 0),
                    len(rows),
                ),
            }
        )
    return intent_rows


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
