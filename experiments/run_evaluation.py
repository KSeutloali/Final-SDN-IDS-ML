#!/usr/bin/env python3
"""Run repeatable SDN evaluation scenarios and export JSON/CSV results."""

from __future__ import print_function

import argparse
from pathlib import Path
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experiments.common import (
    capture_session_details,
    compose,
    controller_logs_since,
    dashboard_state,
    default_modes,
    default_scenarios,
    ensure_topology_running,
    isoformat_utc,
    project_root,
    recreate_controller,
    results_root,
    run_on_host,
    start_capture_session,
    stop_capture_session,
    warmup_scenario_connectivity,
    utc_slug,
    write_json,
)
from experiments.extract_results import (
    aggregate_results,
    build_family_summary,
    build_intent_summary,
    build_mode_comparison,
    build_scenario_comparison,
    extract_run_result,
    write_csv,
    write_json as write_result_json,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run report-ready SDN comparison experiments against the current lab.",
    )
    parser.add_argument(
        "--results-dir",
        default=None,
        help="Target results directory. Defaults to experiments/results/evaluation_<timestamp>.",
    )
    parser.add_argument(
        "--modes",
        default="dynamic_enforcement,static_firewall,threshold_ids,ml_enhanced_ids",
        help="Comma-separated mode list.",
    )
    parser.add_argument(
        "--scenarios",
        default="benign,port_scan,dos",
        help="Comma-separated scenario list.",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=2,
        help="Repeat count per mode/scenario combination.",
    )
    parser.add_argument(
        "--settle-seconds",
        type=float,
        default=3.0,
        help="Pause after each scenario before metrics are collected.",
    )
    parser.add_argument(
        "--controller-ready-timeout",
        type=float,
        default=25.0,
        help="Seconds to wait for the recreated controller to reconnect to the lab.",
    )
    parser.add_argument(
        "--flood-count",
        type=int,
        default=1200,
        help="Packet count for the DoS scenario.",
    )
    parser.add_argument(
        "--hping-interval-usec",
        type=int,
        default=1000,
        help="Microsecond interval for the DoS scenario.",
    )
    parser.add_argument(
        "--capture-interfaces",
        default="",
        help="Optional comma-separated capture interface override.",
    )
    parser.add_argument(
        "--no-captures",
        action="store_true",
        help="Skip packet capture start/stop during the evaluation runs.",
    )
    parser.add_argument(
        "--ml-model-path",
        default="models/live_smoke_collection_model.joblib",
        help="Runtime model path used for the ML-enhanced comparison mode.",
    )
    parser.add_argument(
        "--anomaly-model-path",
        default="",
        help="Optional anomaly model path used by anomaly-only and combined hybrid comparison modes.",
    )
    parser.add_argument(
        "--no-restore-controller",
        action="store_true",
        help="Leave the controller in the last evaluation mode instead of restoring defaults.",
    )
    return parser.parse_args()


def _select(mapping, names, label):
    selected = []
    for name in [item.strip() for item in names.split(",") if item.strip()]:
        if name not in mapping:
            raise SystemExit("Unknown %s: %s" % (label, name))
        selected.append(mapping[name])
    return selected


def _run_one_scenario(
    mode,
    scenario,
    repeat_index,
    args,
    run_dir,
):
    recreate_controller(mode, timeout_seconds=args.controller_ready_timeout)
    warmup_scenario_connectivity(
        scenario,
        timeout_seconds=max(5.0, min(args.controller_ready_timeout, 15.0)),
    )
    before_payload = dashboard_state()
    start_epoch = time.time()
    start_iso = isoformat_utc(start_epoch)

    capture_info = {"session_name": "", "files": [], "status": "inactive"}
    started_capture = None
    if not args.no_captures:
        started_capture = start_capture_session(
            scenario.name,
            capture_interfaces=(args.capture_interfaces or None),
        )

    command_result = run_on_host(
        scenario.host,
        scenario.command,
        capture_output=True,
        check=not scenario.allow_nonzero,
    )
    command_stdout = command_result.stdout or ""

    time.sleep(args.settle_seconds)

    if started_capture is not None:
        stopped_capture = stop_capture_session(started_capture["session_name"])
        capture_info = capture_session_details(stopped_capture["session_name"])

    end_epoch = time.time()
    end_iso = isoformat_utc(end_epoch)
    after_payload = dashboard_state()
    controller_log_text = controller_logs_since(start_iso, end_iso)

    result = extract_run_result(
        mode=mode,
        scenario=scenario,
        repeat_index=repeat_index,
        start_epoch=start_epoch,
        end_epoch=end_epoch,
        before_payload=before_payload,
        after_payload=after_payload,
        controller_log_text=controller_log_text,
        command_stdout=command_stdout,
        command_returncode=command_result.returncode,
        capture_metadata=capture_info,
    )

    write_json(run_dir / "before_state.json", before_payload)
    write_json(run_dir / "after_state.json", after_payload)
    write_json(run_dir / "capture.json", capture_info)
    (run_dir / "command.stdout.txt").write_text(command_stdout, encoding="utf-8")
    (run_dir / "controller.log").write_text(controller_log_text, encoding="utf-8")
    write_json(run_dir / "result.json", result)
    return result


def main():
    args = parse_args()
    ensure_topology_running()

    root_dir = (
        Path(args.results_dir).resolve()
        if args.results_dir
        else results_root("evaluation_%s" % utc_slug()).resolve()
    )
    root_dir.mkdir(parents=True, exist_ok=True)

    modes = default_modes(args.ml_model_path, args.anomaly_model_path)
    scenarios = default_scenarios(
        flood_count=args.flood_count,
        hping_interval_usec=args.hping_interval_usec,
    )
    selected_modes = _select(modes, args.modes, "mode")
    selected_scenarios = _select(scenarios, args.scenarios, "scenario")

    manifest = {
        "generated_at": isoformat_utc(),
        "results_dir": str(root_dir.relative_to(project_root())),
        "modes": [mode.to_dict() for mode in selected_modes],
        "scenarios": [scenario.to_dict() for scenario in selected_scenarios],
        "repeats": args.repeats,
        "settle_seconds": args.settle_seconds,
        "capture_interfaces": args.capture_interfaces or "",
        "captures_enabled": not args.no_captures,
    }
    write_json(root_dir / "manifest.json", manifest)

    run_rows = []
    try:
        for mode in selected_modes:
            for scenario in selected_scenarios:
                for repeat_index in range(1, max(1, args.repeats) + 1):
                    run_slug = "%s__%s__r%s" % (
                        mode.name,
                        scenario.name,
                        repeat_index,
                    )
                    run_dir = root_dir / "runs" / run_slug
                    run_dir.mkdir(parents=True, exist_ok=True)
                    result = _run_one_scenario(
                        mode=mode,
                        scenario=scenario,
                        repeat_index=repeat_index,
                        args=args,
                        run_dir=run_dir,
                    )
                    run_rows.append(result)

        summary_rows = aggregate_results(run_rows)
        mode_comparison_rows = build_mode_comparison(run_rows)
        family_summary_rows = build_family_summary(run_rows)
        intent_summary_rows = build_intent_summary(run_rows)
        scenario_comparison_rows = build_scenario_comparison(run_rows)
        write_result_json(root_dir / "per_run.json", run_rows)
        write_csv(root_dir / "per_run.csv", run_rows)
        write_result_json(root_dir / "summary.json", summary_rows)
        write_csv(root_dir / "summary.csv", summary_rows)
        write_result_json(root_dir / "mode_comparison.json", mode_comparison_rows)
        write_csv(root_dir / "mode_comparison.csv", mode_comparison_rows)
        write_result_json(root_dir / "family_summary.json", family_summary_rows)
        write_csv(root_dir / "family_summary.csv", family_summary_rows)
        write_result_json(root_dir / "intent_summary.json", intent_summary_rows)
        write_csv(root_dir / "intent_summary.csv", intent_summary_rows)
        write_result_json(root_dir / "scenario_comparison.json", scenario_comparison_rows)
        write_csv(root_dir / "scenario_comparison.csv", scenario_comparison_rows)

        print("Evaluation results written to %s" % root_dir)
        print("Per-run CSV: %s" % (root_dir / "per_run.csv"))
        print("Summary CSV: %s" % (root_dir / "summary.csv"))
        print("Mode comparison CSV: %s" % (root_dir / "mode_comparison.csv"))
        print("Scenario comparison CSV: %s" % (root_dir / "scenario_comparison.csv"))
    finally:
        if not args.no_restore_controller:
            compose(["up", "-d", "--force-recreate", "controller"], check=False)


if __name__ == "__main__":
    main()
