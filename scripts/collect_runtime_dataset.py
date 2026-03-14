#!/usr/bin/env python3
"""Collect a larger live-compatible ML dataset from the running SDN lab."""

from __future__ import print_function

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@dataclass(frozen=True)
class Scenario(object):
    label: str
    scenario: str
    scenario_id: str
    run_id: str
    host: str
    command: str
    note: str = ""
    allow_nonzero: bool = False


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run several labeled scenarios and export a live-compatible parquet dataset.",
    )
    parser.add_argument(
        "--jsonl-output",
        default=None,
        help="Output JSONL path. Defaults to runtime/collected_runtime_dataset_<timestamp>.jsonl",
    )
    parser.add_argument(
        "--parquet-output",
        default=None,
        help="Output parquet path. Defaults to datasets/collected_runtime_dataset_<timestamp>.parquet",
    )
    parser.add_argument(
        "--label-file",
        default="runtime/dataset_label.json",
        help="Path to the shared dataset label file.",
    )
    parser.add_argument(
        "--benign-repeats",
        type=int,
        default=2,
        help="How many times to repeat each benign scenario.",
    )
    parser.add_argument(
        "--attack-repeats",
        type=int,
        default=1,
        help="How many times to repeat each malicious scenario.",
    )
    parser.add_argument(
        "--collection-id",
        default=None,
        help="Optional stable identifier for this collection session.",
    )
    parser.add_argument(
        "--benign-loops",
        type=int,
        default=2,
        help="How many times to repeat each benign sub-sequence inside one run.",
    )
    parser.add_argument(
        "--flood-count",
        type=int,
        default=4000,
        help="Packet count for training flood scenarios. Higher values create more windows.",
    )
    parser.add_argument(
        "--flood-interval-usec",
        type=int,
        default=5000,
        help="Inter-packet gap for training floods in microseconds.",
    )
    parser.add_argument(
        "--settle-seconds",
        type=float,
        default=2.0,
        help="Pause after each scenario to let the recorder flush rows.",
    )
    parser.add_argument(
        "--controller-ready-timeout",
        type=float,
        default=20.0,
        help="Seconds to wait for the recorder-enabled controller to come up.",
    )
    parser.add_argument(
        "--skip-controller-recreate",
        action="store_true",
        help="Use the current controller as-is instead of recreating it with recording enabled.",
    )
    parser.add_argument(
        "--restore-controller",
        action="store_true",
        help="Recreate the controller once more at the end using default compose settings.",
    )
    parser.add_argument(
        "--export-only",
        action="store_true",
        help="Skip traffic generation and export the existing JSONL file to parquet.",
    )
    mitigation_group = parser.add_mutually_exclusive_group()
    mitigation_group.add_argument(
        "--disable-mitigation",
        dest="disable_mitigation",
        action="store_true",
        help="Disable temporary blocking while collecting data so attack runs are not cut short.",
    )
    mitigation_group.add_argument(
        "--keep-mitigation",
        dest="disable_mitigation",
        action="store_false",
        help="Keep normal mitigation behavior during collection.",
    )
    parser.set_defaults(disable_mitigation=True)
    return parser.parse_args()


def project_root():
    return Path(__file__).resolve().parents[1]


def timestamp_slug():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def choose_offline_python():
    root = project_root()
    candidates = (
        root / ".venv-ml310" / "bin" / "python",
        root / ".venv-ml" / "bin" / "python",
    )
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return sys.executable


def run(command, env=None, capture_output=False, check=True):
    printable = " ".join(shlex.quote(part) for part in command)
    print("+ %s" % printable)
    effective_env = None
    if env is not None:
        effective_env = dict(os.environ)
        effective_env.update(env)
    completed = subprocess.run(
        command,
        cwd=str(project_root()),
        env=effective_env,
        text=True,
        capture_output=capture_output,
    )
    if check and completed.returncode != 0:
        if capture_output:
            if completed.stdout:
                sys.stdout.write(completed.stdout)
            if completed.stderr:
                sys.stderr.write(completed.stderr)
        raise SystemExit(completed.returncode)
    return completed


def compose(command, env=None, capture_output=False, check=True):
    return run(["docker", "compose"] + list(command), env=env, capture_output=capture_output, check=check)


def ensure_topology_running():
    result = compose(
        ["exec", "mininet", "sh", "-lc", "pgrep -af 'custom_topology.py'"],
        capture_output=True,
    )
    if not result.stdout.strip():
        print(
            "No running Mininet topology found. Start it with ./scripts/run_topology.sh first.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def mininet_host_pid(host_name):
    result = compose(
        ["exec", "mininet", "sh", "-lc", "pgrep -fo 'mininet:%s'" % host_name],
        capture_output=True,
    )
    pid = result.stdout.strip()
    if not pid:
        print("Could not find a running Mininet shell for %s." % host_name, file=sys.stderr)
        raise SystemExit(1)
    return pid


def run_on_host(host_name, command, check=True):
    pid = mininet_host_pid(host_name)
    return compose(
        ["exec", "mininet", "mnexec", "-a", pid, "sh", "-lc", command],
        check=check,
    )


def controller_logs_tail():
    return compose(["logs", "--tail=80", "controller"], capture_output=True).stdout


def wait_for_controller_ready(expected_output_path, timeout_seconds):
    deadline = time.time() + timeout_seconds
    needle = "dataset_recorder_ready enabled=True"
    path_hint = "output_path=%s" % expected_output_path
    while time.time() < deadline:
        logs = controller_logs_tail()
        if needle in logs and path_hint in logs:
            return
        time.sleep(1.0)
    print("Controller did not become ready with dataset recording enabled.", file=sys.stderr)
    raise SystemExit(1)


def set_label(
    label_file,
    label=None,
    scenario=None,
    scenario_id=None,
    run_id=None,
    collection_id=None,
    note=None,
):
    command = ["python3", "scripts/set_dataset_label.py", "--label-file", label_file]
    if label is None:
        command.append("--clear")
    else:
        command.extend(
            [
                label,
                "--scenario",
                scenario or "",
                "--scenario-id",
                scenario_id or "",
                "--run-id",
                run_id or "",
                "--collection-id",
                collection_id or "",
                "--note",
                note or "",
            ]
        )
    run(command)


def recreate_controller_for_recording(
    jsonl_output,
    label_file,
    timeout_seconds,
    disable_mitigation,
):
    env = dict(
        SDN_ML_DATASET_RECORDING_ENABLED="true",
        SDN_ML_DATASET_RECORDING_PATH=jsonl_output,
        SDN_ML_DATASET_LABEL_PATH=label_file,
        SDN_ML_DATASET_DISABLE_MITIGATION=(
            "true" if disable_mitigation else "false"
        ),
    )
    compose(
        ["up", "-d", "--force-recreate", "controller"],
        env=env,
    )
    wait_for_controller_ready(jsonl_output, timeout_seconds)


def restore_default_controller():
    compose(["up", "-d", "--force-recreate", "controller"])


def export_runtime_dataset(jsonl_output, parquet_output):
    python_exec = choose_offline_python()
    run(
        [
            python_exec,
            "scripts/export_runtime_dataset.py",
            "--input",
            jsonl_output,
            "--output",
            parquet_output,
        ]
    )
    run([python_exec, "scripts/inspect_dataset.py", parquet_output], check=True)


def build_scenarios(
    collection_id,
    benign_repeats,
    attack_repeats,
    benign_loops,
    flood_count,
    flood_interval_usec,
):
    scenarios = []

    def add_scenario(label, scenario_id, repeat_index, host, command, note="", allow_nonzero=False):
        scenario_name = "%s_r%s" % (scenario_id, repeat_index)
        scenarios.append(
            Scenario(
                label=label,
                scenario=scenario_name,
                scenario_id=scenario_id,
                run_id="%s:%s" % (collection_id, scenario_name),
                host=host,
                command=command,
                note=note,
                allow_nonzero=allow_nonzero,
            )
        )

    benign_loop_count = max(1, benign_loops)
    for repeat_index in range(1, max(1, benign_repeats) + 1):
        add_scenario(
            label="benign",
            scenario_id="benign_http_h1_to_h2",
            repeat_index=repeat_index,
            host="h1",
            command=(
                "for _i in $(seq 1 %s); do "
                "/workspace/ryu-apps/traffic/benign_traffic.sh 10.0.0.2 80; "
                "sleep 2; "
                "done"
            )
            % benign_loop_count,
            note="extended_http_benign",
        )
        add_scenario(
            label="benign",
            scenario_id="benign_http_h4_to_h5",
            repeat_index=repeat_index,
            host="h4",
            command=(
                "for _i in $(seq 1 %s); do "
                "/workspace/ryu-apps/traffic/benign_traffic.sh 10.0.0.5 8080; "
                "sleep 2; "
                "done"
            )
            % benign_loop_count,
            note="extended_http_benign",
        )
        add_scenario(
            label="benign",
            scenario_id="benign_mixed_h1",
            repeat_index=repeat_index,
            host="h1",
            command=(
                "for _i in $(seq 1 %s); do "
                "ping -c 3 -i 0.4 10.0.0.4 >/dev/null; "
                "ping -c 3 -i 0.4 10.0.0.5 >/dev/null; "
                "/workspace/ryu-apps/traffic/benign_traffic.sh 10.0.0.2 80 >/dev/null; "
                "sleep 2; "
                "done"
            )
            % benign_loop_count,
            note="mixed_icmp_http_benign",
        )
        add_scenario(
            label="benign",
            scenario_id="benign_dual_service_h4",
            repeat_index=repeat_index,
            host="h4",
            command=(
                "for _i in $(seq 1 %s); do "
                "/workspace/ryu-apps/traffic/benign_traffic.sh 10.0.0.2 80 >/dev/null; "
                "/workspace/ryu-apps/traffic/benign_traffic.sh 10.0.0.5 8080 >/dev/null; "
                "sleep 2; "
                "done"
            )
            % benign_loop_count,
            note="multi_service_benign",
        )

    for repeat_index in range(1, max(1, attack_repeats) + 1):
        add_scenario(
            label="malicious",
            scenario_id="attack_port_scan_tcp_h3",
            repeat_index=repeat_index,
            host="h3",
            command="/workspace/ryu-apps/attacks/port_scan.sh 10.0.0.2",
            note="tcp_syn_port_scan",
        )
        add_scenario(
            label="malicious",
            scenario_id="attack_port_scan_udp_h3",
            repeat_index=repeat_index,
            host="h3",
            command=(
                "nmap -sU -Pn -T4 --max-retries 0 --top-ports 12 10.0.0.2"
            ),
            note="udp_service_probe",
        )
        add_scenario(
            label="malicious",
            scenario_id="attack_icmp_sweep_h3",
            repeat_index=repeat_index,
            host="h3",
            command=(
                "for _round in 1 2 3; do "
                "for _ip in 10.0.0.1 10.0.0.2 10.0.0.4 10.0.0.5; do "
                "ping -c 3 -i 0.2 ${_ip} >/dev/null; "
                "done; "
                "sleep 1; "
                "done"
            ),
            note="icmp_host_sweep",
        )
        add_scenario(
            label="malicious",
            scenario_id="attack_syn_flood_h1",
            repeat_index=repeat_index,
            host="h1",
            command=(
                "SDN_HPING_INTERVAL_USEC=%s "
                "/workspace/ryu-apps/attacks/dos_flood.sh 10.0.0.2 80 %s"
            )
            % (flood_interval_usec, flood_count),
            note="open_port_syn_flood",
            allow_nonzero=True,
        )
        add_scenario(
            label="malicious",
            scenario_id="attack_failed_connection_flood_h4",
            repeat_index=repeat_index,
            host="h4",
            command=(
                "SDN_HPING_INTERVAL_USEC=%s "
                "/workspace/ryu-apps/attacks/dos_flood.sh 10.0.0.2 81 %s"
            )
            % (flood_interval_usec, flood_count),
            note="closed_port_failed_connection_flood",
            allow_nonzero=True,
        )
    return scenarios


def main():
    args = parse_args()
    stamp = timestamp_slug()
    collection_id = args.collection_id or stamp
    jsonl_output = args.jsonl_output or "runtime/collected_runtime_dataset_%s.jsonl" % stamp
    parquet_output = args.parquet_output or "datasets/collected_runtime_dataset_%s.parquet" % stamp
    label_file = args.label_file

    if not args.export_only:
        ensure_topology_running()
        if not args.skip_controller_recreate:
            recreate_controller_for_recording(
                jsonl_output=jsonl_output,
                label_file=label_file,
                timeout_seconds=args.controller_ready_timeout,
                disable_mitigation=args.disable_mitigation,
            )

        try:
            scenarios = build_scenarios(
                collection_id=collection_id,
                benign_repeats=args.benign_repeats,
                attack_repeats=args.attack_repeats,
                benign_loops=args.benign_loops,
                flood_count=args.flood_count,
                flood_interval_usec=args.flood_interval_usec,
            )
            for scenario in scenarios:
                print(
                    "\n== scenario=%s scenario_id=%s label=%s host=%s =="
                    % (
                        scenario.scenario,
                        scenario.scenario_id,
                        scenario.label,
                        scenario.host,
                    )
                )
                set_label(
                    label_file,
                    scenario.label,
                    scenario.scenario,
                    scenario.scenario_id,
                    scenario.run_id,
                    collection_id,
                    scenario.note,
                )
                result = run_on_host(
                    scenario.host,
                    scenario.command,
                    check=not scenario.allow_nonzero,
                )
                if scenario.allow_nonzero and result.returncode != 0:
                    print(
                        "warning: scenario=%s exited_with=%s and will still be kept"
                        % (scenario.scenario, result.returncode)
                    )
                time.sleep(max(0.0, args.settle_seconds))
        finally:
            set_label(label_file, None, None)

    export_runtime_dataset(jsonl_output, parquet_output)

    if args.restore_controller:
        restore_default_controller()

    print("\nCollection complete.")
    print("collection_id=%s" % collection_id)
    print("jsonl=%s" % jsonl_output)
    print("parquet=%s" % parquet_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
