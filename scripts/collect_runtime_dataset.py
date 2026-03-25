#!/usr/bin/env python3
"""Collect a larger live-compatible ML dataset from the running SDN lab."""

from __future__ import print_function

import argparse
from collections import Counter
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
    scenario_family: str
    scenario_variant: str
    run_id: str
    host: str
    command: str
    src_host: str = ""
    dst_host: str = ""
    dst_service: str = ""
    duration_seconds: str = ""
    rate_parameter: str = ""
    concurrency_level: str = ""
    note: str = ""
    allow_nonzero: bool = False


COLLECTION_PROFILES = ("balanced", "scan_heavy", "flood_heavy")


def profile_settings(profile_name):
    profile = str(profile_name or "balanced").strip().lower()
    if profile == "scan_heavy":
        return {
            "scan_repeat_factor": 3,
            "sweep_repeat_factor": 2,
            "flood_repeat_factor": 1,
            "include_extended_scans": True,
            "include_extended_benign": True,
        }
    if profile == "flood_heavy":
        return {
            "scan_repeat_factor": 1,
            "sweep_repeat_factor": 1,
            "flood_repeat_factor": 3,
            "include_extended_scans": False,
            "include_extended_benign": True,
        }
    return {
        "scan_repeat_factor": 1,
        "sweep_repeat_factor": 1,
        "flood_repeat_factor": 1,
        "include_extended_scans": False,
        "include_extended_benign": True,
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run several labeled scenarios and export a live-compatible parquet dataset.",
    )
    parser.add_argument(
        "--collection-profile",
        default="balanced",
        choices=COLLECTION_PROFILES,
        help=(
            "Scenario mix profile. 'scan_heavy' increases scan and sweep coverage "
            "while still keeping flood scenarios in every repeat."
        ),
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
        help="How many times to repeat each benign scenario family.",
    )
    parser.add_argument(
        "--attack-repeats",
        type=int,
        default=1,
        help="How many times to repeat each malicious scenario family.",
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
    scenario_family=None,
    scenario_variant=None,
    traffic_class=None,
    src_host=None,
    dst_host=None,
    dst_service=None,
    duration_seconds=None,
    rate_parameter=None,
    concurrency_level=None,
    capture_file=None,
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
                "--scenario-family",
                scenario_family or "",
                "--scenario-variant",
                scenario_variant or "",
                "--traffic-class",
                traffic_class or label or "",
                "--run-id",
                run_id or "",
                "--collection-id",
                collection_id or "",
                "--src-host",
                src_host or "",
                "--dst-host",
                dst_host or "",
                "--dst-service",
                dst_service or "",
                "--duration-seconds",
                duration_seconds or "",
                "--rate-parameter",
                rate_parameter or "",
                "--concurrency-level",
                concurrency_level or "",
                "--capture-file",
                capture_file or "",
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


def benign_http_command(target_ip, port, loop_count, spacing_seconds):
    return (
        "for _i in $(seq 1 {loops}); do "
        "/workspace/ryu-apps/traffic/benign_traffic.sh {target_ip} {port} >/dev/null; "
        "sleep {spacing}; "
        "done"
    ).format(
        loops=max(1, int(loop_count)),
        target_ip=target_ip,
        port=int(port),
        spacing=float(spacing_seconds),
    )


def benign_mixed_command(http_target, http_port, ping_targets, rounds, ping_interval, pause_seconds):
    ping_sequence = " ".join(str(target) for target in ping_targets)
    return (
        "for _round in $(seq 1 {rounds}); do "
        "for _ip in {ping_sequence}; do "
        "ping -c 3 -i {ping_interval} ${{_ip}} >/dev/null; "
        "done; "
        "/workspace/ryu-apps/traffic/benign_traffic.sh {http_target} {http_port} >/dev/null; "
        "sleep {pause_seconds}; "
        "done"
    ).format(
        rounds=max(1, int(rounds)),
        ping_sequence=ping_sequence,
        ping_interval=float(ping_interval),
        http_target=http_target,
        http_port=int(http_port),
        pause_seconds=float(pause_seconds),
    )


def benign_dual_service_command(primary_target, primary_port, secondary_target, secondary_port, rounds, pause_seconds):
    return (
        "for _round in $(seq 1 {rounds}); do "
        "/workspace/ryu-apps/traffic/benign_traffic.sh {primary_target} {primary_port} >/dev/null; "
        "/workspace/ryu-apps/traffic/benign_traffic.sh {secondary_target} {secondary_port} >/dev/null; "
        "sleep {pause_seconds}; "
        "done"
    ).format(
        rounds=max(1, int(rounds)),
        primary_target=primary_target,
        primary_port=int(primary_port),
        secondary_target=secondary_target,
        secondary_port=int(secondary_port),
        pause_seconds=float(pause_seconds),
    )


def benign_bursty_command(primary_target, primary_port, secondary_target, secondary_port, burst_size, rounds, intra_spacing, pause_seconds):
    return (
        "for _round in $(seq 1 {rounds}); do "
        "for _burst in $(seq 1 {burst_size}); do "
        "( "
        "/workspace/ryu-apps/traffic/benign_traffic.sh {primary_target} {primary_port} >/dev/null; "
        "/workspace/ryu-apps/traffic/benign_traffic.sh {secondary_target} {secondary_port} >/dev/null "
        ") & "
        "sleep {intra_spacing}; "
        "done; "
        "wait; "
        "sleep {pause_seconds}; "
        "done"
    ).format(
        rounds=max(1, int(rounds)),
        burst_size=max(1, int(burst_size)),
        primary_target=primary_target,
        primary_port=int(primary_port),
        secondary_target=secondary_target,
        secondary_port=int(secondary_port),
        intra_spacing=float(intra_spacing),
        pause_seconds=float(pause_seconds),
    )


def tcp_scan_command(target, ports, timing, retries):
    return "nmap -sS -Pn -%s --max-retries %s -p %s %s" % (
        timing,
        int(retries),
        ports,
        target,
    )


def udp_scan_command(target, top_ports, timing, retries):
    return "nmap -sU -Pn -%s --max-retries %s --top-ports %s %s" % (
        timing,
        int(retries),
        int(top_ports),
        target,
    )


def icmp_sweep_command(targets, rounds, ping_count, ping_interval, pause_seconds):
    target_list = " ".join(str(target) for target in targets)
    return (
        "for _round in $(seq 1 {rounds}); do "
        "for _ip in {target_list}; do "
        "ping -c {ping_count} -i {ping_interval} ${{_ip}} >/dev/null; "
        "done; "
        "sleep {pause_seconds}; "
        "done"
    ).format(
        rounds=max(1, int(rounds)),
        target_list=target_list,
        ping_count=max(1, int(ping_count)),
        ping_interval=float(ping_interval),
        pause_seconds=float(pause_seconds),
    )


def syn_flood_command(target, port, packet_count, interval_usec):
    return (
        "SDN_HPING_INTERVAL_USEC=%s "
        "/workspace/ryu-apps/attacks/dos_flood.sh %s %s %s"
    ) % (
        int(interval_usec),
        target,
        int(port),
        int(packet_count),
    )


def summarize_scenarios(scenarios):
    label_counts = Counter()
    family_counts = Counter()
    variant_examples = {}
    for scenario in scenarios:
        label_counts[scenario.label] += 1
        family_counts[scenario.scenario_family] += 1
        variant_examples.setdefault(scenario.scenario_family, scenario.scenario_variant)

    print("\nPlanned scenario summary:")
    print("total_scenarios=%s" % len(scenarios))
    print("labels=%s" % dict(sorted(label_counts.items())))
    print("families=%s" % dict(sorted(family_counts.items())))
    print("example_variants=%s" % dict(sorted(variant_examples.items())))


def build_scenarios(
    collection_id,
    benign_repeats,
    attack_repeats,
    benign_loops,
    flood_count,
    flood_interval_usec,
    collection_profile="balanced",
):
    scenarios = []
    profile = profile_settings(collection_profile)

    def add_scenario(
        label,
        scenario_id,
        scenario_family,
        scenario_variant,
        repeat_index,
        host,
        command,
        src_host,
        dst_host,
        dst_service,
        duration_seconds,
        rate_parameter,
        concurrency_level,
        note="",
        allow_nonzero=False,
        sequence=None,
    ):
        scenario_name = "%s_r%s" % (scenario_id, repeat_index)
        if sequence is not None:
            scenario_name = "%s_s%s" % (scenario_name, sequence)
        scenarios.append(
            Scenario(
                label=label,
                scenario=scenario_name,
                scenario_id=scenario_id,
                scenario_family=scenario_family,
                scenario_variant=scenario_variant,
                run_id="%s:%s" % (collection_id, scenario_name),
                host=host,
                command=command,
                src_host=src_host,
                dst_host=dst_host,
                dst_service=dst_service,
                duration_seconds=str(duration_seconds),
                rate_parameter=str(rate_parameter),
                concurrency_level=str(concurrency_level),
                note=note,
                allow_nonzero=allow_nonzero,
            )
        )

    benign_loop_count = max(1, benign_loops)
    for repeat_index in range(1, max(0, int(benign_repeats)) + 1):
        add_scenario(
            label="benign",
            scenario_id="benign_http_h1_to_h2",
            scenario_family="benign_http_repeated",
            scenario_variant="h1_to_h2_80_spacing_2s",
            repeat_index=repeat_index,
            host="h1",
            command=benign_http_command("10.0.0.2", 80, benign_loop_count, 2.0),
            src_host="h1",
            dst_host="h2",
            dst_service="10.0.0.2:80/http",
            duration_seconds=benign_loop_count * 2,
            rate_parameter="spacing=2.0s",
            concurrency_level=1,
            note="repeated_http_h2",
        )
        add_scenario(
            label="benign",
            scenario_id="benign_http_h4_to_h5",
            scenario_family="benign_http_repeated",
            scenario_variant="h4_to_h5_8080_spacing_2s",
            repeat_index=repeat_index,
            host="h4",
            command=benign_http_command("10.0.0.5", 8080, benign_loop_count, 2.0),
            src_host="h4",
            dst_host="h5",
            dst_service="10.0.0.5:8080/http-alt",
            duration_seconds=benign_loop_count * 2,
            rate_parameter="spacing=2.0s",
            concurrency_level=1,
            note="repeated_http_h5",
        )
        add_scenario(
            label="benign",
            scenario_id="benign_mixed_h1",
            scenario_family="benign_mixed_icmp_http",
            scenario_variant="h1_ping_h4_h5_and_http_h2",
            repeat_index=repeat_index,
            host="h1",
            command=benign_mixed_command(
                http_target="10.0.0.2",
                http_port=80,
                ping_targets=("10.0.0.4", "10.0.0.5"),
                rounds=benign_loop_count,
                ping_interval=0.4,
                pause_seconds=2.0,
            ),
            src_host="h1",
            dst_host="h2,h4,h5",
            dst_service="icmp+10.0.0.2:80/http",
            duration_seconds=benign_loop_count * 6,
            rate_parameter="ping_interval=0.4s,http_spacing=2.0s",
            concurrency_level=1,
            note="mixed_icmp_http_benign",
        )
        add_scenario(
            label="benign",
            scenario_id="benign_dual_service_h4",
            scenario_family="benign_multi_service",
            scenario_variant="h4_h2_80_then_h5_8080",
            repeat_index=repeat_index,
            host="h4",
            command=benign_dual_service_command(
                "10.0.0.2",
                80,
                "10.0.0.5",
                8080,
                benign_loop_count,
                2.0,
            ),
            src_host="h4",
            dst_host="h2,h5",
            dst_service="10.0.0.2:80/http+10.0.0.5:8080/http-alt",
            duration_seconds=benign_loop_count * 2,
            rate_parameter="sequential_dual_service_spacing=2.0s",
            concurrency_level=1,
            note="multi_service_benign",
        )

        if profile["include_extended_benign"]:
            add_scenario(
                label="benign",
                scenario_id="benign_http_long_interval_h1",
                scenario_family="benign_long_interval",
                scenario_variant="h1_to_h2_80_spacing_5s",
                repeat_index=repeat_index,
                host="h1",
                command=benign_http_command("10.0.0.2", 80, max(2, benign_loop_count), 5.0),
                src_host="h1",
                dst_host="h2",
                dst_service="10.0.0.2:80/http",
                duration_seconds=max(2, benign_loop_count) * 5,
                rate_parameter="spacing=5.0s",
                concurrency_level=1,
                note="long_interval_http_benign",
            )
            add_scenario(
                label="benign",
                scenario_id="benign_http_long_interval_h4",
                scenario_family="benign_long_interval",
                scenario_variant="h4_to_h5_8080_spacing_5s",
                repeat_index=repeat_index,
                host="h4",
                command=benign_http_command("10.0.0.5", 8080, max(2, benign_loop_count), 5.0),
                src_host="h4",
                dst_host="h5",
                dst_service="10.0.0.5:8080/http-alt",
                duration_seconds=max(2, benign_loop_count) * 5,
                rate_parameter="spacing=5.0s",
                concurrency_level=1,
                note="long_interval_http_benign",
            )
            add_scenario(
                label="benign",
                scenario_id="benign_bursty_h1",
                scenario_family="benign_bursty_legitimate",
                scenario_variant="h1_parallel_http_h2_h5_bursts",
                repeat_index=repeat_index,
                host="h1",
                command=benign_bursty_command(
                    "10.0.0.2",
                    80,
                    "10.0.0.5",
                    8080,
                    burst_size=max(3, benign_loop_count + 1),
                    rounds=2,
                    intra_spacing=0.5,
                    pause_seconds=20.0,
                ),
                src_host="h1",
                dst_host="h2,h5",
                dst_service="10.0.0.2:80/http+10.0.0.5:8080/http-alt",
                duration_seconds=40,
                rate_parameter="burst_size=%s,pause=20.0s" % max(3, benign_loop_count + 1),
                concurrency_level=2,
                note="bursty_legitimate_parallel_http",
            )
            add_scenario(
                label="benign",
                scenario_id="benign_mixed_h4",
                scenario_family="benign_mixed_icmp_http",
                scenario_variant="h4_ping_h1_h2_and_http_h5",
                repeat_index=repeat_index,
                host="h4",
                command=benign_mixed_command(
                    http_target="10.0.0.5",
                    http_port=8080,
                    ping_targets=("10.0.0.1", "10.0.0.2"),
                    rounds=benign_loop_count,
                    ping_interval=0.5,
                    pause_seconds=3.0,
                ),
                src_host="h4",
                dst_host="h1,h2,h5",
                dst_service="icmp+10.0.0.5:8080/http-alt",
                duration_seconds=benign_loop_count * 7,
                rate_parameter="ping_interval=0.5s,http_spacing=3.0s",
                concurrency_level=1,
                note="mixed_icmp_http_benign",
            )

    for repeat_index in range(1, max(0, int(attack_repeats)) + 1):
        for sequence in range(1, profile["scan_repeat_factor"] + 1):
            add_scenario(
                label="malicious",
                scenario_id="attack_port_scan_tcp_h3",
                scenario_family="tcp_port_scan",
                scenario_variant="h3_to_h2_ports_1_20_t4",
                repeat_index=repeat_index,
                host="h3",
                command=tcp_scan_command("10.0.0.2", "23,1-20", "T4", 0),
                src_host="h3",
                dst_host="h2",
                dst_service="10.0.0.2:1-23/tcp",
                duration_seconds=8,
                rate_parameter="timing=T4,retries=0",
                concurrency_level=1,
                note="tcp_syn_port_scan",
                sequence=sequence,
            )
            add_scenario(
                label="malicious",
                scenario_id="attack_port_scan_tcp_h1_to_h5",
                scenario_family="tcp_port_scan",
                scenario_variant="h1_to_h5_ports_1_30_t3",
                repeat_index=repeat_index,
                host="h1",
                command=tcp_scan_command("10.0.0.5", "1-30", "T3", 1),
                src_host="h1",
                dst_host="h5",
                dst_service="10.0.0.5:1-30/tcp",
                duration_seconds=10,
                rate_parameter="timing=T3,retries=1",
                concurrency_level=1,
                note="tcp_syn_port_scan",
                sequence=sequence,
            )
            add_scenario(
                label="malicious",
                scenario_id="attack_port_scan_udp_h3",
                scenario_family="udp_port_scan",
                scenario_variant="h3_to_h2_top12_t4",
                repeat_index=repeat_index,
                host="h3",
                command=udp_scan_command("10.0.0.2", 12, "T4", 0),
                src_host="h3",
                dst_host="h2",
                dst_service="10.0.0.2:top12/udp",
                duration_seconds=8,
                rate_parameter="timing=T4,top_ports=12",
                concurrency_level=1,
                note="udp_service_probe",
                sequence=sequence,
            )
            add_scenario(
                label="malicious",
                scenario_id="attack_port_scan_udp_h1_to_h5",
                scenario_family="udp_port_scan",
                scenario_variant="h1_to_h5_top20_t3",
                repeat_index=repeat_index,
                host="h1",
                command=udp_scan_command("10.0.0.5", 20, "T3", 0),
                src_host="h1",
                dst_host="h5",
                dst_service="10.0.0.5:top20/udp",
                duration_seconds=10,
                rate_parameter="timing=T3,top_ports=20",
                concurrency_level=1,
                note="udp_service_probe",
                sequence=sequence,
            )
            if profile["include_extended_scans"]:
                add_scenario(
                    label="malicious",
                    scenario_id="attack_port_scan_tcp_wide_h3",
                    scenario_family="tcp_port_scan_wide",
                    scenario_variant="h3_to_h2_ports_1_100_t3",
                    repeat_index=repeat_index,
                    host="h3",
                    command=tcp_scan_command("10.0.0.2", "1-100", "T3", 1),
                    src_host="h3",
                    dst_host="h2",
                    dst_service="10.0.0.2:1-100/tcp",
                    duration_seconds=12,
                    rate_parameter="timing=T3,retries=1",
                    concurrency_level=1,
                    note="wider_filtered_tcp_scan",
                    sequence=sequence,
                )
                add_scenario(
                    label="malicious",
                    scenario_id="attack_port_scan_tcp_wide_h1_to_h5",
                    scenario_family="tcp_port_scan_wide",
                    scenario_variant="h1_to_h5_ports_1_120_t3",
                    repeat_index=repeat_index,
                    host="h1",
                    command=tcp_scan_command("10.0.0.5", "1-120", "T3", 1),
                    src_host="h1",
                    dst_host="h5",
                    dst_service="10.0.0.5:1-120/tcp",
                    duration_seconds=12,
                    rate_parameter="timing=T3,retries=1",
                    concurrency_level=1,
                    note="wider_filtered_tcp_scan",
                    sequence=sequence,
                )
                add_scenario(
                    label="malicious",
                    scenario_id="attack_host_scan_tcp_h3",
                    scenario_family="multi_host_scan",
                    scenario_variant="h3_to_10_0_0_1_5_ports_1_30",
                    repeat_index=repeat_index,
                    host="h3",
                    command=tcp_scan_command("10.0.0.1-5", "1-30", "T4", 0),
                    src_host="h3",
                    dst_host="10.0.0.1-5",
                    dst_service="10.0.0.1-5:1-30/tcp",
                    duration_seconds=10,
                    rate_parameter="timing=T4,retries=0",
                    concurrency_level=1,
                    note="multi_host_tcp_scan",
                    sequence=sequence,
                )
                add_scenario(
                    label="malicious",
                    scenario_id="attack_host_scan_tcp_h1",
                    scenario_family="multi_host_scan",
                    scenario_variant="h1_to_10_0_0_2_5_ports_20_80",
                    repeat_index=repeat_index,
                    host="h1",
                    command=tcp_scan_command("10.0.0.2-5", "20-80", "T3", 0),
                    src_host="h1",
                    dst_host="10.0.0.2-5",
                    dst_service="10.0.0.2-5:20-80/tcp",
                    duration_seconds=10,
                    rate_parameter="timing=T3,retries=0",
                    concurrency_level=1,
                    note="multi_host_tcp_scan",
                    sequence=sequence,
                )

        for sequence in range(1, profile["sweep_repeat_factor"] + 1):
            add_scenario(
                label="malicious",
                scenario_id="attack_icmp_sweep_h3",
                scenario_family="icmp_sweep",
                scenario_variant="h3_to_h1_h2_h4_h5_rounds_3",
                repeat_index=repeat_index,
                host="h3",
                command=icmp_sweep_command(
                    ("10.0.0.1", "10.0.0.2", "10.0.0.4", "10.0.0.5"),
                    rounds=3,
                    ping_count=3,
                    ping_interval=0.2,
                    pause_seconds=1.0,
                ),
                src_host="h3",
                dst_host="h1,h2,h4,h5",
                dst_service="icmp",
                duration_seconds=12,
                rate_parameter="ping_interval=0.2s,rounds=3",
                concurrency_level=1,
                note="icmp_host_sweep",
                sequence=sequence,
            )
            if profile["include_extended_scans"]:
                add_scenario(
                    label="malicious",
                    scenario_id="attack_icmp_sweep_h1",
                    scenario_family="icmp_sweep",
                    scenario_variant="h1_to_h2_h3_h4_h5_rounds_4",
                    repeat_index=repeat_index,
                    host="h1",
                    command=icmp_sweep_command(
                        ("10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"),
                        rounds=4,
                        ping_count=2,
                        ping_interval=0.3,
                        pause_seconds=1.0,
                    ),
                    src_host="h1",
                    dst_host="h2,h3,h4,h5",
                    dst_service="icmp",
                    duration_seconds=14,
                    rate_parameter="ping_interval=0.3s,rounds=4",
                    concurrency_level=1,
                    note="icmp_host_sweep",
                    sequence=sequence,
                )

        for sequence in range(1, profile["flood_repeat_factor"] + 1):
            add_scenario(
                label="malicious",
                scenario_id="attack_syn_flood_h1",
                scenario_family="syn_flood_open_port",
                scenario_variant="h1_to_h2_80",
                repeat_index=repeat_index,
                host="h1",
                command=syn_flood_command("10.0.0.2", 80, flood_count, flood_interval_usec),
                src_host="h1",
                dst_host="h2",
                dst_service="10.0.0.2:80/http",
                duration_seconds=max(1, int((flood_count * max(1, flood_interval_usec)) / 1000000.0)),
                rate_parameter="count=%s,interval_usec=%s" % (flood_count, flood_interval_usec),
                concurrency_level=1,
                note="open_port_syn_flood",
                allow_nonzero=True,
                sequence=sequence,
            )
            add_scenario(
                label="malicious",
                scenario_id="attack_syn_flood_h4_to_h5",
                scenario_family="syn_flood_open_port",
                scenario_variant="h4_to_h5_8080",
                repeat_index=repeat_index,
                host="h4",
                command=syn_flood_command("10.0.0.5", 8080, flood_count, flood_interval_usec),
                src_host="h4",
                dst_host="h5",
                dst_service="10.0.0.5:8080/http-alt",
                duration_seconds=max(1, int((flood_count * max(1, flood_interval_usec)) / 1000000.0)),
                rate_parameter="count=%s,interval_usec=%s" % (flood_count, flood_interval_usec),
                concurrency_level=1,
                note="open_port_syn_flood",
                allow_nonzero=True,
                sequence=sequence,
            )
            add_scenario(
                label="malicious",
                scenario_id="attack_failed_connection_flood_h4",
                scenario_family="syn_flood_failed_connection",
                scenario_variant="h4_to_h2_81",
                repeat_index=repeat_index,
                host="h4",
                command=syn_flood_command("10.0.0.2", 81, flood_count, flood_interval_usec),
                src_host="h4",
                dst_host="h2",
                dst_service="10.0.0.2:81/closed",
                duration_seconds=max(1, int((flood_count * max(1, flood_interval_usec)) / 1000000.0)),
                rate_parameter="count=%s,interval_usec=%s" % (flood_count, flood_interval_usec),
                concurrency_level=1,
                note="closed_port_failed_connection_flood",
                allow_nonzero=True,
                sequence=sequence,
            )
            add_scenario(
                label="malicious",
                scenario_id="attack_failed_connection_flood_h1_to_h5",
                scenario_family="syn_flood_failed_connection",
                scenario_variant="h1_to_h5_9999",
                repeat_index=repeat_index,
                host="h1",
                command=syn_flood_command("10.0.0.5", 9999, flood_count, flood_interval_usec),
                src_host="h1",
                dst_host="h5",
                dst_service="10.0.0.5:9999/closed",
                duration_seconds=max(1, int((flood_count * max(1, flood_interval_usec)) / 1000000.0)),
                rate_parameter="count=%s,interval_usec=%s" % (flood_count, flood_interval_usec),
                concurrency_level=1,
                note="closed_port_failed_connection_flood",
                allow_nonzero=True,
                sequence=sequence,
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
                collection_profile=args.collection_profile,
            )
            summarize_scenarios(scenarios)
            for scenario in scenarios:
                print(
                    "\n== scenario=%s scenario_id=%s family=%s label=%s host=%s variant=%s =="
                    % (
                        scenario.scenario,
                        scenario.scenario_id,
                        scenario.scenario_family,
                        scenario.label,
                        scenario.host,
                        scenario.scenario_variant,
                    )
                )
                set_label(
                    label_file,
                    label=scenario.label,
                    scenario=scenario.scenario,
                    scenario_id=scenario.scenario_id,
                    run_id=scenario.run_id,
                    collection_id=collection_id,
                    note=scenario.note,
                    scenario_family=scenario.scenario_family,
                    scenario_variant=scenario.scenario_variant,
                    traffic_class=scenario.label,
                    src_host=scenario.src_host,
                    dst_host=scenario.dst_host,
                    dst_service=scenario.dst_service,
                    duration_seconds=scenario.duration_seconds,
                    rate_parameter=scenario.rate_parameter,
                    concurrency_level=scenario.concurrency_level,
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
    print("profile=%s" % args.collection_profile)
    print("collection_id=%s" % collection_id)
    print("jsonl=%s" % jsonl_output)
    print("parquet=%s" % parquet_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
