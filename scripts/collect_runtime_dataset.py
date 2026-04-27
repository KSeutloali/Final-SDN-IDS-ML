#!/usr/bin/env python3
"""Collect a larger live-compatible ML dataset from the running SDN lab."""

from __future__ import print_function

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import math
import os
from pathlib import Path
import shlex
import subprocess
import sys
import textwrap
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
    expected_detection_target: str = ""
    threshold_evasive: bool = False
    known_family: bool = False
    blended_with_benign: bool = False
    allow_nonzero: bool = False
    setup_actions: tuple = ()
    cleanup_actions: tuple = ()


@dataclass(frozen=True)
class HostAction(object):
    host: str
    command: str
    description: str = ""
    allow_nonzero: bool = False


COLLECTION_PROFILES = ("balanced", "scan_heavy", "flood_heavy", "benign_heavy")


def profile_settings(profile_name):
    profile = str(profile_name or "balanced").strip().lower()
    if profile == "benign_heavy":
        return {
            "benign_repeat_factor": 4,
            "benign_loop_multiplier": 4,
            "default_benign_concurrency": 3,
            "default_benign_jitter_seconds": 0.75,
            "scan_repeat_factor": 0,
            "sweep_repeat_factor": 0,
            "flood_repeat_factor": 0,
            "include_extended_scans": False,
            "include_extended_benign": True,
            "include_advanced_benign": True,
        }
    if profile == "scan_heavy":
        return {
            "benign_repeat_factor": 1,
            "benign_loop_multiplier": 1,
            "default_benign_concurrency": 1,
            "default_benign_jitter_seconds": 0.0,
            "scan_repeat_factor": 3,
            "sweep_repeat_factor": 2,
            "flood_repeat_factor": 1,
            "include_extended_scans": True,
            "include_layered_eval_scenarios": True,
            "include_extended_benign": True,
            "include_advanced_benign": False,
        }
    if profile == "flood_heavy":
        return {
            "benign_repeat_factor": 1,
            "benign_loop_multiplier": 1,
            "default_benign_concurrency": 1,
            "default_benign_jitter_seconds": 0.0,
            "scan_repeat_factor": 1,
            "sweep_repeat_factor": 1,
            "flood_repeat_factor": 3,
            "include_extended_scans": False,
            "include_layered_eval_scenarios": False,
            "include_extended_benign": True,
            "include_advanced_benign": False,
        }
    return {
        "benign_repeat_factor": 1,
        "benign_loop_multiplier": 1,
        "default_benign_concurrency": 1,
        "default_benign_jitter_seconds": 0.0,
        "scan_repeat_factor": 1,
        "sweep_repeat_factor": 1,
        "flood_repeat_factor": 1,
        "include_extended_scans": False,
        "include_layered_eval_scenarios": False,
        "include_extended_benign": True,
        "include_advanced_benign": False,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run several labeled scenarios and export a live-compatible parquet dataset.",
    )
    parser.add_argument(
        "--collection-profile",
        default="balanced",
        choices=COLLECTION_PROFILES,
        help=(
            "Scenario mix profile. 'scan_heavy' increases scan and sweep coverage "
            "while still keeping flood scenarios in every repeat. "
            "'benign_heavy' focuses on long-running, diverse benign activity for anomaly training."
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
        "--benign-concurrency",
        type=int,
        default=0,
        help="Optional concurrent benign session count. Uses the profile default when set to 0.",
    )
    parser.add_argument(
        "--benign-jitter-seconds",
        type=float,
        default=0.0,
        help="Optional additional sleep jitter for benign timing variation. Uses the profile default when set to 0.",
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=42,
        help="Deterministic seed used when generating jittered benign traffic patterns.",
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
    return parser.parse_args(argv)


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


def run_host_action(action):
    description = " (%s)" % action.description if action.description else ""
    print(
        "-- host_action host=%s%s" % (
            action.host,
            description,
        )
    )
    return run_on_host(
        action.host,
        action.command,
        check=not bool(action.allow_nonzero),
    )


def safe_cleanup_action(action):
    result = run_on_host(action.host, action.command, check=False)
    if result.returncode != 0:
        print(
            "warning: cleanup host_action host=%s description=%s exited_with=%s"
            % (
                action.host,
                action.description or "cleanup",
                result.returncode,
            )
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
    expected_detection_target=None,
    threshold_evasive=None,
    known_family=None,
    blended_with_benign=None,
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
                "--expected-detection-target",
                expected_detection_target or "",
                "--threshold-evasive",
                "true" if bool(threshold_evasive) else "false",
                "--known-family",
                "true" if bool(known_family) else "false",
                "--blended-with-benign",
                "true" if bool(blended_with_benign) else "false",
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


def inline_python_command(script, *args):
    script_body = textwrap.dedent(script).strip()
    argument_string = " ".join(shlex.quote(str(value)) for value in args)
    if argument_string:
        return "python3 - %s <<'PY'\n%s\nPY" % (argument_string, script_body)
    return "python3 - <<'PY'\n%s\nPY" % script_body


def background_python_command(script, args=(), marker="", log_path=""):
    script_body = textwrap.dedent(script).strip()
    argument_values = [marker] if marker else []
    argument_values.extend(list(args or ()))
    argument_string = " ".join(shlex.quote(str(value)) for value in argument_values)
    redirection = ""
    if log_path:
        redirection = " >%s 2>&1" % shlex.quote(str(log_path))
    return "(python3 - %s <<'PY'\n%s\nPY\n)%s &" % (
        argument_string,
        script_body,
        redirection,
    )


def cleanup_marker_command(marker):
    return "pkill -f %s >/dev/null 2>&1 || true" % shlex.quote(str(marker))


def http_service_directory(host_name):
    if host_name == "h2":
        return "/tmp/primary_http_service_www"
    if host_name == "h5":
        return "/tmp/backup_http_service_www"
    return "/tmp/%s_www" % host_name


def prepare_http_payload_command(host_name, filename, size_kib):
    service_directory = http_service_directory(host_name)
    return inline_python_command(
        """
        from pathlib import Path
        import sys

        service_directory = Path(sys.argv[1])
        filename = sys.argv[2]
        size_kib = max(1, int(sys.argv[3]))
        service_directory.mkdir(parents=True, exist_ok=True)
        payload = ("SDN-BENIGN-DATA-" * 256).encode("ascii")
        target = service_directory / filename
        remaining = size_kib * 1024
        with target.open("wb") as handle:
            while remaining > 0:
                chunk = payload[: min(len(payload), remaining)]
                handle.write(chunk)
                remaining -= len(chunk)
        print("prepared_http_payload path=%s bytes=%s" % (target, target.stat().st_size))
        """,
        service_directory,
        filename,
        int(size_kib),
    )


def remove_http_payload_command(host_name, filename):
    return "rm -f %s" % shlex.quote(
        str(Path(http_service_directory(host_name)) / filename)
    )


def benign_http_command(target_ip, port, loop_count, spacing_seconds):
    return (
        "for _i in $(seq 1 {loops}); do "
        "sh /workspace/ryu-apps/traffic/benign_traffic.sh {target_ip} {port} >/dev/null; "
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
        "sh /workspace/ryu-apps/traffic/benign_traffic.sh {http_target} {http_port} >/dev/null; "
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
        "sh /workspace/ryu-apps/traffic/benign_traffic.sh {primary_target} {primary_port} >/dev/null; "
        "sh /workspace/ryu-apps/traffic/benign_traffic.sh {secondary_target} {secondary_port} >/dev/null; "
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
        "sh /workspace/ryu-apps/traffic/benign_traffic.sh {primary_target} {primary_port} >/dev/null; "
        "sh /workspace/ryu-apps/traffic/benign_traffic.sh {secondary_target} {secondary_port} >/dev/null "
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


def benign_http_polling_command(targets, rounds, pause_seconds, jitter_seconds, random_seed):
    target_arguments = []
    for target_ip, target_port in targets:
        target_arguments.extend([target_ip, int(target_port)])
    return inline_python_command(
        """
        import random
        import socket
        import sys
        import time

        rounds = max(1, int(sys.argv[1]))
        pause_seconds = float(sys.argv[2])
        jitter_seconds = max(0.0, float(sys.argv[3]))
        random_seed = int(sys.argv[4])
        targets = []
        values = sys.argv[5:]
        for index in range(0, len(values), 2):
            targets.append((values[index], int(values[index + 1])))

        jitter = random.Random(random_seed)
        request_templates = (
            "HEAD / HTTP/1.0\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n",
            "GET / HTTP/1.0\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n",
        )

        for round_index in range(rounds):
            for target_ip, target_port in targets:
                request = request_templates[round_index % len(request_templates)].format(
                    host=target_ip
                ).encode("ascii")
                sock = socket.create_connection((target_ip, target_port), timeout=10)
                sock.settimeout(10)
                sock.sendall(request)
                sock.recv(256)
                sock.close()
            time.sleep(pause_seconds + jitter.uniform(0.0, jitter_seconds))
        """,
        int(rounds),
        float(pause_seconds),
        float(jitter_seconds),
        int(random_seed),
        *target_arguments
    )


def benign_http_bulk_command(
    target_ip,
    port,
    path,
    rounds,
    pause_seconds,
    jitter_seconds,
    random_seed,
    parallel_streams,
):
    return inline_python_command(
        """
        import random
        import socket
        import sys
        import threading
        import time

        target_ip = sys.argv[1]
        target_port = int(sys.argv[2])
        path = sys.argv[3]
        rounds = max(1, int(sys.argv[4]))
        pause_seconds = float(sys.argv[5])
        jitter_seconds = max(0.0, float(sys.argv[6]))
        random_seed = int(sys.argv[7])
        parallel_streams = max(1, int(sys.argv[8]))

        jitter = random.Random(random_seed)
        request = (
            "GET {path} HTTP/1.0\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n"
        ).format(path=path, host=target_ip).encode("ascii")

        def fetch_once():
            sock = socket.create_connection((target_ip, target_port), timeout=10)
            sock.settimeout(10)
            sock.sendall(request)
            while sock.recv(8192):
                pass
            sock.close()

        for _round in range(rounds):
            threads = []
            for _ in range(parallel_streams):
                thread = threading.Thread(target=fetch_once)
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join()
            time.sleep(pause_seconds + jitter.uniform(0.0, jitter_seconds))
        """,
        target_ip,
        int(port),
        path,
        int(rounds),
        float(pause_seconds),
        float(jitter_seconds),
        int(random_seed),
        int(parallel_streams),
    )


def benign_udp_service_start_command(marker, port):
    return background_python_command(
        """
        import socket
        import sys

        _marker = sys.argv[1]
        port = int(sys.argv[2])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        while True:
            payload, address = sock.recvfrom(2048)
            if payload == b"__sdn_stop__":
                break
            sock.sendto((b"ok:" + payload)[:512], address)
        sock.close()
        """,
        args=(int(port),),
        marker=marker,
        log_path="/tmp/%s.log" % marker,
    )


def benign_udp_request_response_command(
    target_ip,
    port,
    rounds,
    requests_per_round,
    pause_seconds,
    jitter_seconds,
    random_seed,
):
    return inline_python_command(
        """
        import random
        import socket
        import sys
        import time

        target_ip = sys.argv[1]
        target_port = int(sys.argv[2])
        rounds = max(1, int(sys.argv[3]))
        requests_per_round = max(1, int(sys.argv[4]))
        pause_seconds = float(sys.argv[5])
        jitter_seconds = max(0.0, float(sys.argv[6]))
        random_seed = int(sys.argv[7])

        jitter = random.Random(random_seed)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        for round_index in range(rounds):
            for request_index in range(requests_per_round):
                payload = (
                    "dns-like-query-%s-%s" % (round_index, request_index)
                ).encode("ascii")
                sock.sendto(payload, (target_ip, target_port))
                sock.recvfrom(1024)
            time.sleep(pause_seconds + jitter.uniform(0.0, jitter_seconds))
        sock.close()
        """,
        target_ip,
        int(port),
        int(rounds),
        int(requests_per_round),
        float(pause_seconds),
        float(jitter_seconds),
        int(random_seed),
    )


def benign_tcp_service_start_command(marker, port, reply_prefix):
    return background_python_command(
        """
        import socket
        import sys

        _marker = sys.argv[1]
        port = int(sys.argv[2])
        reply_prefix = sys.argv[3]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(16)
        while True:
            connection, _address = sock.accept()
            payload = connection.recv(1024)
            if payload == b"__sdn_stop__":
                connection.close()
                break
            connection.sendall((reply_prefix + ":" + payload.decode("utf-8", "ignore")).encode("utf-8"))
            connection.close()
        sock.close()
        """,
        args=(int(port), reply_prefix),
        marker=marker,
        log_path="/tmp/%s.log" % marker,
    )


def benign_tcp_session_command(
    target_ip,
    port,
    rounds,
    messages_per_round,
    pause_seconds,
    jitter_seconds,
    random_seed,
):
    return inline_python_command(
        """
        import random
        import socket
        import sys
        import time

        target_ip = sys.argv[1]
        target_port = int(sys.argv[2])
        rounds = max(1, int(sys.argv[3]))
        messages_per_round = max(1, int(sys.argv[4]))
        pause_seconds = float(sys.argv[5])
        jitter_seconds = max(0.0, float(sys.argv[6]))
        random_seed = int(sys.argv[7])
        message_templates = (
            "status",
            "show interfaces",
            "sync peers",
            "health check",
        )
        jitter = random.Random(random_seed)

        for round_index in range(rounds):
            for message_index in range(messages_per_round):
                payload = message_templates[(round_index + message_index) % len(message_templates)]
                connection = socket.create_connection((target_ip, target_port), timeout=10)
                connection.settimeout(10)
                connection.sendall((payload + "\\n").encode("utf-8"))
                connection.recv(256)
                connection.close()
            time.sleep(pause_seconds + jitter.uniform(0.0, jitter_seconds))
        """,
        target_ip,
        int(port),
        int(rounds),
        int(messages_per_round),
        float(pause_seconds),
        float(jitter_seconds),
        int(random_seed),
    )


def benign_browser_like_command(targets, rounds, think_seconds, jitter_seconds, random_seed):
    target_arguments = []
    for target_ip, target_port in targets:
        target_arguments.extend([target_ip, int(target_port)])
    return inline_python_command(
        """
        import random
        import socket
        import sys
        import time

        rounds = max(1, int(sys.argv[1]))
        think_seconds = float(sys.argv[2])
        jitter_seconds = max(0.0, float(sys.argv[3]))
        random_seed = int(sys.argv[4])
        targets = []
        values = sys.argv[5:]
        for index in range(0, len(values), 2):
            targets.append((values[index], int(values[index + 1])))

        request_templates = (
            "GET / HTTP/1.0\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n",
            "HEAD / HTTP/1.0\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n",
            "GET /?view=dashboard HTTP/1.0\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n",
            "GET /favicon.ico HTTP/1.0\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n",
        )
        jitter = random.Random(random_seed)

        for round_index in range(rounds):
            for target_index, (target_ip, target_port) in enumerate(targets):
                request_count = 2 + ((round_index + target_index) % 2)
                for request_index in range(request_count):
                    request = request_templates[
                        (round_index + target_index + request_index) % len(request_templates)
                    ].format(host=target_ip).encode("ascii")
                    sock = socket.create_connection((target_ip, target_port), timeout=10)
                    sock.settimeout(10)
                    sock.sendall(request)
                    while sock.recv(4096):
                        pass
                    sock.close()
                time.sleep(0.2 + jitter.uniform(0.0, min(0.4, jitter_seconds)))
            time.sleep(think_seconds + jitter.uniform(0.0, jitter_seconds))
        """,
        int(rounds),
        float(think_seconds),
        float(jitter_seconds),
        int(random_seed),
        *target_arguments
    )


def benign_dns_then_service_access_command(
    udp_target_ip,
    udp_port,
    http_targets,
    rounds,
    pause_seconds,
    jitter_seconds,
    random_seed,
):
    target_arguments = []
    for target_ip, target_port in http_targets:
        target_arguments.extend([target_ip, int(target_port)])
    return inline_python_command(
        """
        import random
        import socket
        import sys
        import time

        udp_target_ip = sys.argv[1]
        udp_target_port = int(sys.argv[2])
        rounds = max(1, int(sys.argv[3]))
        pause_seconds = float(sys.argv[4])
        jitter_seconds = max(0.0, float(sys.argv[5]))
        random_seed = int(sys.argv[6])
        http_targets = []
        values = sys.argv[7:]
        for index in range(0, len(values), 2):
            http_targets.append((values[index], int(values[index + 1])))

        jitter = random.Random(random_seed)
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(2.0)

        for round_index in range(rounds):
            for query_index in range(2):
                payload = ("lookup-%s-%s" % (round_index, query_index)).encode("ascii")
                udp_sock.sendto(payload, (udp_target_ip, udp_target_port))
                udp_sock.recvfrom(1024)

            for target_ip, target_port in http_targets:
                request = (
                    "GET / HTTP/1.0\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n"
                ).format(host=target_ip).encode("ascii")
                sock = socket.create_connection((target_ip, target_port), timeout=10)
                sock.settimeout(10)
                sock.sendall(request)
                while sock.recv(4096):
                    pass
                sock.close()

            time.sleep(pause_seconds + jitter.uniform(0.0, jitter_seconds))

        udp_sock.close()
        """,
        udp_target_ip,
        int(udp_port),
        int(rounds),
        float(pause_seconds),
        float(jitter_seconds),
        int(random_seed),
        *target_arguments
    )


def benign_persistent_tcp_service_start_command(marker, port, reply_prefix):
    return background_python_command(
        """
        import socket
        import sys

        _marker = sys.argv[1]
        port = int(sys.argv[2])
        reply_prefix = sys.argv[3]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(16)
        while True:
            connection, _address = sock.accept()
            connection.settimeout(10.0)
            try:
                while True:
                    payload = connection.recv(1024)
                    if not payload:
                        break
                    if payload.strip() == b"__sdn_stop__":
                        connection.close()
                        sock.close()
                        raise SystemExit(0)
                    response = (reply_prefix + ":" + payload.decode("utf-8", "ignore")).encode("utf-8")
                    connection.sendall(response[:512])
            except socket.timeout:
                pass
            finally:
                connection.close()
        """,
        args=(int(port), reply_prefix),
        marker=marker,
        log_path="/tmp/%s.log" % marker,
    )


def benign_chat_keepalive_command(
    target_ip,
    port,
    sessions,
    keepalive_count,
    keepalive_interval,
    jitter_seconds,
    random_seed,
):
    return inline_python_command(
        """
        import random
        import socket
        import sys
        import time

        target_ip = sys.argv[1]
        target_port = int(sys.argv[2])
        sessions = max(1, int(sys.argv[3]))
        keepalive_count = max(1, int(sys.argv[4]))
        keepalive_interval = float(sys.argv[5])
        jitter_seconds = max(0.0, float(sys.argv[6]))
        random_seed = int(sys.argv[7])
        chatter_templates = ("presence", "typing", "message", "idle")
        jitter = random.Random(random_seed)

        for session_index in range(sessions):
            connection = socket.create_connection((target_ip, target_port), timeout=10)
            connection.settimeout(10)
            for keepalive_index in range(keepalive_count):
                payload = chatter_templates[
                    (session_index + keepalive_index) % len(chatter_templates)
                ]
                message = ("%s-%s-%s\\n" % (payload, session_index, keepalive_index)).encode("utf-8")
                connection.sendall(message)
                connection.recv(256)
                time.sleep(keepalive_interval + jitter.uniform(0.0, jitter_seconds))
            connection.close()
            time.sleep(1.0 + jitter.uniform(0.0, jitter_seconds))
        """,
        target_ip,
        int(port),
        int(sessions),
        int(keepalive_count),
        float(keepalive_interval),
        float(jitter_seconds),
        int(random_seed),
    )


def tcp_scan_command(target, ports, timing, retries, scan_delay_ms=None):
    command = [
        "nmap",
        "-sS",
        "-Pn",
        "-%s" % timing,
        "--max-retries",
        str(int(retries)),
    ]
    if scan_delay_ms is not None:
        command.extend(["--scan-delay", "%sms" % int(scan_delay_ms)])
    command.extend(["-p", str(ports), str(target)])
    return " ".join(shlex.quote(part) for part in command)


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


def blended_stealth_scan_command(
    scan_target,
    scan_ports,
    http_target,
    http_port,
    http_rounds,
    http_spacing_seconds,
    scan_delay_ms,
):
    return (
        "( %s ) & %s; wait"
        % (
            benign_http_command(http_target, http_port, http_rounds, http_spacing_seconds),
            tcp_scan_command(
                scan_target,
                scan_ports,
                "T2",
                0,
                scan_delay_ms=scan_delay_ms,
            ),
        )
    )


def periodic_beacon_like_command(target_ip, port, rounds, pause_seconds, jitter_seconds, random_seed):
    return inline_python_command(
        """
        import random
        import socket
        import sys
        import time

        target_ip = sys.argv[1]
        target_port = int(sys.argv[2])
        rounds = max(1, int(sys.argv[3]))
        pause_seconds = float(sys.argv[4])
        jitter_seconds = max(0.0, float(sys.argv[5]))
        random_seed = int(sys.argv[6])

        jitter = random.Random(random_seed)
        for round_index in range(rounds):
            connection = socket.create_connection((target_ip, target_port), timeout=10)
            connection.settimeout(10)
            payload = ("beacon-%s\\n" % round_index).encode("ascii")
            connection.sendall(payload)
            connection.recv(128)
            connection.close()
            time.sleep(pause_seconds + jitter.uniform(0.0, jitter_seconds))
        """,
        target_ip,
        int(port),
        int(rounds),
        float(pause_seconds),
        float(jitter_seconds),
        int(random_seed),
    )


def lateral_movement_like_command(targets, rounds, pause_seconds, jitter_seconds, random_seed):
    target_arguments = []
    for target_ip, target_port in targets:
        target_arguments.extend([target_ip, int(target_port)])
    return inline_python_command(
        """
        import random
        import socket
        import sys
        import time

        rounds = max(1, int(sys.argv[1]))
        pause_seconds = float(sys.argv[2])
        jitter_seconds = max(0.0, float(sys.argv[3]))
        random_seed = int(sys.argv[4])
        values = sys.argv[5:]
        targets = []
        for index in range(0, len(values), 2):
            targets.append((values[index], int(values[index + 1])))

        jitter = random.Random(random_seed)
        for round_index in range(rounds):
            for target_ip, target_port in targets:
                connection = socket.create_connection((target_ip, target_port), timeout=10)
                connection.settimeout(10)
                payload = ("session-%s-%s\\n" % (round_index, target_port)).encode("ascii")
                connection.sendall(payload)
                connection.recv(128)
                connection.close()
            time.sleep(pause_seconds + jitter.uniform(0.0, jitter_seconds))
        """,
        int(rounds),
        float(pause_seconds),
        float(jitter_seconds),
        int(random_seed),
        *target_arguments
    )


def summarize_scenarios(scenarios):
    label_counts = Counter()
    family_counts = Counter()
    expected_target_counts = Counter()
    variant_examples = {}
    for scenario in scenarios:
        label_counts[scenario.label] += 1
        family_counts[scenario.scenario_family] += 1
        if scenario.expected_detection_target:
            expected_target_counts[scenario.expected_detection_target] += 1
        variant_examples.setdefault(scenario.scenario_family, scenario.scenario_variant)

    print("\nPlanned scenario summary:")
    print("total_scenarios=%s" % len(scenarios))
    print("labels=%s" % dict(sorted(label_counts.items())))
    print("families=%s" % dict(sorted(family_counts.items())))
    if expected_target_counts:
        print("expected_detection_targets=%s" % dict(sorted(expected_target_counts.items())))
    print("example_variants=%s" % dict(sorted(variant_examples.items())))


def build_scenarios(
    collection_id,
    benign_repeats,
    attack_repeats,
    benign_loops,
    flood_count,
    flood_interval_usec,
    collection_profile="balanced",
    benign_concurrency=0,
    benign_jitter_seconds=0.0,
    random_seed=42,
):
    scenarios = []
    profile = profile_settings(collection_profile)

    def default_expected_detection_target(label, scenario_family):
        if label != "malicious":
            return ""
        if scenario_family in (
            "tcp_port_scan_stealth",
            "multi_host_scan_stealth",
        ):
            return "classifier"
        if scenario_family in (
            "blended_stealth_scan",
            "syn_abuse_below_threshold",
        ):
            return "hybrid"
        if scenario_family in (
            "periodic_beacon_like",
            "lateral_movement_like",
        ):
            return "anomaly"
        return "threshold"

    def default_threshold_evasive(label, scenario_family):
        return bool(
            label == "malicious"
            and scenario_family
            in (
                "tcp_port_scan_stealth",
                "multi_host_scan_stealth",
                "blended_stealth_scan",
                "periodic_beacon_like",
                "syn_abuse_below_threshold",
                "lateral_movement_like",
            )
        )

    def default_known_family(label, scenario_family):
        return bool(
            label == "malicious"
            and scenario_family
            in (
                "tcp_port_scan",
                "udp_port_scan",
                "tcp_port_scan_wide",
                "multi_host_scan",
                "icmp_sweep",
                "syn_flood_open_port",
                "syn_flood_failed_connection",
                "tcp_port_scan_stealth",
                "multi_host_scan_stealth",
                "blended_stealth_scan",
                "syn_abuse_below_threshold",
            )
        )

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
        setup_actions=None,
        cleanup_actions=None,
        expected_detection_target=None,
        threshold_evasive=None,
        known_family=None,
        blended_with_benign=None,
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
                expected_detection_target=(
                    expected_detection_target
                    if expected_detection_target is not None
                    else default_expected_detection_target(label, scenario_family)
                ),
                threshold_evasive=(
                    bool(threshold_evasive)
                    if threshold_evasive is not None
                    else default_threshold_evasive(label, scenario_family)
                ),
                known_family=(
                    bool(known_family)
                    if known_family is not None
                    else default_known_family(label, scenario_family)
                ),
                blended_with_benign=bool(blended_with_benign),
                allow_nonzero=allow_nonzero,
                setup_actions=tuple(setup_actions or ()),
                cleanup_actions=tuple(cleanup_actions or ()),
            )
        )

    benign_repeat_count = max(
        0,
        int(benign_repeats) * int(profile.get("benign_repeat_factor", 1)),
    )
    benign_loop_count = max(
        1,
        int(benign_loops) * int(profile.get("benign_loop_multiplier", 1)),
    )
    effective_benign_concurrency = max(
        1,
        int(benign_concurrency or profile.get("default_benign_concurrency", 1)),
    )
    effective_benign_jitter = (
        float(benign_jitter_seconds)
        if float(benign_jitter_seconds or 0.0) > 0.0
        else float(profile.get("default_benign_jitter_seconds", 0.0))
    )
    attack_repeat_count = max(0, int(attack_repeats))

    for repeat_index in range(1, benign_repeat_count + 1):
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
            bursty_burst_size = max(3, benign_loop_count + 1)
            bursty_rounds = 2
            bursty_intra_spacing = 0.5
            bursty_pause_seconds = 20.0
            if profile.get("include_advanced_benign", False):
                bursty_burst_size = min(3, max(2, effective_benign_concurrency))
                bursty_rounds = 1
                bursty_intra_spacing = 1.0
                bursty_pause_seconds = 8.0
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
                    burst_size=bursty_burst_size,
                    rounds=bursty_rounds,
                    intra_spacing=bursty_intra_spacing,
                    pause_seconds=bursty_pause_seconds,
                ),
                src_host="h1",
                dst_host="h2,h5",
                dst_service="10.0.0.2:80/http+10.0.0.5:8080/http-alt",
                duration_seconds=int(
                    (bursty_burst_size * max(0.5, bursty_intra_spacing) * bursty_rounds)
                    + (bursty_pause_seconds * bursty_rounds)
                ),
                rate_parameter="burst_size=%s,pause=%ss"
                % (bursty_burst_size, bursty_pause_seconds),
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

        if profile.get("include_advanced_benign", False):
            primary_filename = "bulk-primary-r%s.bin" % repeat_index
            backup_filename = "bulk-backup-r%s.bin" % repeat_index
            admin_marker = "sdn_benign_admin_%s" % repeat_index
            peer_marker = "sdn_benign_peer_%s" % repeat_index
            udp_marker = "sdn_benign_udp_%s" % repeat_index
            dns_mix_marker = "sdn_benign_dnsmix_%s" % repeat_index
            chat_marker = "sdn_benign_chat_%s" % repeat_index

            add_scenario(
                label="benign",
                scenario_id="benign_browser_mix_h1",
                scenario_family="benign_browser_like_multi_fetch",
                scenario_variant="h1_multi_fetch_h2_80_h5_8080",
                repeat_index=repeat_index,
                host="h1",
                command=benign_browser_like_command(
                    targets=(("10.0.0.2", 80), ("10.0.0.5", 8080)),
                    rounds=max(3, benign_loop_count),
                    think_seconds=1.75,
                    jitter_seconds=effective_benign_jitter,
                    random_seed=int(random_seed) + (repeat_index * 7),
                ),
                src_host="h1",
                dst_host="h2,h5",
                dst_service="10.0.0.2:80/http+10.0.0.5:8080/http-alt",
                duration_seconds=max(3, benign_loop_count) * 2,
                rate_parameter="think=1.75s,jitter=%ss" % effective_benign_jitter,
                concurrency_level=2,
                note="browser_like_multi_fetch_with_think_time",
            )

            add_scenario(
                label="benign",
                scenario_id="benign_service_checks_h3",
                scenario_family="benign_service_checks",
                scenario_variant="h3_periodic_checks_h2_80_h5_8080",
                repeat_index=repeat_index,
                host="h3",
                command=benign_http_polling_command(
                    targets=(("10.0.0.2", 80), ("10.0.0.5", 8080)),
                    rounds=max(4, benign_loop_count),
                    pause_seconds=1.5,
                    jitter_seconds=effective_benign_jitter,
                    random_seed=int(random_seed) + (repeat_index * 11),
                ),
                src_host="h3",
                dst_host="h2,h5",
                dst_service="10.0.0.2:80/http+10.0.0.5:8080/http-alt",
                duration_seconds=max(4, benign_loop_count) * 2,
                rate_parameter="pause=1.5s,jitter=%ss" % effective_benign_jitter,
                concurrency_level=1,
                note="periodic_service_checks",
            )
            add_scenario(
                label="benign",
                scenario_id="benign_bulk_transfer_h1",
                scenario_family="benign_bulk_transfer",
                scenario_variant="h1_http_bulk_download_h2",
                repeat_index=repeat_index,
                host="h1",
                command=benign_http_bulk_command(
                    "10.0.0.2",
                    80,
                    "/%s" % primary_filename,
                    rounds=max(2, benign_loop_count // 2),
                    pause_seconds=2.0,
                    jitter_seconds=effective_benign_jitter,
                    random_seed=int(random_seed) + (repeat_index * 17),
                    parallel_streams=max(1, effective_benign_concurrency - 1),
                ),
                src_host="h1",
                dst_host="h2",
                dst_service="10.0.0.2:80/http-bulk",
                duration_seconds=max(2, benign_loop_count // 2) * 3,
                rate_parameter="parallel_streams=%s,file=768KiB" % max(
                    1,
                    effective_benign_concurrency - 1,
                ),
                concurrency_level=max(1, effective_benign_concurrency - 1),
                note="bulk_transfer_http_download",
                setup_actions=(
                    HostAction(
                        host="h2",
                        command=prepare_http_payload_command("h2", primary_filename, 768),
                        description="prepare_bulk_http_payload_h2",
                    ),
                ),
                cleanup_actions=(
                    HostAction(
                        host="h2",
                        command=remove_http_payload_command("h2", primary_filename),
                        description="cleanup_bulk_http_payload_h2",
                        allow_nonzero=True,
                    ),
                ),
            )
            add_scenario(
                label="benign",
                scenario_id="benign_backup_burst_h4",
                scenario_family="benign_backup_burst",
                scenario_variant="h4_parallel_backup_bursts_h5",
                repeat_index=repeat_index,
                host="h4",
                command=benign_http_bulk_command(
                    "10.0.0.5",
                    8080,
                    "/%s" % backup_filename,
                    rounds=max(2, math.ceil(benign_loop_count / 3.0)),
                    pause_seconds=4.0,
                    jitter_seconds=effective_benign_jitter,
                    random_seed=int(random_seed) + (repeat_index * 23),
                    parallel_streams=max(2, effective_benign_concurrency),
                ),
                src_host="h4",
                dst_host="h5",
                dst_service="10.0.0.5:8080/http-backup",
                duration_seconds=max(2, math.ceil(benign_loop_count / 3.0)) * 5,
                rate_parameter="parallel_streams=%s,file=1024KiB" % max(
                    2,
                    effective_benign_concurrency,
                ),
                concurrency_level=max(2, effective_benign_concurrency),
                note="backup_like_burst_http_download",
                setup_actions=(
                    HostAction(
                        host="h5",
                        command=prepare_http_payload_command("h5", backup_filename, 1024),
                        description="prepare_bulk_http_payload_h5",
                    ),
                ),
                cleanup_actions=(
                    HostAction(
                        host="h5",
                        command=remove_http_payload_command("h5", backup_filename),
                        description="cleanup_bulk_http_payload_h5",
                        allow_nonzero=True,
                    ),
                ),
            )
            add_scenario(
                label="benign",
                scenario_id="benign_admin_session_h1",
                scenario_family="benign_admin_session",
                scenario_variant="h1_to_h2_2222_short_control_sessions",
                repeat_index=repeat_index,
                host="h1",
                command=benign_tcp_session_command(
                    "10.0.0.2",
                    2222,
                    rounds=max(3, benign_loop_count),
                    messages_per_round=max(2, effective_benign_concurrency),
                    pause_seconds=1.5,
                    jitter_seconds=effective_benign_jitter,
                    random_seed=int(random_seed) + (repeat_index * 29),
                ),
                src_host="h1",
                dst_host="h2",
                dst_service="10.0.0.2:2222/admin-sim",
                duration_seconds=max(3, benign_loop_count) * 2,
                rate_parameter="messages_per_round=%s,jitter=%ss"
                % (max(2, effective_benign_concurrency), effective_benign_jitter),
                concurrency_level=1,
                note="ssh_like_admin_control_sessions",
                setup_actions=(
                    HostAction(
                        host="h2",
                        command=benign_tcp_service_start_command(
                            admin_marker,
                            2222,
                            "admin-ok",
                        ),
                        description="start_admin_session_service",
                    ),
                ),
                cleanup_actions=(
                    HostAction(
                        host="h2",
                        command=cleanup_marker_command(admin_marker),
                        description="stop_admin_session_service",
                        allow_nonzero=True,
                    ),
                ),
            )
            add_scenario(
                label="benign",
                scenario_id="benign_dns_then_http_h3",
                scenario_family="benign_dns_then_service_access",
                scenario_variant="h3_udp_lookup_h5_5354_then_http_h2",
                repeat_index=repeat_index,
                host="h3",
                command=benign_dns_then_service_access_command(
                    "10.0.0.5",
                    5354,
                    http_targets=(("10.0.0.2", 80),),
                    rounds=max(3, benign_loop_count),
                    pause_seconds=1.25,
                    jitter_seconds=effective_benign_jitter,
                    random_seed=int(random_seed) + (repeat_index * 31),
                ),
                src_host="h3",
                dst_host="h2,h5",
                dst_service="10.0.0.5:5354/udp-dns-sim+10.0.0.2:80/http",
                duration_seconds=max(3, benign_loop_count) * 2,
                rate_parameter="udp_lookups=2,pause=1.25s,jitter=%ss"
                % effective_benign_jitter,
                concurrency_level=1,
                note="dns_then_service_access_pattern",
                setup_actions=(
                    HostAction(
                        host="h5",
                        command=benign_udp_service_start_command(dns_mix_marker, 5354),
                        description="start_dns_then_http_udp_service",
                    ),
                ),
                cleanup_actions=(
                    HostAction(
                        host="h5",
                        command=cleanup_marker_command(dns_mix_marker),
                        description="stop_dns_then_http_udp_service",
                        allow_nonzero=True,
                    ),
                ),
            )
            add_scenario(
                label="benign",
                scenario_id="benign_udp_rr_h4",
                scenario_family="benign_udp_request_response",
                scenario_variant="h4_to_h5_5353_udp_rr",
                repeat_index=repeat_index,
                host="h4",
                command=benign_udp_request_response_command(
                    "10.0.0.5",
                    5353,
                    rounds=max(4, benign_loop_count),
                    requests_per_round=max(3, effective_benign_concurrency + 1),
                    pause_seconds=1.0,
                    jitter_seconds=effective_benign_jitter,
                    random_seed=int(random_seed) + (repeat_index * 31),
                ),
                src_host="h4",
                dst_host="h5",
                dst_service="10.0.0.5:5353/udp-sim",
                duration_seconds=max(4, benign_loop_count) * 2,
                rate_parameter="requests_per_round=%s,jitter=%ss"
                % (max(3, effective_benign_concurrency + 1), effective_benign_jitter),
                concurrency_level=1,
                note="dns_like_udp_request_response",
                setup_actions=(
                    HostAction(
                        host="h5",
                        command=benign_udp_service_start_command(udp_marker, 5353),
                        description="start_udp_request_response_service",
                    ),
                ),
                cleanup_actions=(
                    HostAction(
                        host="h5",
                        command=cleanup_marker_command(udp_marker),
                        description="stop_udp_request_response_service",
                        allow_nonzero=True,
                    ),
                ),
            )
            add_scenario(
                label="benign",
                scenario_id="benign_chat_keepalive_h4",
                scenario_family="benign_chat_keepalive",
                scenario_variant="h4_to_h2_5222_keepalive_session",
                repeat_index=repeat_index,
                host="h4",
                command=benign_chat_keepalive_command(
                    "10.0.0.2",
                    5222,
                    sessions=max(2, benign_loop_count),
                    keepalive_count=max(4, effective_benign_concurrency + 2),
                    keepalive_interval=0.8,
                    jitter_seconds=effective_benign_jitter,
                    random_seed=int(random_seed) + (repeat_index * 33),
                ),
                src_host="h4",
                dst_host="h2",
                dst_service="10.0.0.2:5222/chat-sim",
                duration_seconds=max(2, benign_loop_count) * 4,
                rate_parameter="keepalive_interval=0.8s,jitter=%ss"
                % effective_benign_jitter,
                concurrency_level=1,
                note="chat_like_persistent_keepalive_session",
                setup_actions=(
                    HostAction(
                        host="h2",
                        command=benign_persistent_tcp_service_start_command(
                            chat_marker,
                            5222,
                            "chat-ok",
                        ),
                        description="start_chat_keepalive_service",
                    ),
                ),
                cleanup_actions=(
                    HostAction(
                        host="h2",
                        command=cleanup_marker_command(chat_marker),
                        description="stop_chat_keepalive_service",
                        allow_nonzero=True,
                    ),
                ),
            )
            add_scenario(
                label="benign",
                scenario_id="benign_peer_sync_h3",
                scenario_family="benign_peer_sync",
                scenario_variant="h3_to_h4_9091_sync_sessions",
                repeat_index=repeat_index,
                host="h3",
                command=benign_tcp_session_command(
                    "10.0.0.4",
                    9091,
                    rounds=max(3, benign_loop_count),
                    messages_per_round=max(3, effective_benign_concurrency + 1),
                    pause_seconds=1.0,
                    jitter_seconds=effective_benign_jitter,
                    random_seed=int(random_seed) + (repeat_index * 37),
                ),
                src_host="h3",
                dst_host="h4",
                dst_service="10.0.0.4:9091/internal-sync",
                duration_seconds=max(3, benign_loop_count) * 2,
                rate_parameter="messages_per_round=%s,jitter=%ss"
                % (max(3, effective_benign_concurrency + 1), effective_benign_jitter),
                concurrency_level=1,
                note="peer_to_peer_internal_sync",
                setup_actions=(
                    HostAction(
                        host="h4",
                        command=benign_tcp_service_start_command(
                            peer_marker,
                            9091,
                            "sync-ok",
                        ),
                        description="start_peer_sync_service",
                    ),
                ),
                cleanup_actions=(
                    HostAction(
                        host="h4",
                        command=cleanup_marker_command(peer_marker),
                        description="stop_peer_sync_service",
                        allow_nonzero=True,
                    ),
                ),
            )

    for repeat_index in range(1, attack_repeat_count + 1):
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

            if profile.get("include_layered_eval_scenarios", False):
                beacon_marker = "sdn_eval_beacon_%s_%s" % (repeat_index, sequence)
                lateral_h2_marker = "sdn_eval_lateral_h2_%s_%s" % (repeat_index, sequence)
                lateral_h4_marker = "sdn_eval_lateral_h4_%s_%s" % (repeat_index, sequence)

                add_scenario(
                    label="malicious",
                    scenario_id="attack_tcp_scan_stealth_h3",
                    scenario_family="tcp_port_scan_stealth",
                    scenario_variant="h3_to_h2_ports_22_23_80_delay_1600ms",
                    repeat_index=repeat_index,
                    host="h3",
                    command=tcp_scan_command(
                        "10.0.0.2",
                        "22,23,80",
                        "T2",
                        0,
                        scan_delay_ms=1600,
                    ),
                    src_host="h3",
                    dst_host="h2",
                    dst_service="10.0.0.2:22,23,80/tcp",
                    duration_seconds=8,
                    rate_parameter="timing=T2,scan_delay_ms=1600,retries=0",
                    concurrency_level=1,
                    note="low_and_slow_tcp_port_scan",
                    sequence=sequence,
                    expected_detection_target="classifier",
                    threshold_evasive=True,
                    known_family=True,
                )
                add_scenario(
                    label="malicious",
                    scenario_id="attack_host_scan_stealth_h3",
                    scenario_family="multi_host_scan_stealth",
                    scenario_variant="h3_to_10_0_0_2_4_port_22_delay_1800ms",
                    repeat_index=repeat_index,
                    host="h3",
                    command=tcp_scan_command(
                        "10.0.0.2-4",
                        "22",
                        "T2",
                        0,
                        scan_delay_ms=1800,
                    ),
                    src_host="h3",
                    dst_host="10.0.0.2-4",
                    dst_service="10.0.0.2-4:22/tcp",
                    duration_seconds=8,
                    rate_parameter="timing=T2,scan_delay_ms=1800,retries=0",
                    concurrency_level=1,
                    note="low_and_slow_multi_host_scan",
                    sequence=sequence,
                    expected_detection_target="classifier",
                    threshold_evasive=True,
                    known_family=True,
                )
                add_scenario(
                    label="malicious",
                    scenario_id="attack_blended_stealth_scan_h1",
                    scenario_family="blended_stealth_scan",
                    scenario_variant="h1_http_h5_while_scanning_h2_ports_22_23_80",
                    repeat_index=repeat_index,
                    host="h1",
                    command=blended_stealth_scan_command(
                        scan_target="10.0.0.2",
                        scan_ports="22,23,80",
                        http_target="10.0.0.5",
                        http_port=8080,
                        http_rounds=max(2, benign_loop_count),
                        http_spacing_seconds=3.0,
                        scan_delay_ms=1800,
                    ),
                    src_host="h1",
                    dst_host="h2,h5",
                    dst_service="10.0.0.2:22,23,80/tcp+10.0.0.5:8080/http-alt",
                    duration_seconds=max(8, benign_loop_count * 3),
                    rate_parameter="scan_delay_ms=1800,http_spacing=3.0s",
                    concurrency_level=2,
                    note="benign_http_blended_with_stealth_scan",
                    sequence=sequence,
                    expected_detection_target="hybrid",
                    threshold_evasive=True,
                    known_family=True,
                    blended_with_benign=True,
                )
                add_scenario(
                    label="malicious",
                    scenario_id="attack_periodic_beacon_h1",
                    scenario_family="periodic_beacon_like",
                    scenario_variant="h1_to_h4_9443_rounds_6_pause_6s",
                    repeat_index=repeat_index,
                    host="h1",
                    command=periodic_beacon_like_command(
                        "10.0.0.4",
                        9443,
                        rounds=6,
                        pause_seconds=6.0,
                        jitter_seconds=max(0.5, effective_benign_jitter),
                        random_seed=int(random_seed) + (repeat_index * 41) + sequence,
                    ),
                    src_host="h1",
                    dst_host="h4",
                    dst_service="10.0.0.4:9443/beacon-sim",
                    duration_seconds=36,
                    rate_parameter="pause=6.0s,jitter=%ss"
                    % max(0.5, effective_benign_jitter),
                    concurrency_level=1,
                    note="periodic_low_and_slow_beacon_like_activity",
                    sequence=sequence,
                    setup_actions=(
                        HostAction(
                            host="h4",
                            command=benign_tcp_service_start_command(
                                beacon_marker,
                                9443,
                                "beacon-ok",
                            ),
                            description="start_beacon_like_service",
                        ),
                    ),
                    cleanup_actions=(
                        HostAction(
                            host="h4",
                            command=cleanup_marker_command(beacon_marker),
                            description="stop_beacon_like_service",
                            allow_nonzero=True,
                        ),
                    ),
                    expected_detection_target="anomaly",
                    threshold_evasive=True,
                    known_family=False,
                )
                add_scenario(
                    label="malicious",
                    scenario_id="attack_syn_abuse_below_threshold_h4",
                    scenario_family="syn_abuse_below_threshold",
                    scenario_variant="h4_to_h2_81_count_6_interval_700000",
                    repeat_index=repeat_index,
                    host="h4",
                    command=syn_flood_command("10.0.0.2", 81, 6, 700000),
                    src_host="h4",
                    dst_host="h2",
                    dst_service="10.0.0.2:81/closed",
                    duration_seconds=5,
                    rate_parameter="count=6,interval_usec=700000",
                    concurrency_level=1,
                    note="sub_threshold_syn_abuse_closed_port",
                    allow_nonzero=True,
                    sequence=sequence,
                    expected_detection_target="hybrid",
                    threshold_evasive=True,
                    known_family=True,
                )
                add_scenario(
                    label="malicious",
                    scenario_id="attack_lateral_movement_h3",
                    scenario_family="lateral_movement_like",
                    scenario_variant="h3_to_h2_2223_h4_9092_rounds_3",
                    repeat_index=repeat_index,
                    host="h3",
                    command=lateral_movement_like_command(
                        targets=(("10.0.0.2", 2223), ("10.0.0.4", 9092)),
                        rounds=3,
                        pause_seconds=3.0,
                        jitter_seconds=max(0.5, effective_benign_jitter),
                        random_seed=int(random_seed) + (repeat_index * 43) + sequence,
                    ),
                    src_host="h3",
                    dst_host="h2,h4",
                    dst_service="10.0.0.2:2223/admin-sim+10.0.0.4:9092/internal-sync",
                    duration_seconds=10,
                    rate_parameter="rounds=3,pause=3.0s,jitter=%ss"
                    % max(0.5, effective_benign_jitter),
                    concurrency_level=1,
                    note="low_rate_lateral_movement_like_internal_sessions",
                    sequence=sequence,
                    setup_actions=(
                        HostAction(
                            host="h2",
                            command=benign_tcp_service_start_command(
                                lateral_h2_marker,
                                2223,
                                "ops-ok",
                            ),
                            description="start_lateral_service_h2",
                        ),
                        HostAction(
                            host="h4",
                            command=benign_tcp_service_start_command(
                                lateral_h4_marker,
                                9092,
                                "sync-ok",
                            ),
                            description="start_lateral_service_h4",
                        ),
                    ),
                    cleanup_actions=(
                        HostAction(
                            host="h4",
                            command=cleanup_marker_command(lateral_h4_marker),
                            description="stop_lateral_service_h4",
                            allow_nonzero=True,
                        ),
                        HostAction(
                            host="h2",
                            command=cleanup_marker_command(lateral_h2_marker),
                            description="stop_lateral_service_h2",
                            allow_nonzero=True,
                        ),
                    ),
                    expected_detection_target="anomaly",
                    threshold_evasive=True,
                    known_family=False,
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
                benign_concurrency=args.benign_concurrency,
                benign_jitter_seconds=args.benign_jitter_seconds,
                random_seed=args.random_seed,
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
                try:
                    for action in scenario.setup_actions:
                        run_host_action(action)

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
                        expected_detection_target=scenario.expected_detection_target,
                        threshold_evasive=scenario.threshold_evasive,
                        known_family=scenario.known_family,
                        blended_with_benign=scenario.blended_with_benign,
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
                    for action in reversed(scenario.cleanup_actions):
                        safe_cleanup_action(action)
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
