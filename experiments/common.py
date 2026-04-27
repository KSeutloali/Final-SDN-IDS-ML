"""Shared helpers for repeatable SDN evaluation runs."""

from __future__ import print_function

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from core.command_queue import ControllerCommandQueue
from core.ids_mode import IDSModeStateStore, normalize_ids_mode_public
from scripts.collect_runtime_dataset import (
    blended_stealth_scan_command,
    periodic_beacon_like_command,
    syn_flood_command,
    tcp_scan_command,
)


@dataclass(frozen=True)
class EvaluationMode(object):
    """One controller configuration used during comparison."""

    name: str
    title: str
    description: str
    env: dict
    mitigation_enabled: bool

    def to_dict(self):
        payload = asdict(self)
        payload["env"] = dict(self.env)
        return payload


@dataclass(frozen=True)
class EvaluationScenario(object):
    """One traffic or attack scenario used during comparison."""

    name: str
    title: str
    label: str
    host: str
    command: str
    description: str
    source_ip: str
    allow_nonzero: bool = False
    warmup_targets: tuple = ()
    scenario_family: str = ""
    expected_detection_target: str = ""
    threshold_evasive: bool = False
    known_family: bool = False
    blended_with_benign: bool = False

    def to_dict(self):
        return asdict(self)


def project_root():
    return Path(__file__).resolve().parents[1]


def topology_state_path():
    return project_root() / "runtime" / "mininet_runtime.json"


def results_root(default_name=None):
    root = project_root() / "experiments" / "results"
    root.mkdir(parents=True, exist_ok=True)
    if default_name:
        target = root / default_name
        target.mkdir(parents=True, exist_ok=True)
        return target
    return root


def utc_now():
    return datetime.now(timezone.utc)


def utc_slug():
    return utc_now().strftime("%Y%m%d_%H%M%S")


def isoformat_utc(value=None):
    if value is None:
        return utc_now().isoformat()
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc).isoformat()
        return value.astimezone(timezone.utc).isoformat()
    return datetime.fromtimestamp(float(value), timezone.utc).isoformat()


def print_command(command):
    printable = " ".join(shlex.quote(str(part)) for part in command)
    print("+ %s" % printable)


def run(command, env=None, capture_output=False, check=True, cwd=None):
    print_command(command)
    effective_env = None
    if env is not None:
        effective_env = dict(os.environ)
        effective_env.update(env)
    completed = subprocess.run(
        [str(part) for part in command],
        cwd=str(cwd or project_root()),
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
    return run(
        ["docker", "compose"] + list(command),
        env=env,
        capture_output=capture_output,
        check=check,
    )


def parse_kv_lines(output_text):
    parsed = {}
    for raw_line in (output_text or "").splitlines():
        line = raw_line.strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _mode_env(
    *,
    ids_enabled,
    ml_enabled,
    mitigation_enabled,
    ids_mode=None,
    inference_mode=None,
    mode_state_path="",
    ml_model_path="",
    anomaly_model_path="",
    hybrid_policy=None,
    extra_env=None,
):
    env = {
        "SDN_IDS_ENABLED": "true" if ids_enabled else "false",
        "SDN_ML_ENABLED": "true" if ml_enabled else "false",
        "SDN_MITIGATION_ENABLED": "true" if mitigation_enabled else "false",
    }
    if ids_mode:
        env["SDN_IDS_MODE"] = ids_mode
    if inference_mode:
        env["SDN_ML_INFERENCE_MODE"] = inference_mode
    if mode_state_path:
        env["SDN_IDS_MODE_STATE_PATH"] = mode_state_path
    if ml_model_path:
        env["SDN_ML_MODEL_PATH"] = ml_model_path
    if anomaly_model_path:
        env["SDN_ML_ANOMALY_MODEL_PATH"] = anomaly_model_path
    if hybrid_policy:
        env["SDN_ML_HYBRID_POLICY"] = hybrid_policy
    if extra_env:
        env.update({str(key): str(value) for key, value in dict(extra_env).items()})
    return env


def default_modes(ml_model_path, anomaly_model_path=""):
    mode_state_path = "runtime/ids_mode_state_experiments.json"
    return {
        "dynamic_enforcement": EvaluationMode(
            name="dynamic_enforcement",
            title="SDN Dynamic Firewall/IDS Enforcement",
            description="Threshold-based IDS with automatic SDN mitigation enabled.",
            env=_mode_env(
                ids_enabled=True,
                ml_enabled=False,
                mitigation_enabled=True,
                mode_state_path=mode_state_path,
            ),
            mitigation_enabled=True,
        ),
        "static_firewall": EvaluationMode(
            name="static_firewall",
            title="Traditional Static Firewall",
            description="Only the static firewall policy is active; IDS and ML are disabled.",
            env=_mode_env(
                ids_enabled=False,
                ml_enabled=False,
                mitigation_enabled=True,
                mode_state_path=mode_state_path,
            ),
            mitigation_enabled=True,
        ),
        "threshold_ids": EvaluationMode(
            name="threshold_ids",
            title="Threshold-Based IDS",
            description="Threshold IDS alerts are active but automatic mitigation is disabled.",
            env=_mode_env(
                ids_enabled=True,
                ml_enabled=False,
                mitigation_enabled=False,
                mode_state_path=mode_state_path,
            ),
            mitigation_enabled=False,
        ),
        "ml_enhanced_ids": EvaluationMode(
            name="ml_enhanced_ids",
            title="ML-Enhanced IDS",
            description="Threshold baseline plus hybrid ML IDS with the configured runtime model.",
            env=_mode_env(
                ids_enabled=True,
                ml_enabled=True,
                mitigation_enabled=True,
                ids_mode="hybrid",
                inference_mode="combined",
                mode_state_path=mode_state_path,
                ml_model_path=ml_model_path,
                anomaly_model_path=anomaly_model_path,
                hybrid_policy="layered_consensus",
            ),
            mitigation_enabled=True,
        ),
        "threshold_only": EvaluationMode(
            name="threshold_only",
            title="Threshold IDS Only",
            description="Deterministic threshold IDS only, with mitigation disabled for clean detection comparison.",
            env=_mode_env(
                ids_enabled=True,
                ml_enabled=False,
                mitigation_enabled=False,
                mode_state_path=mode_state_path,
            ),
            mitigation_enabled=False,
        ),
        "classifier_only": EvaluationMode(
            name="classifier_only",
            title="Classifier Only",
            description="Supervised ML detection only, with threshold IDS disabled and mitigation disabled.",
            env=_mode_env(
                ids_enabled=False,
                ml_enabled=True,
                mitigation_enabled=False,
                ids_mode="ml",
                inference_mode="classifier_only",
                mode_state_path=mode_state_path,
                ml_model_path=ml_model_path,
                anomaly_model_path=anomaly_model_path,
            ),
            mitigation_enabled=False,
        ),
        "anomaly_only": EvaluationMode(
            name="anomaly_only",
            title="Anomaly Only",
            description="Isolation Forest anomaly detection only, with mitigation disabled for alert-quality comparison.",
            env=_mode_env(
                ids_enabled=False,
                ml_enabled=True,
                mitigation_enabled=False,
                ids_mode="ml",
                inference_mode="anomaly_only",
                mode_state_path=mode_state_path,
                ml_model_path=ml_model_path,
                anomaly_model_path=anomaly_model_path,
            ),
            mitigation_enabled=False,
        ),
        "hybrid": EvaluationMode(
            name="hybrid",
            title="Layered Hybrid IDS",
            description="Threshold-first hybrid IDS using both supervised and anomaly-aware ML, with mitigation disabled for comparison.",
            env=_mode_env(
                ids_enabled=True,
                ml_enabled=True,
                mitigation_enabled=False,
                ids_mode="hybrid",
                inference_mode="combined",
                mode_state_path=mode_state_path,
                ml_model_path=ml_model_path,
                anomaly_model_path=anomaly_model_path,
                hybrid_policy="layered_consensus",
            ),
            mitigation_enabled=False,
        ),
        "hybrid_blocking": EvaluationMode(
            name="hybrid_blocking",
            title="Layered Hybrid IPS",
            description=(
                "Threshold-first hybrid IDS/IPS with controlled ML-assisted blocking "
                "enabled, including strict anomaly-only escalation."
            ),
            env=_mode_env(
                ids_enabled=True,
                ml_enabled=True,
                mitigation_enabled=True,
                ids_mode="hybrid",
                inference_mode="combined",
                mode_state_path=mode_state_path,
                ml_model_path=ml_model_path,
                anomaly_model_path=anomaly_model_path,
                hybrid_policy="layered_consensus",
                extra_env={
                    "SDN_ML_HYBRID_ANOMALY_ONLY_BLOCK_ENABLED": "true",
                    "SDN_ML_HYBRID_ANOMALY_ONLY_BLOCK_THRESHOLD": "0.75",
                },
            ),
            mitigation_enabled=True,
        ),
    }


def default_scenarios(flood_count=1200, hping_interval_usec=1000):
    return {
        "benign": EvaluationScenario(
            name="benign",
            title="Benign HTTP and ICMP",
            label="benign",
            host="h1",
            command="sh /workspace/ryu-apps/traffic/benign_traffic.sh 10.0.0.2 80",
            description="Normal client traffic to the primary server.",
            source_ip="10.0.0.1",
            allow_nonzero=False,
            warmup_targets=("10.0.0.2",),
            scenario_family="benign_background",
        ),
        "port_scan": EvaluationScenario(
            name="port_scan",
            title="TCP SYN Port Scan",
            label="malicious",
            host="h3",
            command="/workspace/ryu-apps/attacks/port_scan.sh 10.0.0.2",
            description="High-rate TCP SYN probe against multiple destination ports.",
            source_ip="10.0.0.3",
            allow_nonzero=False,
            warmup_targets=("10.0.0.2",),
            scenario_family="tcp_port_scan",
            expected_detection_target="threshold",
            known_family=True,
        ),
        "dos": EvaluationScenario(
            name="dos",
            title="SYN Flood / DoS",
            label="malicious",
            host="h3",
            command=(
                "SDN_HPING_INTERVAL_USEC={interval} "
                "/workspace/ryu-apps/attacks/dos_flood.sh 10.0.0.2 80 {count}"
            ).format(interval=hping_interval_usec, count=flood_count),
            description="Repeated SYN flood against the primary HTTP service.",
            source_ip="10.0.0.3",
            allow_nonzero=True,
            warmup_targets=("10.0.0.2",),
            scenario_family="syn_flood_open_port",
            expected_detection_target="threshold",
            known_family=True,
        ),
        "threshold_syn_flood_h4": EvaluationScenario(
            name="threshold_syn_flood_h4",
            title="Threshold SYN Flood",
            label="malicious",
            host="h4",
            command=syn_flood_command(
                "10.0.0.5",
                8080,
                packet_count=max(400, int(flood_count)),
                interval_usec=hping_interval_usec,
            ),
            description="Obvious SYN flood on the stable h4 to h5 path for threshold-authoritative validation.",
            source_ip="10.0.0.4",
            allow_nonzero=True,
            warmup_targets=("10.0.0.5",),
            scenario_family="syn_flood_open_port",
            expected_detection_target="threshold",
            known_family=True,
        ),
        "stealth_scan_h1": EvaluationScenario(
            name="stealth_scan_h1",
            title="Stealth TCP Scan",
            label="malicious",
            host="h1",
            command=tcp_scan_command(
                "10.0.0.5",
                "22,80,443,8080",
                "T2",
                0,
                scan_delay_ms=1200,
            ),
            description="Low-and-slow TCP scan intended to stay below the threshold recon cutoffs.",
            source_ip="10.0.0.1",
            allow_nonzero=False,
            warmup_targets=("10.0.0.5",),
            scenario_family="tcp_port_scan_stealth",
            expected_detection_target="classifier",
            threshold_evasive=True,
            known_family=True,
        ),
        "blended_stealth_scan_h1": EvaluationScenario(
            name="blended_stealth_scan_h1",
            title="Blended Stealth Scan",
            label="malicious",
            host="h1",
            command=blended_stealth_scan_command(
                scan_target="10.0.0.5",
                scan_ports="22,80,443,8080",
                http_target="10.0.0.2",
                http_port=80,
                http_rounds=2,
                http_spacing_seconds=1.5,
                scan_delay_ms=1200,
            ),
            description="Benign-looking HTTP traffic blended with a low-rate stealth scan to test hybrid enrichment.",
            source_ip="10.0.0.1",
            allow_nonzero=False,
            warmup_targets=("10.0.0.2", "10.0.0.5"),
            scenario_family="blended_stealth_scan",
            expected_detection_target="hybrid",
            threshold_evasive=True,
            known_family=True,
            blended_with_benign=True,
        ),
        "periodic_beacon_h4": EvaluationScenario(
            name="periodic_beacon_h4",
            title="Periodic Beacon-Like Traffic",
            label="malicious",
            host="h4",
            command=periodic_beacon_like_command(
                "10.0.0.5",
                8080,
                rounds=8,
                pause_seconds=2.5,
                jitter_seconds=0.5,
                random_seed=17,
            ),
            description="Low-rate periodic internal callbacks intended to be subtle for threshold and more anomaly-oriented for ML.",
            source_ip="10.0.0.4",
            allow_nonzero=False,
            warmup_targets=("10.0.0.5",),
            scenario_family="periodic_beacon_like",
            expected_detection_target="anomaly",
            threshold_evasive=True,
        ),
    }


def ensure_topology_running():
    runtime_state = _topology_runtime()
    topology_pid = runtime_state.get("topology_pid")
    if runtime_state.get("active") and topology_pid:
        result = compose(
            ["exec", "mininet", "sh", "-lc", "kill -0 %s" % int(topology_pid)],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            return

    result = compose(
        ["exec", "mininet", "sh", "-lc", "pgrep -af '[c]ustom_topology.py|[t]opology.custom_topology'"],
        capture_output=True,
        check=False,
    )
    if result.returncode == 0 and result.stdout.strip():
        return

    print(
        "No running Mininet topology found. Start it with ./scripts/run_topology.sh first.",
        file=sys.stderr,
    )
    raise SystemExit(1)


def mininet_host_pid(host_name):
    runtime_state = _topology_runtime()
    runtime_pid = (runtime_state.get("host_pids") or {}).get(host_name)
    if runtime_state.get("active") and runtime_pid:
        result = compose(
            ["exec", "mininet", "sh", "-lc", "kill -0 %s" % int(runtime_pid)],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            return str(runtime_pid)

    result = compose(
        ["exec", "mininet", "sh", "-lc", "pgrep -fo '[m]ininet:%s'" % host_name],
        capture_output=True,
        check=False,
    )
    pid = result.stdout.strip()
    if not pid:
        print("Could not find a running Mininet shell for %s." % host_name, file=sys.stderr)
        raise SystemExit(1)
    return pid


def run_on_host(host_name, command, capture_output=True, check=True):
    pid = mininet_host_pid(host_name)
    return compose(
        ["exec", "mininet", "mnexec", "-a", pid, "sh", "-lc", command],
        capture_output=capture_output,
        check=check,
    )


def wait_for_host_connectivity(
    host_name,
    target_ip,
    timeout_seconds=12.0,
    runner=None,
    sleep_fn=None,
):
    """Wait until one Mininet host can reach a target IP."""

    runner = runner or run_on_host
    sleep_fn = sleep_fn or time.sleep
    deadline = time.time() + max(1.0, float(timeout_seconds))
    command = "ping -c 1 -W 1 %s >/dev/null 2>&1" % str(target_ip)
    while time.time() < deadline:
        result = runner(host_name, command, capture_output=True, check=False)
        if result.returncode == 0:
            return True
        sleep_fn(0.5)
    return False


def warmup_scenario_connectivity(scenario, timeout_seconds=12.0, runner=None, sleep_fn=None):
    """Prime connectivity for a scenario before measurements begin."""

    for target_ip in tuple(getattr(scenario, "warmup_targets", ()) or ()):
        reachable = wait_for_host_connectivity(
            scenario.host,
            target_ip,
            timeout_seconds=timeout_seconds,
            runner=runner,
            sleep_fn=sleep_fn,
        )
        if not reachable:
            raise SystemExit(
                "Timed out waiting for %s to reach %s before scenario %s."
                % (scenario.host, target_ip, scenario.name)
            )


def _topology_runtime():
    try:
        return json.loads(topology_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def expected_public_mode(mode):
    return normalize_ids_mode_public(
        getattr(mode, "env", {}).get("SDN_IDS_MODE", "threshold"),
        default="threshold",
    )


def clear_pending_controller_commands(root_path=None):
    """Remove stale dashboard/controller commands before a deterministic evaluation run."""

    root = Path(root_path) if root_path is not None else project_root() / "runtime" / "controller_commands"
    pending_path = root / "pending"
    if not pending_path.exists():
        return 0

    removed = 0
    for command_path in pending_path.glob("*.json"):
        try:
            command_path.unlink()
            removed += 1
        except OSError:
            continue
    return removed


def sync_controller_mode_state(mode, state_store=None):
    """Keep the persisted IDS mode aligned with the evaluation mode being launched."""

    state_path = getattr(mode, "env", {}).get(
        "SDN_IDS_MODE_STATE_PATH",
        "runtime/ids_mode_state.json",
    )
    state_store = state_store or IDSModeStateStore(project_root() / state_path)
    public_mode = expected_public_mode(mode)
    return state_store.persist(
        public_mode,
        effective_mode=public_mode,
        requested_by="evaluation_runner",
        previous_mode=None,
    )


def ensure_controller_mode(mode, timeout_seconds=10.0, state_reader=None, command_queue=None, sleep_fn=None):
    """Use the runtime command queue to force the controller into the requested mode."""

    desired_mode = expected_public_mode(mode)
    state_reader = state_reader or dashboard_state
    command_queue = command_queue or ControllerCommandQueue()
    sleep_fn = sleep_fn or time.sleep
    deadline = time.time() + max(1.0, float(timeout_seconds))
    command = None

    while time.time() < deadline:
        payload = dict(state_reader() or {})
        ml_status = dict(payload.get("ml_status") or {})
        selected_mode = normalize_ids_mode_public(
            ml_status.get("selected_mode_api") or ml_status.get("selected_mode") or desired_mode,
            default=desired_mode,
        )
        if selected_mode == desired_mode:
            return payload

        if command is None:
            command = command_queue.enqueue(
                "set_ids_mode",
                {
                    "mode": desired_mode,
                    "requested_by": "evaluation_runner",
                },
            )
        sleep_fn(0.5)

    raise SystemExit(
        "Controller did not switch to %s mode within %.1f seconds."
        % (desired_mode, timeout_seconds)
    )


def recreate_controller(mode, timeout_seconds=25.0):
    restart_started_at = time.time()
    clear_pending_controller_commands()
    sync_controller_mode_state(mode)
    clear_switch_flow_state()
    _restart_controller_service(mode)
    wait_for_controller_ready(restart_started_at, timeout_seconds)
    ensure_controller_mode(
        mode,
        timeout_seconds=max(2.0, min(float(timeout_seconds), 10.0)),
    )


def _restart_controller_service(mode, compose_runner=None, sleep_fn=None, max_attempts=3):
    compose_runner = compose_runner or compose
    sleep_fn = sleep_fn or time.sleep
    last_result = None
    for attempt in range(1, max(1, int(max_attempts)) + 1):
        result = compose_runner(
            ["up", "-d", "--force-recreate", "controller"],
            env=mode.env,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            return result
        last_result = result
        combined_output = "%s\n%s" % (result.stdout or "", result.stderr or "")
        if (
            "Conflict. The container name" not in combined_output
            and "name is already in use" not in combined_output
        ) or attempt >= max_attempts:
            if result.stdout:
                sys.stdout.write(result.stdout)
            if result.stderr:
                sys.stderr.write(result.stderr)
            raise SystemExit(result.returncode or 1)
        sleep_fn(1.0)
    raise SystemExit(getattr(last_result, "returncode", 1) or 1)


def clear_switch_flow_state(compose_runner=None):
    compose_runner = compose_runner or compose
    result = compose_runner(
        [
            "exec",
            "mininet",
            "sh",
            "-lc",
            "for br in $(ovs-vsctl list-br); do ovs-ofctl -O OpenFlow13 del-flows \"$br\"; done",
        ],
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        return result
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    raise SystemExit(result.returncode or 1)


def wait_for_controller_ready(restart_started_at, timeout_seconds=25.0, min_switches=1):
    state_path = project_root() / "runtime" / "dashboard_state.json"
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            payload = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            time.sleep(0.5)
            continue
        generated_at = float(payload.get("generated_at_epoch") or 0.0)
        active_switches = int(payload.get("summary", {}).get("active_switches") or 0)
        if generated_at >= restart_started_at and active_switches >= min_switches:
            return payload
        time.sleep(0.5)
    raise SystemExit("Controller did not become ready within %.1f seconds." % timeout_seconds)


def dashboard_state():
    state_path = project_root() / "runtime" / "dashboard_state.json"
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def controller_logs_since(start_iso, end_iso=None):
    command = ["logs", "--no-color", "--since", start_iso]
    if end_iso:
        command.extend(["--until", end_iso])
    command.append("controller")
    return compose(command, capture_output=True).stdout


def start_capture_session(scenario_name, capture_interfaces=None):
    command = ["./scripts/start_captures.sh", scenario_name]
    if capture_interfaces:
        command.append(capture_interfaces)
    result = run(command, capture_output=True)
    parsed = parse_kv_lines(result.stdout)
    return {
        "session_name": parsed.get("capture_session", ""),
        "capture_dir": parsed.get("capture_dir", ""),
        "stdout": result.stdout,
    }


def stop_capture_session(session_name=None):
    command = ["./scripts/stop_captures.sh"]
    if session_name:
        command.append(session_name)
    result = run(command, capture_output=True, check=False)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    parsed = parse_kv_lines(result.stdout)
    files = [line for line in lines if line.endswith(".pcap")]
    return {
        "session_name": parsed.get("capture_session", session_name or ""),
        "files": files,
        "stdout": result.stdout,
        "returncode": result.returncode,
    }


def capture_session_details(session_name):
    if not session_name:
        return {"session_name": "", "files": [], "status": "inactive"}

    session_dir = project_root() / "captures" / "output" / session_name
    notes_path = session_dir / "capture_session.txt"
    metadata = {
        "session_name": session_name,
        "session_dir": str(session_dir.relative_to(project_root())) if session_dir.exists() else "",
        "files": [],
        "status": "inactive",
    }
    if notes_path.exists():
        notes = parse_kv_lines(notes_path.read_text(encoding="utf-8"))
        metadata.update(notes)
    if session_dir.exists():
        file_rows = []
        total_size = 0
        for capture_path in sorted(session_dir.glob("*.pcap")):
            stat = capture_path.stat()
            total_size += stat.st_size
            file_rows.append(
                {
                    "name": capture_path.name,
                    "path": str(capture_path.relative_to(project_root())),
                    "size_bytes": stat.st_size,
                    "modified_at": isoformat_utc(stat.st_mtime),
                }
            )
        metadata["files"] = file_rows
        metadata["total_size_bytes"] = total_size
        metadata["file_count"] = len(file_rows)
    return metadata


def write_json(path, payload):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
