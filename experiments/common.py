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


def default_modes(ml_model_path):
    return {
        "dynamic_enforcement": EvaluationMode(
            name="dynamic_enforcement",
            title="SDN Dynamic Firewall/IDS Enforcement",
            description="Threshold-based IDS with automatic SDN mitigation enabled.",
            env={
                "SDN_IDS_ENABLED": "true",
                "SDN_ML_ENABLED": "false",
                "SDN_MITIGATION_ENABLED": "true",
            },
            mitigation_enabled=True,
        ),
        "static_firewall": EvaluationMode(
            name="static_firewall",
            title="Traditional Static Firewall",
            description="Only the static firewall policy is active; IDS and ML are disabled.",
            env={
                "SDN_IDS_ENABLED": "false",
                "SDN_ML_ENABLED": "false",
                "SDN_MITIGATION_ENABLED": "true",
            },
            mitigation_enabled=True,
        ),
        "threshold_ids": EvaluationMode(
            name="threshold_ids",
            title="Threshold-Based IDS",
            description="Threshold IDS alerts are active but automatic mitigation is disabled.",
            env={
                "SDN_IDS_ENABLED": "true",
                "SDN_ML_ENABLED": "false",
                "SDN_MITIGATION_ENABLED": "false",
            },
            mitigation_enabled=False,
        ),
        "ml_enhanced_ids": EvaluationMode(
            name="ml_enhanced_ids",
            title="ML-Enhanced IDS",
            description="Threshold baseline plus hybrid ML IDS with the configured runtime model.",
            env={
                "SDN_IDS_ENABLED": "true",
                "SDN_ML_ENABLED": "true",
                "SDN_ML_MODE": "hybrid",
                "SDN_ML_MODEL_PATH": ml_model_path,
                "SDN_MITIGATION_ENABLED": "true",
            },
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
            command="/workspace/ryu-apps/traffic/benign_traffic.sh 10.0.0.2 80",
            description="Normal client traffic to the primary server.",
            source_ip="10.0.0.1",
            allow_nonzero=False,
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


def _topology_runtime():
    try:
        return json.loads(topology_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def recreate_controller(mode, timeout_seconds=25.0):
    restart_started_at = time.time()
    compose(
        ["up", "-d", "--force-recreate", "controller"],
        env=mode.env,
    )
    wait_for_controller_ready(restart_started_at, timeout_seconds)


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
