"""Custom multi-switch Mininet topology for the SDN security testbed."""

import argparse
import json
import os
from pathlib import Path
import sys
import threading
import time
from functools import partial

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from captures.capture_manager import PacketCaptureManager
from config.settings import load_config
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, OVSSwitch, RemoteController
from mininet.topo import Topo

HOST_ROLES = (
    ("h1", "client-a", "10.0.0.1"),
    ("h2", "server-web", "10.0.0.2"),
    ("h3", "attacker", "10.0.0.3"),
    ("h4", "client-b", "10.0.0.4"),
    ("h5", "server-backup", "10.0.0.5"),
)

INTERFACE_MAP = (
    "h1-eth0 <-> s1-eth1  client-a edge link",
    "h4-eth0 <-> s1-eth2  client-b edge link",
    "s1-eth3 <-> s2-eth1  access-to-core link",
    "h3-eth0 <-> s2-eth2  attacker edge link",
    "s2-eth3 <-> s3-eth1  core-to-server link",
    "h2-eth0 <-> s3-eth2  primary server link",
    "h5-eth0 <-> s3-eth3  backup server link",
)

TOPOLOGY_RUNTIME_STATE_PATH = PROJECT_ROOT / "runtime" / "mininet_runtime.json"
TOPOLOGY_MONITOR_INTERVAL_SECONDS = 2.0

SERVICE_SPECS = (
    ("h2", 80, "primary_http_service"),
    ("h5", 8080, "backup_http_service"),
)


class SecurityLabTopo(Topo):
    """Three-switch topology with clients, servers, and one attacker host."""

    def build(self):
        left_access = self.addSwitch("s1", protocols="OpenFlow13")
        core = self.addSwitch("s2", protocols="OpenFlow13")
        right_access = self.addSwitch("s3", protocols="OpenFlow13")

        client_a = self.addHost("h1", ip="10.0.0.1/24")
        server = self.addHost("h2", ip="10.0.0.2/24")
        attacker = self.addHost("h3", ip="10.0.0.3/24")
        client_b = self.addHost("h4", ip="10.0.0.4/24")
        backup_server = self.addHost("h5", ip="10.0.0.5/24")

        self.addLink(client_a, left_access, port2=1, cls=TCLink, bw=40, delay="3ms")
        self.addLink(client_b, left_access, port2=2, cls=TCLink, bw=40, delay="3ms")
        self.addLink(left_access, core, port1=3, port2=1, cls=TCLink, bw=100, delay="2ms")
        self.addLink(attacker, core, port2=2, cls=TCLink, bw=30, delay="2ms")
        self.addLink(core, right_access, port1=3, port2=1, cls=TCLink, bw=100, delay="2ms")
        self.addLink(server, right_access, port2=2, cls=TCLink, bw=40, delay="3ms")
        self.addLink(backup_server, right_access, port2=3, cls=TCLink, bw=40, delay="3ms")


def build_network(
    controller_ip="127.0.0.1",
    controller_port=6633,
    switch_mode="user",
    start_services=False,
):
    """Build and start the Mininet network with a remote Ryu controller."""

    topo = SecurityLabTopo()
    switch_class = (
        partial(OVSSwitch, datapath="user")
        if switch_mode == "user"
        else OVSKernelSwitch
    )
    network = Mininet(
        topo=topo,
        controller=None,
        switch=switch_class,
        autoSetMacs=True,
        link=TCLink,
    )

    controller = RemoteController(
        "c0",
        ip=controller_ip,
        port=controller_port,
    )
    network.addController(controller)
    network.start()
    disable_host_offloading(network)

    app_config = load_config()
    network.capture_manager = PacketCaptureManager(
        app_config.capture,
        interface_runtime_map=build_capture_interface_runtime_map(
            network,
            app_config.capture.interfaces,
        ),
    )
    network.capture_manager.start_continuous_capture()
    network.service_processes = []
    if start_services:
        network.service_processes = start_support_services(network)

    start_runtime_monitor(
        network,
        controller_ip=controller_ip,
        controller_port=controller_port,
        switch_mode=switch_mode,
        services_enabled=start_services,
    )

    write_runtime_state(
        network,
        controller_ip=controller_ip,
        controller_port=controller_port,
        switch_mode=switch_mode,
        services_enabled=start_services,
    )
    describe_network(network, start_services=start_services)
    return network


def disable_host_offloading(network):
    """Disable checksum and segmentation offloads on Mininet host interfaces."""

    offload_features = (
        "rx",
        "tx",
        "sg",
        "tso",
        "ufo",
        "gso",
        "gro",
        "lro",
    )

    for host in network.hosts:
        for interface_name in host.intfNames():
            if interface_name == "lo":
                continue
            for feature in offload_features:
                host.cmd(
                    "ethtool -K {interface} {feature} off >/dev/null 2>&1 || true".format(
                        interface=interface_name,
                        feature=feature,
                    )
                )


def build_capture_interface_runtime_map(network, interface_names):
    interface_runtime_map = {}
    for host in network.hosts:
        host_pid = int(getattr(host, "pid", 0) or 0)
        for interface_name in host.intfNames():
            interface_runtime_map[interface_name] = {
                "namespace_pid": host_pid,
                "host_name": host.name,
            }

    for interface_name in interface_names:
        interface_runtime_map.setdefault(
            interface_name,
            {
                "namespace_pid": None,
                "host_name": None,
            },
        )
    return interface_runtime_map


def start_support_services(network):
    """Start simple HTTP services used by the benign and flood scenarios."""

    service_processes = []
    for host_name, port, service_name in SERVICE_SPECS:
        host = network.get(host_name)
        service_directory = "/tmp/{name}_www".format(name=service_name)
        host.cmd("mkdir -p {directory}".format(directory=service_directory))
        log_path = "/tmp/{service_name}_{port}.log".format(
            service_name=service_name,
            port=port,
        )
        log_handle = open(log_path, "w")
        process = host.popen(
            [
                "python3",
                "-m",
                "http.server",
                str(port),
                "--bind",
                "0.0.0.0",
                "--directory",
                service_directory,
            ],
            stdout=log_handle,
            stderr=log_handle,
        )
        wait_for_service_ready(host, port, log_path=log_path)
        service_processes.append(
            {
                "host_name": host_name,
                "process_id": str(process.pid),
                "process": process,
                "port": port,
                "service_name": service_name,
                "service_directory": service_directory,
                "log_path": log_path,
                "log_handle": log_handle,
            }
        )
    return service_processes


def stop_support_services(network):
    """Stop any background services started by this topology helper."""

    stop_runtime_monitor(network)

    for process in getattr(network, "service_processes", []):
        log_handle = process.get("log_handle")
        running_process = process.get("process")
        if running_process is not None and running_process.poll() is None:
            running_process.terminate()
            try:
                running_process.wait(timeout=2.0)
            except Exception:
                running_process.kill()
        elif process.get("process_id"):
            host = network.get(process["host_name"])
            host.cmd("kill {pid}".format(pid=process["process_id"]))
        if log_handle is not None and not log_handle.closed:
            log_handle.close()

    capture_manager = getattr(network, "capture_manager", None)
    if capture_manager is not None:
        capture_manager.stop()


def start_runtime_monitor(network, controller_ip, controller_port, switch_mode, services_enabled):
    stop_event = threading.Event()

    def _monitor():
        while not stop_event.wait(TOPOLOGY_MONITOR_INTERVAL_SECONDS):
            capture_manager = getattr(network, "capture_manager", None)
            if capture_manager is not None:
                try:
                    capture_manager.ensure_healthy(restart_workers=True)
                except Exception:
                    pass
            try:
                write_runtime_state(
                    network,
                    controller_ip=controller_ip,
                    controller_port=controller_port,
                    switch_mode=switch_mode,
                    services_enabled=services_enabled,
                )
            except Exception:
                pass

    monitor_thread = threading.Thread(
        target=_monitor,
        name="topology-runtime-monitor",
    )
    monitor_thread.daemon = True
    monitor_thread.start()
    network.runtime_monitor = {
        "thread": monitor_thread,
        "stop_event": stop_event,
    }


def stop_runtime_monitor(network):
    runtime_monitor = getattr(network, "runtime_monitor", None)
    if not runtime_monitor:
        return
    stop_event = runtime_monitor.get("stop_event")
    monitor_thread = runtime_monitor.get("thread")
    if stop_event is not None:
        stop_event.set()
    if monitor_thread is not None and monitor_thread.is_alive():
        monitor_thread.join(timeout=3.0)
    network.runtime_monitor = None


def wait_for_service_ready(host, port, attempts=40, sleep_seconds=0.25, log_path=None):
    """Wait until a background TCP service is listening on the host namespace."""

    probe = (
        "python3 -c \"import socket; "
        "sock = socket.socket(); "
        "sock.settimeout(0.5); "
        "status = sock.connect_ex(('127.0.0.1', {port})); "
        "print('ready' if status == 0 else 'not-ready'); "
        "sock.close()\""
    ).format(port=port)

    for _ in range(attempts):
        if host.cmd(probe).strip() == "ready":
            return
        time.sleep(sleep_seconds)

    log_excerpt = ""
    if log_path:
        log_excerpt = host.cmd("tail -n 20 {path} 2>/dev/null || true".format(path=log_path)).strip()

    raise RuntimeError(
        "Timed out waiting for service on {host}:{port}. log={log}".format(
            host=host.name,
            port=port,
            log=log_excerpt or "unavailable",
        )
    )


def write_runtime_state(network, controller_ip, controller_port, switch_mode, services_enabled):
    """Persist topology readiness and host namespace PIDs for validation helpers."""

    TOPOLOGY_RUNTIME_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    capture_manager = getattr(network, "capture_manager", None)
    capture_status = capture_manager.status() if capture_manager is not None else {}
    payload = {
        "active": True,
        "updated_at": time.time(),
        "topology_pid": os.getpid(),
        "controller_ip": controller_ip,
        "controller_port": controller_port,
        "switch_mode": switch_mode,
        "services_enabled": bool(services_enabled),
        "capture_active": bool(capture_status.get("active")),
        "host_pids": dict(
            (host.name, int(getattr(host, "pid", 0) or 0))
            for host in network.hosts
        ),
    }
    temp_path = TOPOLOGY_RUNTIME_STATE_PATH.with_suffix(".tmp")
    temp_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    temp_path.replace(TOPOLOGY_RUNTIME_STATE_PATH)


def clear_runtime_state():
    payload = {
        "active": False,
        "updated_at": time.time(),
        "topology_pid": None,
        "host_pids": {},
    }
    TOPOLOGY_RUNTIME_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = TOPOLOGY_RUNTIME_STATE_PATH.with_suffix(".tmp")
    temp_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    temp_path.replace(TOPOLOGY_RUNTIME_STATE_PATH)


def describe_network(network, start_services=False):
    """Print host roles, service endpoints, and interface names for captures."""

    info("\n*** Hosts ready:\n")
    for host_name, role, address in HOST_ROLES:
        info("  {host} = {role} {address}\n".format(host=host_name, role=role, address=address))

    info("\n*** Interface map:\n")
    for interface_line in INTERFACE_MAP:
        info("  {line}\n".format(line=interface_line))

    if start_services:
        info("\n*** Background services:\n")
        for process in getattr(network, "service_processes", []):
            info(
                "  {host}:{port} = python3 -m http.server {port}\n".format(
                    host=process["host_name"],
                    port=process["port"],
                )
            )
    capture_manager = getattr(network, "capture_manager", None)
    if capture_manager is not None:
        capture_status = capture_manager.status()
        info("\n*** Continuous capture:\n")
        info(
            "  active={active} tool={tool} interfaces={interfaces}\n".format(
                active=capture_status.get("active"),
                tool=app_config_capture_tool(capture_status),
                interfaces=",".join(
                    row.get("interface", "-")
                    for row in capture_status.get("interfaces", [])
                )
                or "-",
            )
        )


def app_config_capture_tool(capture_status):
    return capture_status.get("tool") or "tcpdump"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Start the SDN security Mininet topology.",
    )
    parser.add_argument(
        "--controller-ip",
        default="127.0.0.1",
        help="IP address of the remote Ryu controller.",
    )
    parser.add_argument(
        "--controller-port",
        type=int,
        default=6633,
        help="OpenFlow port exposed by the Ryu controller.",
    )
    parser.add_argument(
        "--switch-mode",
        choices=("user", "kernel"),
        default=os.getenv("SDN_MININET_SWITCH_MODE", "user"),
        help="Open vSwitch datapath mode for Mininet.",
    )
    parser.add_argument(
        "--no-cli",
        action="store_true",
        help="Start the topology and exit after the services are initialized.",
    )
    service_group = parser.add_mutually_exclusive_group()
    service_group.add_argument(
        "--start-services",
        dest="start_services",
        action="store_true",
        help="Start simple HTTP services on the server hosts.",
    )
    service_group.add_argument(
        "--no-services",
        dest="start_services",
        action="store_false",
        help="Do not start background services on the server hosts.",
    )
    parser.set_defaults(start_services=True)
    return parser.parse_args()


if __name__ == "__main__":
    setLogLevel("info")
    arguments = parse_args()
    network = build_network(
        controller_ip=arguments.controller_ip,
        controller_port=arguments.controller_port,
        switch_mode=arguments.switch_mode,
        start_services=arguments.start_services,
    )
    try:
        if arguments.no_cli:
            time.sleep(1.0)
        else:
            CLI(network)
    finally:
        stop_support_services(network)
        clear_runtime_state()
        network.stop()
