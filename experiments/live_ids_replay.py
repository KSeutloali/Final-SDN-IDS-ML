"""Replay a port scan and SYN flood against the running controller."""

import argparse
import os
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from topology.custom_topology import build_network


def start_http_server(host, port):
    command = (
        "sh -c 'python3 -m http.server {port} "
        ">/tmp/http_server_{port}.log 2>&1 & echo $!'"
    ).format(port=port)
    return host.cmd(command).strip()


def stop_process(host, process_id):
    if not process_id:
        return
    host.cmd("kill {pid}".format(pid=process_id))


def main():
    parser = argparse.ArgumentParser(
        description="Run a live Mininet replay for IDS validation."
    )
    parser.add_argument("--controller-ip", default="controller")
    parser.add_argument("--controller-port", type=int, default=6633)
    parser.add_argument("--switch-mode", default="user", choices=("user", "kernel"))
    parser.add_argument("--server-port", type=int, default=80)
    parser.add_argument("--scan-ports", default="1-30")
    parser.add_argument("--scan-extra-args", default="-T4")
    parser.add_argument("--hping-count", type=int, default=300)
    parser.add_argument("--settle-seconds", type=float, default=2.0)
    parser.add_argument("--pause-seconds", type=float, default=2.0)
    args = parser.parse_args()

    network = build_network(
        controller_ip=args.controller_ip,
        controller_port=args.controller_port,
        switch_mode=args.switch_mode,
    )

    server_pid = ""
    try:
        time.sleep(args.settle_seconds)
        print("=== pingall ===")
        print("pingall_loss={loss}".format(loss=network.pingAll()))

        client = network.get("h1")
        server = network.get("h2")
        attacker = network.get("h3")

        server_pid = start_http_server(server, args.server_port)
        time.sleep(1.0)

        print("=== nmap from h3 ===")
        scan_command = "nmap -Pn -sS {extra_args} -p {ports} 10.0.0.2".format(
            extra_args=args.scan_extra_args,
            ports=args.scan_ports,
        )
        print(attacker.cmd(scan_command).strip())

        time.sleep(args.pause_seconds)

        print("=== hping3 from h1 ===")
        flood_command = "hping3 -S -p {port} -i u1000 -c {count} 10.0.0.2".format(
            port=args.server_port,
            count=args.hping_count,
        )
        print(client.cmd(flood_command).strip())

        time.sleep(args.pause_seconds)
    finally:
        stop_process(server, server_pid)
        network.stop()


if __name__ == "__main__":
    main()
