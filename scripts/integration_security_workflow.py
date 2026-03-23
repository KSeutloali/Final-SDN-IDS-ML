#!/usr/bin/env python3
"""End-to-end validation of quarantine, capture snapshot, and manual unblock."""

from __future__ import print_function

import argparse
import json
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.common import ensure_topology_running, run_on_host  # noqa: E402


def fetch_json(base_url, suffix, method="GET"):
    url = base_url.rstrip("/") + suffix
    request = Request(url, method=method)
    with urlopen(request, timeout=8.0) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_bytes(base_url, suffix):
    if suffix.startswith("http://") or suffix.startswith("https://"):
        url = suffix
    elif suffix.startswith("/"):
        parsed = urlparse(base_url)
        url = "%s://%s%s" % (parsed.scheme, parsed.netloc, suffix)
    else:
        url = base_url.rstrip("/") + "/" + suffix.lstrip("/")
    request = Request(url, method="GET")
    with urlopen(request, timeout=12.0) as response:
        return response.read()


def is_capture_bytes(payload):
    if len(payload) < 4:
        return False
    magic = payload[:4]
    return magic in (
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
        b"\x0a\x0d\x0d\x0a",
    )


def wait_for(description, timeout_seconds, poll_seconds, predicate):
    deadline = time.time() + timeout_seconds
    last_value = None
    while time.time() < deadline:
        last_value = predicate()
        if last_value:
            return last_value
        time.sleep(poll_seconds)
    raise RuntimeError("Timed out waiting for %s" % description)


def blocked_host_row(base_url, src_ip):
    payload = fetch_json(base_url, "/api/blocked-hosts")
    for row in payload.get("blocked_hosts", []):
        if row.get("src_ip") == src_ip:
            return row
    return None


def relevant_snapshot(base_url, src_ip):
    payload = fetch_json(base_url, "/api/captures")
    snapshots = payload.get("captures", {}).get("snapshots", [])
    for snapshot in snapshots:
        if snapshot.get("source_ip") == src_ip:
            return snapshot
    return None


def maybe_unblock(base_url, src_ip):
    if not blocked_host_row(base_url, src_ip):
        return
    fetch_json(
        base_url,
        "/api/blocked-hosts/%s/unblock" % quote(src_ip, safe=""),
        method="POST",
    )
    wait_for(
        "existing unblock of %s" % src_ip,
        timeout_seconds=12.0,
        poll_seconds=1.0,
        predicate=lambda: blocked_host_row(base_url, src_ip) is None,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Validate the live security workflow from attack to manual release.",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8080/sdn-security",
        help="Dashboard base URL.",
    )
    parser.add_argument(
        "--attacker-host",
        default="h3",
        help="Mininet host used for the port scan.",
    )
    parser.add_argument(
        "--attacker-ip",
        default="10.0.0.3",
        help="Expected IPv4 address of the attacker host.",
    )
    parser.add_argument(
        "--target-ip",
        default="10.0.0.2",
        help="Target server IP for the validation attack.",
    )
    args = parser.parse_args()

    try:
        ensure_topology_running()
    except SystemExit:
        print(
            "Mininet topology is not running. Start it with ./scripts/run_topology.sh first.",
            file=sys.stderr,
        )
        return 1

    try:
        fetch_json(args.base_url, "/api/health")
    except (HTTPError, URLError, ValueError) as error:
        print("Dashboard API is not reachable: %s" % error, file=sys.stderr)
        return 1

    print("Clearing previous quarantine state for %s if needed..." % args.attacker_ip)
    maybe_unblock(args.base_url, args.attacker_ip)

    print("Running benign traffic smoke check...")
    run_on_host(
        "h1",
        "/workspace/ryu-apps/traffic/benign_traffic.sh %s 80" % args.target_ip,
        capture_output=True,
        check=True,
    )

    print("Launching port scan from %s..." % args.attacker_host)
    run_on_host(
        args.attacker_host,
        "/workspace/ryu-apps/attacks/port_scan.sh %s" % args.target_ip,
        capture_output=True,
        check=True,
    )

    blocked = wait_for(
        "quarantine of %s" % args.attacker_ip,
        timeout_seconds=20.0,
        poll_seconds=1.0,
        predicate=lambda: blocked_host_row(args.base_url, args.attacker_ip),
    )
    print(
        "Quarantine observed: src_ip=%s reason=%s detector=%s"
        % (
            blocked.get("src_ip"),
            blocked.get("reason"),
            blocked.get("detector"),
        )
    )

    snapshot = wait_for(
        "preserved capture snapshot for %s" % args.attacker_ip,
        timeout_seconds=20.0,
        poll_seconds=1.0,
        predicate=lambda: relevant_snapshot(args.base_url, args.attacker_ip),
    )
    print(
        "Capture snapshot observed: %s"
        % (snapshot.get("primary_download_path") or snapshot.get("snapshot_name"))
    )
    download_path = snapshot.get("primary_download_path")
    if not download_path:
        raise RuntimeError("Snapshot is missing a primary download path: %r" % snapshot)
    capture_bytes = fetch_bytes(args.base_url, download_path)
    if not is_capture_bytes(capture_bytes):
        raise RuntimeError("Downloaded snapshot does not look like pcap/pcapng data.")
    print("Capture download verified: %d bytes of pcap-compatible data." % len(capture_bytes))

    print("Requesting manual unblock...")
    unblock_response = fetch_json(
        args.base_url,
        "/api/blocked-hosts/%s/unblock" % quote(args.attacker_ip, safe=""),
        method="POST",
    )
    if not unblock_response.get("accepted"):
        raise RuntimeError("Unblock request was not accepted: %r" % unblock_response)

    wait_for(
        "manual release of %s" % args.attacker_ip,
        timeout_seconds=15.0,
        poll_seconds=1.0,
        predicate=lambda: blocked_host_row(args.base_url, args.attacker_ip) is None,
    )
    print("Manual unblock completed.")
    print("Security workflow integration check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
