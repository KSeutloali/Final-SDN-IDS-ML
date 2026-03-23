#!/usr/bin/env python3
"""Validate live IDS mode switching from the dashboard API."""

from __future__ import print_function

import argparse
import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def fetch_json(base_url, suffix, method="GET", payload=None):
    url = base_url.rstrip("/") + suffix
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
    with urlopen(request, timeout=8.0) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_for(description, timeout_seconds, poll_seconds, predicate):
    deadline = time.time() + timeout_seconds
    last_value = None
    while time.time() < deadline:
        last_value = predicate()
        if last_value:
            return last_value
        time.sleep(poll_seconds)
    raise RuntimeError("Timed out waiting for %s" % description)


def mode_payload(base_url):
    return fetch_json(base_url, "/api/ml-ids").get("ml", {})


def queue_mode(base_url, mode):
    response = fetch_json(
        base_url,
        "/api/set-ids-mode",
        method="POST",
        payload={"mode": mode},
    )
    if not response.get("accepted"):
        raise RuntimeError("Mode switch was not accepted: %r" % response)
    return response


def wait_for_command(base_url, command_id):
    return wait_for(
        "command %s" % command_id,
        timeout_seconds=12.0,
        poll_seconds=0.25,
        predicate=lambda: _command_result(base_url, command_id),
    )


def _command_result(base_url, command_id):
    payload = fetch_json(base_url, "/api/commands/%s" % command_id)
    if payload.get("status") in ("completed", "noop", "rejected", "failed"):
        return payload
    return None


def wait_for_mode(base_url, requested_mode):
    return wait_for(
        "effective mode %s" % requested_mode,
        timeout_seconds=12.0,
        poll_seconds=0.5,
        predicate=lambda: _mode_matches(base_url, requested_mode),
    )


def _mode_matches(base_url, requested_mode):
    payload = mode_payload(base_url)
    selected_mode = payload.get("selected_mode_api")
    effective_mode = payload.get("effective_mode_api")
    if selected_mode == requested_mode and effective_mode == requested_mode:
        return payload
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Validate live IDS mode switching without controller restart.",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8080/sdn-security",
        help="Dashboard base URL.",
    )
    parser.add_argument(
        "--modes",
        nargs="+",
        default=["threshold", "ml", "hybrid"],
        help="Modes to cycle through during validation.",
    )
    args = parser.parse_args()

    try:
        original = mode_payload(args.base_url)
    except (HTTPError, URLError, ValueError) as error:
        print("Dashboard API is not reachable: %s" % error, file=sys.stderr)
        return 1

    original_mode = original.get("selected_mode_api") or "threshold"
    print("Initial IDS mode: %s" % original_mode)

    current_mode = original_mode
    try:
        for mode in args.modes:
            print("Requesting mode: %s" % mode)
            queued = queue_mode(args.base_url, mode)
            command = wait_for_command(args.base_url, queued.get("command_id"))
            if command.get("status") == "rejected":
                raise RuntimeError("Controller rejected %s: %r" % (mode, command.get("result")))
            payload = wait_for_mode(args.base_url, mode)
            current_mode = payload.get("selected_mode_api") or mode
            print(
                "Mode active: selected=%s effective=%s"
                % (payload.get("selected_mode_api"), payload.get("effective_mode_api"))
            )
    finally:
        if current_mode != original_mode:
            print("Restoring original mode: %s" % original_mode)
            queued = queue_mode(args.base_url, original_mode)
            wait_for_command(args.base_url, queued.get("command_id"))
            wait_for_mode(args.base_url, original_mode)

    print("IDS mode switching validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
