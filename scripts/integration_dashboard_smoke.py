#!/usr/bin/env python3
"""Lightweight smoke test for the live monitoring dashboard APIs."""

from __future__ import print_function

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


ENDPOINTS = (
    ("health", "/api/health", ("status", "generated_at")),
    ("overview", "/api/dashboard", ("summary", "traffic", "alerts")),
    ("traffic", "/api/traffic", ("traffic", "summary")),
    ("alerts", "/api/alerts", ("alerts",)),
    ("blocked_hosts", "/api/blocked-hosts", ("blocked_hosts",)),
    ("performance", "/api/performance", ("performance",)),
    ("captures", "/api/captures", ("captures",)),
    ("ml_ids", "/api/ml-ids", ("ml",)),
    ("settings", "/api/settings", ("settings",)),
)


def fetch_json(base_url, suffix):
    url = base_url.rstrip("/") + suffix
    with urlopen(url, timeout=5.0) as response:
        payload = response.read().decode("utf-8")
    return json.loads(payload)


def main():
    parser = argparse.ArgumentParser(
        description="Validate that the dashboard APIs are responding with expected sections.",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8080/sdn-security",
        help="Dashboard base URL.",
    )
    args = parser.parse_args()

    failures = []
    for name, suffix, keys in ENDPOINTS:
        try:
            payload = fetch_json(args.base_url, suffix)
        except (HTTPError, URLError, ValueError) as error:
            failures.append("%s: %s" % (name, error))
            continue

        missing = [key for key in keys if key not in payload]
        if missing:
            failures.append("%s: missing keys %s" % (name, ", ".join(missing)))
            continue

        print("[ok] %s" % name)

    if failures:
        for failure in failures:
            print("[fail] %s" % failure, file=sys.stderr)
        return 1

    print("Dashboard smoke test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
