#!/bin/sh
set -eu

TARGET_IP="${1:-10.0.0.2}"
TARGET_PORTS="${2:-23,1-20}"
SCAN_EXTRA_ARGS="${SDN_NMAP_ARGS:--Pn -T5 --max-retries 0 --min-rate 5000}"

if ! command -v nmap >/dev/null 2>&1; then
  echo "nmap is required for the port scan scenario."
  exit 1
fi

echo "Starting TCP SYN port scan against ${TARGET_IP} on ports ${TARGET_PORTS}"
echo "Use a target range such as 10.0.0.1-5 to exercise host-scan thresholds."
nmap -sS ${SCAN_EXTRA_ARGS} -p "${TARGET_PORTS}" "${TARGET_IP}"
