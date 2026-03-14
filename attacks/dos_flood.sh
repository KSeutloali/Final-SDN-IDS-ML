#!/bin/sh
set -eu

TARGET_IP="${1:-10.0.0.2}"
PORT="${2:-80}"
COUNT="${3:-300}"
INTERVAL_USEC="${SDN_HPING_INTERVAL_USEC:-1000}"

if ! command -v hping3 >/dev/null 2>&1; then
  echo "hping3 is required for the flood scenario."
  exit 1
fi

echo "Starting SYN flood against ${TARGET_IP}:${PORT} with ${COUNT} packets"
echo "Target an open service such as h2:80 for clear syn_flood_detected events."
hping3 -S -p "${PORT}" -i "u${INTERVAL_USEC}" -c "${COUNT}" "${TARGET_IP}"
