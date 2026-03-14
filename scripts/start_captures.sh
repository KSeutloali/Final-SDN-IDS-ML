#!/bin/sh
set -eu

SCENARIO="${1:-manual}"
CAPTURE_INTERFACES="${2:-${SDN_CAPTURE_INTERFACES:-h1-eth0,h3-eth0,h2-eth0,s2-eth3}}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SESSION_NAME="${SCENARIO}-${TIMESTAMP}"
HOST_CAPTURE_DIR="captures/output/${SESSION_NAME}"
CONTAINER_CAPTURE_DIR="/workspace/ryu-apps/${HOST_CAPTURE_DIR}"
SESSION_FILE="captures/output/.active_capture_session"
NOTES_FILE="${HOST_CAPTURE_DIR}/capture_session.txt"

mkdir -p "${HOST_CAPTURE_DIR}"

docker compose exec -T \
  -e CAPTURE_DIR="${CONTAINER_CAPTURE_DIR}" \
  -e CAPTURE_INTERFACES="${CAPTURE_INTERFACES}" \
  -e CAPTURE_SESSION="${SESSION_NAME}" \
  mininet sh -lc '
set -eu
mkdir -p "$CAPTURE_DIR/.pids"
captured_any=0
old_ifs=$IFS
IFS=","
for iface in $CAPTURE_INTERFACES; do
  iface=$(echo "$iface" | tr -d " ")
  [ -n "$iface" ] || continue
  if ! ip link show "$iface" >/dev/null 2>&1; then
    echo "capture_skipped iface=$iface reason=missing_interface"
    continue
  fi
  output_file="$CAPTURE_DIR/${CAPTURE_SESSION}-${iface}.pcap"
  pid_file="$CAPTURE_DIR/.pids/${iface}.pid"
  nohup tcpdump -U -nn -i "$iface" -w "$output_file" >/dev/null 2>&1 &
  echo $! > "$pid_file"
  echo "capture_started iface=$iface file=$output_file pid=$(cat "$pid_file")"
  captured_any=1
done
IFS=$old_ifs
if [ "$captured_any" -eq 0 ]; then
  echo "no_capture_started"
  exit 1
fi
'

printf '%s\n' "${SESSION_NAME}" > "${SESSION_FILE}"
{
  echo "scenario=${SCENARIO}"
  echo "timestamp=${TIMESTAMP}"
  echo "started_at=${STARTED_AT}"
  echo "interfaces=${CAPTURE_INTERFACES}"
  echo "status=active"
  echo "wireshark_example=wireshark ${HOST_CAPTURE_DIR}/${SESSION_NAME}-h2-eth0.pcap"
  echo "tshark_example=tshark -r ${HOST_CAPTURE_DIR}/${SESSION_NAME}-s2-eth3.pcap"
} > "${NOTES_FILE}"

echo "capture_session=${SESSION_NAME}"
echo "capture_dir=${HOST_CAPTURE_DIR}"
