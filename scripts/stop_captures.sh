#!/bin/sh
set -eu

SESSION_FILE="captures/output/.active_capture_session"
SESSION_NAME="${1:-}"

if [ -z "${SESSION_NAME}" ]; then
  if [ ! -f "${SESSION_FILE}" ]; then
    echo "No active capture session file found."
    exit 1
  fi
  SESSION_NAME="$(cat "${SESSION_FILE}")"
fi

HOST_CAPTURE_DIR="captures/output/${SESSION_NAME}"
CONTAINER_CAPTURE_DIR="/workspace/ryu-apps/${HOST_CAPTURE_DIR}"
NOTES_FILE="${HOST_CAPTURE_DIR}/capture_session.txt"
STOPPED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

docker compose exec -T \
  -e CAPTURE_DIR="${CONTAINER_CAPTURE_DIR}" \
  mininet sh -lc '
set -eu
if [ ! -d "$CAPTURE_DIR/.pids" ]; then
  echo "no_pid_directory"
  exit 0
fi
for pid_file in "$CAPTURE_DIR"/.pids/*.pid; do
  [ -e "$pid_file" ] || continue
  pid=$(cat "$pid_file")
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    sleep 1
  fi
  echo "capture_stopped pid=$pid"
  rm -f "$pid_file"
done
rmdir "$CAPTURE_DIR/.pids" >/dev/null 2>&1 || true
'

if [ -f "${SESSION_FILE}" ] && [ "$(cat "${SESSION_FILE}")" = "${SESSION_NAME}" ]; then
  rm -f "${SESSION_FILE}"
fi

if [ -f "${NOTES_FILE}" ]; then
  {
    echo "status=inactive"
    echo "stopped_at=${STOPPED_AT}"
  } >> "${NOTES_FILE}"
fi

echo "capture_session=${SESSION_NAME}"
find "${HOST_CAPTURE_DIR}" -maxdepth 1 -name '*.pcap' | sort
