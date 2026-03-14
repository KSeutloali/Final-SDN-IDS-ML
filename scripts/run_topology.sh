#!/bin/sh
set -eu

CONTROLLER_IP="${SDN_CONTROLLER_IP:-controller}"
CONTROLLER_PORT="${SDN_CONTROLLER_PORT:-6633}"
SWITCH_MODE="${SDN_MININET_SWITCH_MODE:-user}"
SKIP_CLEANUP="${SDN_SKIP_MININET_CLEANUP:-false}"

if [ "${SKIP_CLEANUP}" != "true" ]; then
  echo "Cleaning stale Mininet state in container..."
  docker compose exec mininet mn -c >/dev/null 2>&1 || true
fi

exec docker compose exec mininet sh -lc \
  'cd /workspace/ryu-apps && exec python3 -m topology.custom_topology "$@"' \
  sh \
  --controller-ip "${CONTROLLER_IP}" \
  --controller-port "${CONTROLLER_PORT}" \
  --switch-mode "${SWITCH_MODE}" \
  "$@"
