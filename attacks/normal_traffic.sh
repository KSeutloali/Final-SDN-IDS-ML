#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

exec "${PROJECT_ROOT}/traffic/benign_traffic.sh" "$@"
