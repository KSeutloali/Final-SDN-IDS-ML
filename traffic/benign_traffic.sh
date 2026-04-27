#!/bin/sh
set -eu

TARGET_IP="${1:-10.0.0.2}"
HTTP_PORT="${2:-80}"
PING_COUNT="${3:-5}"

# Optional controls for richer benign behavior without breaking the old call pattern.
TARGET_PEER="${SDN_BENIGN_PEER_IP:-}"
ROUND_LIMIT="${SDN_BENIGN_ROUNDS:-2}"
DURATION_SECONDS="${SDN_BENIGN_DURATION_SECONDS:-0}"

log() {
  echo "[benign_traffic] $1"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

sleep_quiet() {
  if have_cmd sleep; then
    sleep "$1"
  fi
}

http_request() {
  path="$1"
  method="${2:-GET}"
  url="http://${TARGET_IP}:${HTTP_PORT}${path}"

  if have_cmd curl; then
    if [ "$method" = "HEAD" ]; then
      curl -m 4 -s -I -o /dev/null "$url" || true
    else
      curl -m 4 -s -o /dev/null "$url" || true
    fi
    return 0
  fi

  if have_cmd wget; then
    wget -T 4 -q -O /dev/null "$url" || true
    return 0
  fi

  python3 - "$TARGET_IP" "$HTTP_PORT" "$path" "$method" <<'PY'
import socket
import sys

target_ip = sys.argv[1]
target_port = int(sys.argv[2])
path = sys.argv[3]
method = sys.argv[4]
request = (
    "{method} {path} HTTP/1.0\r\n"
    "Host: {host}\r\n"
    "Connection: close\r\n\r\n"
).format(method=method, path=path, host=target_ip).encode("ascii")

sock = socket.create_connection((target_ip, target_port), timeout=10)
sock.settimeout(10)
sock.sendall(request)
while sock.recv(4096):
    pass
sock.close()
PY
}

wait_for_http_service() {
  log "Waiting for HTTP service on ${TARGET_IP}:${HTTP_PORT}"
  python3 - "$TARGET_IP" "$HTTP_PORT" <<'PY'
import socket
import sys
import time

target_ip = sys.argv[1]
target_port = int(sys.argv[2])

for attempt in range(1, 9):
    sock = socket.socket()
    sock.settimeout(5.0)
    try:
        sock.connect((target_ip, target_port))
        print("http_service_ready attempt={0}".format(attempt))
        break
    except OSError:
        if attempt == 8:
            raise
        time.sleep(0.5)
    finally:
        sock.close()
PY
}

warmup_ping() {
  log "ICMP reachability check"
  ping -c "$PING_COUNT" "$TARGET_IP" >/dev/null 2>&1 || true
}

light_ping() {
  ping -c 1 -W 1 "$TARGET_IP" >/dev/null 2>&1 || true
}

peer_ping() {
  if [ -z "$TARGET_PEER" ]; then
    return 0
  fi
  ping -c 1 -W 1 "$TARGET_PEER" >/dev/null 2>&1 || true
}

tcp_connect_check() {
  if have_cmd nc; then
    nc -z -w 1 "$TARGET_IP" "$HTTP_PORT" >/dev/null 2>&1 || true
    return 0
  fi
  python3 - "$TARGET_IP" "$HTTP_PORT" <<'PY'
import socket
import sys

target_ip = sys.argv[1]
target_port = int(sys.argv[2])
sock = socket.socket()
sock.settimeout(3.0)
try:
    sock.connect((target_ip, target_port))
except OSError:
    pass
finally:
    sock.close()
PY
}

round_pause_seconds() {
  round_index="$1"
  case $((round_index % 4)) in
    0) echo "1" ;;
    1) echo "2" ;;
    2) echo "1" ;;
    *) echo "3" ;;
  esac
}

web_browse_round() {
  round_index="$1"
  http_request "/" "GET"
  http_request "/index.html" "GET"
  if [ $((round_index % 2)) -eq 0 ]; then
    http_request "/" "HEAD"
  else
    http_request "/favicon.ico" "GET"
  fi
  if [ $((round_index % 3)) -eq 0 ]; then
    http_request "/?view=dashboard" "GET"
  fi
}

run_round() {
  round_index="$1"
  log "Benign round ${round_index}"

  web_browse_round "$round_index"
  sleep_quiet "$(round_pause_seconds "$round_index")"

  light_ping
  peer_ping
  sleep_quiet 1

  tcp_connect_check
}

should_continue() {
  round_index="$1"
  start_time="$2"

  if [ "$DURATION_SECONDS" -gt 0 ]; then
    now="$(date +%s)"
    elapsed=$((now - start_time))
    [ "$elapsed" -lt "$DURATION_SECONDS" ]
    return
  fi

  [ "$round_index" -lt "$ROUND_LIMIT" ]
}

log "Starting benign traffic against ${TARGET_IP}:${HTTP_PORT}"
if [ -n "$TARGET_PEER" ]; then
  log "Peer target enabled for light background reachability: ${TARGET_PEER}"
fi

warmup_ping
wait_for_http_service

start_time="$(date +%s)"
round_index=0
while :; do
  round_index=$((round_index + 1))
  run_round "$round_index"
  if ! should_continue "$round_index" "$start_time"; then
    break
  fi
done

log "Finished benign traffic after ${round_index} round(s)"
