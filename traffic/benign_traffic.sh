#!/bin/sh
set -eu

TARGET_IP="${1:-10.0.0.2}"
HTTP_PORT="${2:-80}"
PING_COUNT="${3:-5}"

echo "Running benign traffic against ${TARGET_IP}:${HTTP_PORT}"
echo "1. ICMP reachability check"
ping -c "${PING_COUNT}" "${TARGET_IP}"

echo "2. Waiting for HTTP service readiness"
python3 - "${TARGET_IP}" "${HTTP_PORT}" <<'PY'
import sys
import socket
import time

target_ip = sys.argv[1]
target_port = int(sys.argv[2])

for attempt in range(1, 11):
    sock = socket.socket()
    sock.settimeout(10.0)
    try:
        sock.connect((target_ip, target_port))
        print("http_service_ready attempt={0}".format(attempt))
        break
    except OSError:
        if attempt == 10:
            raise
        time.sleep(0.5)
    finally:
        sock.close()
PY

echo "3. HTTP GET using a simple TCP client"
python3 - "${TARGET_IP}" "${HTTP_PORT}" <<'PY'
import socket
import sys

target_ip = sys.argv[1]
target_port = int(sys.argv[2])
request = (
    "GET / HTTP/1.0\r\n"
    "Host: {0}\r\n"
    "Connection: close\r\n\r\n"
).format(target_ip).encode("ascii")

sock = socket.create_connection((target_ip, target_port), timeout=10)
sock.settimeout(10)
sock.sendall(request)
reply = sock.recv(256)
sock.close()
print("http_get bytes={0}".format(len(reply)))
print(reply.decode("iso-8859-1", "replace").splitlines()[0])
PY

echo "4. Repeated short TCP sessions"
python3 - "${TARGET_IP}" "${HTTP_PORT}" <<'PY'
import socket
import sys
import time

target_ip = sys.argv[1]
target_port = int(sys.argv[2])
request = b"GET / HTTP/1.0\r\nHost: benign\r\nConnection: close\r\n\r\n"

for attempt in range(1, 4):
    sock = socket.create_connection((target_ip, target_port), timeout=10)
    sock.settimeout(10)
    sock.sendall(request)
    reply = sock.recv(96)
    print("tcp_session={0} reply_bytes={1}".format(attempt, len(reply)))
    sock.close()
    time.sleep(0.5)
PY
