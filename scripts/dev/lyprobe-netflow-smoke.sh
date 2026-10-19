#!/usr/bin/env bash
# Validate ly_probe capture + NetFlow v5 export to a local UDP collector.
# Run on the sensor host (root). Usage: lyprobe-netflow-smoke.sh [interface]
set -uo pipefail

BIN="${LYPROBE_BIN:-/opt/lyflow/bin/lyprobe}"
IFACE="${1:-ens160}"
PORT="${LYPROBE_COLLECTOR_PORT:-9995}"
OUT="${LYPROBE_SMOKE_DIR:-/tmp/lyprobe-netflow}"
COLLECTOR_LOG="$OUT/collector.log"
PROBE_LOG="$OUT/probe.log"

if [ ! -x "$BIN" ]; then
  echo "FAIL lyprobe binary missing: $BIN" >&2
  exit 1
fi
rm -rf "$OUT"
mkdir -p "$OUT"

python3 - "$PORT" "$COLLECTOR_LOG" <<'PY' &
import socket, sys, time
port = int(sys.argv[1])
path = sys.argv[2]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", port))
sock.settimeout(2)
start = time.time()
count = 0
with open(path, "w", encoding="utf-8") as out:
    while time.time() - start < 22:
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            continue
        count += 1
        out.write(f"{count} {len(data)} {data[:32].hex()}\n")
        out.flush()
print(count)
PY
COLLECTOR_PID=$!
sleep 1

timeout 14 "$BIN" -i "$IFACE" -n "127.0.0.1:$PORT" -t 5 -d 1 -l 1 -s 1 -b 1 -w 32768 >"$PROBE_LOG" 2>&1 &
PROBE_PID=$!
sleep 2
ping -c 8 -i 1 -W 1 10.1.18.1 >/dev/null 2>&1 || true
python3 - <<'PY' >/dev/null 2>&1 || true
import socket
q = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07profile\x04test\x00\x00\x01\x00\x01'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
try:
    s.sendto(q, ('223.5.5.5', 53))
    s.recv(512)
except Exception:
    pass
PY
sleep 3
wait "$PROBE_PID"
PROBE_RC=$?
wait "$COLLECTOR_PID" || true

PACKETS=$(wc -l < "$COLLECTOR_LOG" 2>/dev/null || echo 0)
echo "lyprobe exit: $PROBE_RC (124=timeout, expected)"
echo "collector packets: $PACKETS"
echo "--- probe log tail ---"
tail -12 "$PROBE_LOG" || true
if [ "$PACKETS" -gt 0 ]; then
  echo "OK lyprobe exported NetFlow packets"
  exit 0
fi
echo "FAIL collector received no NetFlow packets" >&2
exit 1
