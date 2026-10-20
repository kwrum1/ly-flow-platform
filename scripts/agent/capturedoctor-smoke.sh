#!/usr/bin/env bash
# Smoke-test the capture doctor against a real interface and a missing one.
# Run on the sensor host as root. Usage: capturedoctor-smoke.sh [interface]
set -uo pipefail

BIN="${CAPTUREDOCTOR_BIN:-/opt/lyflow/bin/lyflow-capturedoctor}"
IFACE="${1:-ens160}"
OUT="${LYFLOW_CAPTURE_SMOKE_OUT:-/tmp/capturedoctor-smoke.json}"
FAIL=0

status() {
  sed -n 's/.*"status": "\([^"]*\)".*/\1/p' "$1" | head -1
}

if [ ! -x "$BIN" ]; then
  echo "FAIL binary missing: $BIN" >&2
  exit 1
fi

rm -f "$OUT"
"$BIN" -once -interface "$IFACE" -process "" -output "$OUT" >/tmp/capturedoctor-ok.log 2>&1
RC=$?
STATE=$(status "$OUT")
echo "interface=$IFACE exit=$RC status=${STATE:-missing}"
if [ "$RC" -eq 2 ]; then
  echo "FAIL real interface unexpectedly critical" >&2
  cat /tmp/capturedoctor-ok.log >&2
  cat "$OUT" 2>/dev/null >&2
  FAIL=1
fi

MISSING="__lyflow_missing_interface__"
"$BIN" -once -interface "$MISSING" -process "" -output "$OUT" >/tmp/capturedoctor-missing.log 2>&1
RC=$?
STATE=$(status "$OUT")
echo "interface=$MISSING exit=$RC status=${STATE:-missing}"
if [ "$RC" -ne 2 ] || [ "$STATE" != "critical" ]; then
  echo "FAIL missing interface was not reported as critical" >&2
  cat /tmp/capturedoctor-missing.log >&2
  cat "$OUT" 2>/dev/null >&2
  FAIL=1
fi
if ! grep -q 'interface_missing' "$OUT" 2>/dev/null; then
  echo "FAIL interface_missing issue missing" >&2
  FAIL=1
fi

if [ "$FAIL" -eq 0 ]; then
  echo "OK capture doctor diagnostics"
fi
exit "$FAIL"
