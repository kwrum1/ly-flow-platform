#!/usr/bin/env bash
# Capture preflight for ly_probe on a host interface.
# Usage: lyprobe-preflight.sh [interface] [binary]
set -uo pipefail

INTERFACE="${1:-}"
BINARY="${2:-/opt/lyflow/bin/lyprobe}"
FAIL=0
ok() { printf 'OK   %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAIL=1; }

if [ "$(id -u)" -eq 0 ]; then ok "running as root"; else fail "root required for capture"; fi
if [ -x "$BINARY" ]; then ok "binary executable: $BINARY"; else fail "binary missing/executable: $BINARY"; fi
BINARY_DIR=$(cd "$(dirname "$BINARY")" 2>/dev/null && pwd || true)
if [ -n "$BINARY_DIR" ] && [ -f "$BINARY_DIR/liblyprobe-1.0.0.so" ]; then
  ok "liblyprobe runtime present"
else
  fail "liblyprobe-1.0.0.so missing next to $BINARY"
fi
if command -v ldd >/dev/null 2>&1 && [ -x "$BINARY" ]; then
  if ldd "$BINARY" 2>/dev/null | grep -q 'not found'; then
    fail "unresolved shared libraries: $(ldd "$BINARY" 2>/dev/null | grep 'not found' | tr '\n' ' ')"
  else
    ok "shared libraries resolved"
  fi
fi
if [ -z "$INTERFACE" ]; then fail "interface argument is required"; fi

if command -v ip >/dev/null 2>&1; then
  if [ -n "$INTERFACE" ] && ip link show "$INTERFACE" >/dev/null 2>&1; then
    STATE=$(ip -o link show "$INTERFACE" | awk '{print $9}')
    if [ "$STATE" = "UP" ] || ip -o link show "$INTERFACE" | grep -q "state UP"; then
      ok "interface $INTERFACE is up"
    else
      warn "interface $INTERFACE state: $STATE"
    fi
    if [ "$INTERFACE" = "lo" ]; then fail "loopback is not a mirror interface"; fi
  else
    fail "interface not found: $INTERFACE"
  fi
else
  fail "ip command missing"
fi

if command -v ethtool >/dev/null 2>&1 && [ -n "$INTERFACE" ]; then
  FEATURES=$(ethtool -k "$INTERFACE" 2>/dev/null || true)
  for feature in rx-gro tx-gso generic-receive-offload; do
    if echo "$FEATURES" | grep -q "^$feature: on"; then
      warn "offload enabled: $feature (disable for stable capture)"
    fi
  done
  RING=$(ethtool -g "$INTERFACE" 2>/dev/null | awk '/Current hardware settings:/{current=1; next} current && /^RX:/{print $2; exit}')
  if [ -n "${RING:-}" ] && [ "$RING" -lt 2048 ] 2>/dev/null; then
    warn "RX ring $RING < 2048"
  else
    ok "RX ring ${RING:-unknown}"
  fi
else
  warn "ethtool missing; offload/ring checks skipped"
fi

if command -v ldconfig >/dev/null 2>&1; then
  if ldconfig -p 2>/dev/null | grep -q 'libpcap'; then ok "libpcap present"; else fail "libpcap missing"; fi
else
  warn "ldconfig missing; libpcap check skipped"
fi

if [ -d /proc/net/pf_ring ]; then ok "PF_RING loaded"; else warn "PF_RING not loaded (AF_PACKET fallback)"; fi
if [ -e /dev/net/tun ]; then ok "/dev/net/tun present"; else warn "/dev/net/tun missing"; fi

if command -v nproc >/dev/null 2>&1; then ok "cpus: $(nproc)"; else warn "nproc missing"; fi

if [ -n "$INTERFACE" ] && command -v ip >/dev/null 2>&1; then
  MTU=$(ip -o link show "$INTERFACE" 2>/dev/null | awk '{print $5}')
  ok "MTU: ${MTU:-unknown}"
fi

exit "$FAIL"
