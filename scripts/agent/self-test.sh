#!/usr/bin/env bash
# Self-test for an installed ly-agent (or a compatible service).
# Usage: self-test.sh [service] [binary]
set -uo pipefail

SERVICE="${1:-ly-agent}"
BINARY="${2:-/opt/lyflow/bin/ly-agent}"
FAIL=0
ok() { printf 'OK   %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAIL=1; }

if [ -x "$BINARY" ]; then ok "binary executable: $BINARY"; else fail "binary missing/executable: $BINARY"; fi

if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet "$SERVICE"; then
    ok "service active: $SERVICE"
  else
    fail "service inactive: $SERVICE"
  fi
  if systemctl is-enabled --quiet "$SERVICE" 2>/dev/null; then
    ok "service enabled: $SERVICE"
  else
    warn "service not enabled: $SERVICE"
  fi
  RESTARTS=$(systemctl show -p NRestarts --value "$SERVICE" 2>/dev/null || true)
  if [ -n "$RESTARTS" ] && [ "$RESTARTS" -gt 0 ] 2>/dev/null; then
    warn "service restarts: $RESTARTS"
  else
    ok "no service restarts"
  fi
else
  fail "systemctl unavailable"
fi

if [ -d /opt/lyflow/data ]; then ok "/opt/lyflow/data present"; else warn "/opt/lyflow/data missing"; fi
if [ -d /opt/lyflow/logs ]; then ok "/opt/lyflow/logs present"; else warn "/opt/lyflow/logs missing"; fi

if command -v journalctl >/dev/null 2>&1; then
  printf '\n--- recent service log ---\n'
  journalctl -u "$SERVICE" -n 15 --no-pager 2>/dev/null || true
fi

exit "$FAIL"
