#!/usr/bin/env bash
# Preflight checks before installing the ly-agent on a host.
set -uo pipefail

FAIL=0
ok() { printf 'OK   %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAIL=1; }

if [ "$(id -u)" -eq 0 ]; then ok "running as root"; else fail "must run as root"; fi

if command -v systemctl >/dev/null 2>&1; then ok "systemd present"; else fail "systemd required"; fi
for command in curl tar awk df; do
  if command -v "$command" >/dev/null 2>&1; then ok "$command present"; else fail "$command missing"; fi
done

if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  ok "os ${PRETTY_NAME:-unknown}"
else
  warn "cannot read /etc/os-release"
fi

if [ -d /opt ] && [ -w /opt ]; then
  ok "/opt writable"
else
  fail "/opt must exist and be writable"
fi

AVAILABLE_KB=$(df -Pk /opt 2>/dev/null | awk 'NR==2 {print $4}')
if [ -n "${AVAILABLE_KB:-}" ] && [ "$AVAILABLE_KB" -ge 1048576 ]; then
  ok "free disk >= 1 GiB"
else
  fail "free disk < 1 GiB"
fi

if command -v timedatectl >/dev/null 2>&1; then
  SYNC=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
  if [ "$SYNC" = "yes" ]; then ok "clock synchronized"; else warn "clock not synchronized"; fi
fi

if command -v getenforce >/dev/null 2>&1; then
  MODE=$(getenforce 2>/dev/null || echo Unknown)
  case "$MODE" in
    Enforcing) warn "SELinux enforcing; verify agent policy" ;;
    *) ok "SELinux ${MODE}" ;;
  esac
fi

if command -v ss >/dev/null 2>&1; then
  ok "ss present"
else
  warn "ss missing; port diagnostics limited"
fi

exit "$FAIL"
