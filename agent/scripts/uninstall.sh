#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/ly-agent}"
LOG_DIR="${LOG_DIR:-/var/log/ly-agent}"
SYSTEMD_UNIT="${SYSTEMD_UNIT:-/etc/systemd/system/ly-agent.service}"
DRY_RUN=0
REMOVE_LOGS=0

usage() {
  cat <<'EOF'
Usage: uninstall.sh [--dry-run] [--remove-logs]

Stops/disables ly-agent and removes files managed by agent/scripts/install.sh.
Logs are preserved unless --remove-logs is provided.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --remove-logs) REMOVE_LOGS=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

run() {
  printf '+ %s\n' "$*"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    "$@"
  fi
}

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "uninstall.sh must run as root" >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  if systemctl cat ly-agent.service >/dev/null 2>&1; then
    run systemctl stop ly-agent.service || true
    run systemctl disable ly-agent.service || true
  else
    echo "service already absent: ly-agent.service"
  fi
fi

if [[ -e "$SYSTEMD_UNIT" ]]; then
  run rm -f "$SYSTEMD_UNIT"
else
  echo "service unit already absent: $SYSTEMD_UNIT"
fi

if command -v systemctl >/dev/null 2>&1; then
  run systemctl daemon-reload || true
  run systemctl reset-failed || true
fi

if [[ -d "$INSTALL_DIR" ]]; then
  case "$INSTALL_DIR" in
    /opt/ly-agent|/usr/local/ly-agent) run rm -rf "$INSTALL_DIR" ;;
    *) echo "refusing to remove non-standard INSTALL_DIR: $INSTALL_DIR" >&2; exit 1 ;;
  esac
else
  echo "install dir already absent: $INSTALL_DIR"
fi

if [[ "$REMOVE_LOGS" -eq 1 ]]; then
  if [[ -d "$LOG_DIR" ]]; then
    case "$LOG_DIR" in
      /var/log/ly-agent) run rm -rf "$LOG_DIR" ;;
      *) echo "refusing to remove non-standard LOG_DIR: $LOG_DIR" >&2; exit 1 ;;
    esac
  else
    echo "log dir already absent: $LOG_DIR"
  fi
else
  echo "preserving logs: $LOG_DIR"
fi

echo "ly-agent uninstall complete"
