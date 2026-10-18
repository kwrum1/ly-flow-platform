#!/usr/bin/env bash
# Restore a previous ly-agent backup created by install-agent.sh.
# Usage: rollback-agent.sh <backup-directory> [service] [binary]
set -euo pipefail

BACKUP="${1:?backup directory is required}"
SERVICE="${2:-ly-agent}"
BINARY="${3:-/opt/lyflow/bin/ly-agent}"

if [ "$(id -u)" -ne 0 ]; then
  echo "rollback-agent: must run as root" >&2
  exit 1
fi
if [ ! -d "$BACKUP" ]; then
  echo "rollback-agent: backup not found: $BACKUP" >&2
  exit 1
fi

if [ -f "$BACKUP/$(basename "$BINARY")" ]; then
  install -m 0755 "$BACKUP/$(basename "$BINARY")" "$BINARY"
fi
if [ -f "$BACKUP/$SERVICE.service" ]; then
  install -m 0644 "$BACKUP/$SERVICE.service" "/etc/systemd/system/$SERVICE.service"
fi
systemctl daemon-reload
systemctl restart "$SERVICE"
sleep 1
systemctl is-active --quiet "$SERVICE"
echo "rollback-agent: restored from $BACKUP"
