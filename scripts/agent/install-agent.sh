#!/usr/bin/env bash
# Idempotent ly-agent installer with backup and automatic rollback on failed self-test.
# Usage: install-agent.sh <package-file> [service] [binary] [unit-file]
set -euo pipefail

PACKAGE="${1:?package file is required}"
SERVICE="${2:-ly-agent}"
BINARY="${3:-/opt/lyflow/bin/ly-agent}"
UNIT_SOURCE="${4:-}"

if [ "$(id -u)" -ne 0 ]; then
  echo "install-agent: must run as root" >&2
  exit 1
fi
if [ ! -f "$PACKAGE" ]; then
  echo "install-agent: package not found: $PACKAGE" >&2
  exit 1
fi

STAMP=$(date +%Y%m%d%H%M%S)
BACKUP="/opt/lyflow/backups/$STAMP"
mkdir -p "$BACKUP" "$(dirname "$BINARY")"
[ -f "$BINARY" ] && cp -a "$BINARY" "$BACKUP/"
[ -f "/etc/systemd/system/$SERVICE.service" ] && cp -a "/etc/systemd/system/$SERVICE.service" "$BACKUP/"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
case "$PACKAGE" in
  *.tar.gz|*.tgz)
    tar -xzf "$PACKAGE" -C "$TMP"
    SOURCE=$(find "$TMP" -type f -perm -u+x | head -1)
    ;;
  *)
    SOURCE="$PACKAGE"
    ;;
esac
if [ -z "${SOURCE:-}" ] || [ ! -f "$SOURCE" ]; then
  echo "install-agent: unable to locate agent binary in package" >&2
  exit 1
fi

install -m 0755 "$SOURCE" "$BINARY"
if [ -n "$UNIT_SOURCE" ] && [ -f "$UNIT_SOURCE" ]; then
  install -m 0644 "$UNIT_SOURCE" "/etc/systemd/system/$SERVICE.service"
fi

systemctl daemon-reload
systemctl enable --now "$SERVICE"
sleep 2

if ! "$(dirname "$0")/self-test.sh" "$SERVICE" "$BINARY"; then
  echo "install-agent: self-test failed, rolling back" >&2
  if [ -f "$BACKUP/$(basename "$BINARY")" ]; then
    install -m 0755 "$BACKUP/$(basename "$BINARY")" "$BINARY"
  fi
  if [ -f "$BACKUP/$SERVICE.service" ]; then
    install -m 0644 "$BACKUP/$SERVICE.service" "/etc/systemd/system/$SERVICE.service"
  fi
  systemctl daemon-reload
  systemctl restart "$SERVICE" || true
  exit 1
fi

echo "install-agent: installed $BINARY (backup: $BACKUP)"
