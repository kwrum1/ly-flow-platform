#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

archive="${OPENRASP_ARCHIVE:-${1:-}}"
if [[ -z "$archive" || ! -f "$archive" ]]; then
  echo "OPENRASP_ARCHIVE must point to the official rasp-java.tar.gz" >&2
  exit 1
fi

install -d -m 0755 /opt/openrasp
tar -xzf "$archive" -C /opt/openrasp --strip-components=1
if [[ ! -f /opt/openrasp/rasp.jar ]]; then
  echo "archive did not contain rasp.jar" >&2
  exit 1
fi
install -m 0755 "$(dirname "$0")/../../scripts/native/openrasp-alarm-bridge.py" /opt/openrasp/openrasp-alarm-bridge.py
install -m 0644 "$(dirname "$0")/../systemd/lyflow-openrasp-bridge.service" /etc/systemd/system/lyflow-openrasp-bridge.service
systemctl daemon-reload
systemctl enable --now lyflow-openrasp-bridge
systemctl --no-pager --full status lyflow-openrasp-bridge | head -20
