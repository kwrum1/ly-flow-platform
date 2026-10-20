#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
install -d -m 0755 /opt/openrasp
install -m 0755 "$root/scripts/native/openrasp-alarm-bridge.py" /opt/openrasp/openrasp-alarm-bridge.py
install -m 0644 "$root/deploy/systemd/lyflow-openrasp-bridge.service" /etc/systemd/system/lyflow-openrasp-bridge.service
systemctl daemon-reload
systemctl enable --now lyflow-openrasp-bridge
systemctl --no-pager --full status lyflow-openrasp-bridge | head -20
