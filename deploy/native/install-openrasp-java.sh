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
script_dir="$(cd "$(dirname "$0")" && pwd)"
bridge_source=""
for candidate in "$script_dir/../../scripts/native/openrasp-alarm-bridge.py" "$script_dir/../scripts/native/openrasp-alarm-bridge.py"; do
  if [[ -f "$candidate" ]]; then bridge_source="$candidate"; break; fi
done
if [[ -z "$bridge_source" ]]; then
  echo "openrasp-alarm-bridge.py not found next to the native install assets" >&2
  exit 1
fi
service_source=""
for candidate in "$script_dir/../systemd/lyflow-openrasp-bridge.service" "$script_dir/../../deploy/systemd/lyflow-openrasp-bridge.service"; do
  if [[ -f "$candidate" ]]; then service_source="$candidate"; break; fi
done
if [[ -z "$service_source" ]]; then
  echo "lyflow-openrasp-bridge.service not found next to the native install assets" >&2
  exit 1
fi
install -m 0755 "$bridge_source" /opt/openrasp/openrasp-alarm-bridge.py
install -m 0644 "$service_source" /etc/systemd/system/lyflow-openrasp-bridge.service
systemctl daemon-reload
systemctl enable --now lyflow-openrasp-bridge
systemctl --no-pager --full status lyflow-openrasp-bridge | head -20
