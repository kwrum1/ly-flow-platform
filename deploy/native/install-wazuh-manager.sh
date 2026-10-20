#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

package="${WAZUH_PACKAGE:-${1:-}}"
if [[ -z "$package" || ! -f "$package" ]]; then
  echo "WAZUH_PACKAGE must point to a wazuh-manager .deb package" >&2
  exit 1
fi

dpkg -i "$package"
systemctl daemon-reload
systemctl enable --now wazuh-manager
systemctl --no-pager --full status wazuh-manager | head -20
