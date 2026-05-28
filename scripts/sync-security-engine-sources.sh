#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/third_party/security-engines"
mkdir -p "$DEST"

clone_or_update() {
  local repo="$1" dir="$2" sparse="${3:-}"
  if [ ! -d "$DEST/$dir/.git" ]; then
    if [ -n "$sparse" ]; then
      git clone --depth 1 --filter=blob:none --sparse "https://github.com/$repo.git" "$DEST/$dir"
      git -C "$DEST/$dir" sparse-checkout set $sparse
    else
      git clone --depth 1 "https://github.com/$repo.git" "$DEST/$dir"
    fi
  else
    git -C "$DEST/$dir" pull --ff-only
  fi
}

clone_or_update OISF/suricata suricata
clone_or_update OISF/suricata-update suricata-update
clone_or_update wazuh/wazuh wazuh "ruleset etc"
clone_or_update VirusTotal/yara yara
clone_or_update Neo23x0/signature-base signature-base "yara"
clone_or_update baidu/openrasp openrasp "plugins agent"
clone_or_update bytedance/Elkeid elkeid "rasp plugins"

echo "Security engine source sync complete: $DEST"
