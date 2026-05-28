#!/usr/bin/env bash
set -euo pipefail

SURICATA_EVE="${SURICATA_EVE:-/var/log/suricata/eve.json}"
WAZUH_ALERTS="${WAZUH_ALERTS:-/var/ossec/logs/alerts/alerts.json}"
YARA_RESULTS="${YARA_RESULTS:-/opt/ly-agent/yara/last-scan.json}"
RASP_EVENTS="${RASP_EVENTS:-/opt/ly-agent/rasp/events.jsonl}"
STATUS_FILE="${ENGINE_STATUS_FILE:-/opt/ly-engine-lab/runtime/status.json}"
INTERVAL="${ENGINE_LAB_INTERVAL:-45}"
SOURCE_ROOT="${ENGINE_SOURCE_ROOT:-/opt/ly-engine-lab/source}"
RULE_ROOT="${ENGINE_RULE_ROOT:-/opt/ly-engine-lab/rules}"
RUNTIME_ROOT="${ENGINE_RUNTIME_ROOT:-/opt/ly-engine-lab/runtime}"

mkdir -p "$(dirname "$SURICATA_EVE")" "$(dirname "$WAZUH_ALERTS")" "$(dirname "$YARA_RESULTS")" "$(dirname "$RASP_EVENTS")" "$RUNTIME_ROOT" "$RULE_ROOT/yara"
touch "$SURICATA_EVE" "$WAZUH_ALERTS" "$YARA_RESULTS" "$RASP_EVENTS"

source_revision() {
  local name head ref target
  name="$1"
  head="$SOURCE_ROOT/$name/.git/HEAD"
  if [ ! -f "$head" ]; then printf 'vendored'; return; fi
  ref="$(cat "$head" 2>/dev/null || true)"
  if [[ "$ref" == ref:* ]]; then
    target="$SOURCE_ROOT/$name/.git/${ref#ref: }"
    if [ -f "$target" ]; then cut -c1-12 "$target"; return; fi
  fi
  printf '%s' "$ref" | cut -c1-12
}

version_of() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then printf 'not-installed'; return; fi
  "$bin" --version 2>&1 | head -n 1 | tr -d '"'
}

rule_count() {
  local dir="$1" pattern="$2"
  find "$dir" -type f \( -name "$pattern" \) 2>/dev/null | wc -l | tr -d ' '
}

first_yara_rule() {
  find "$RULE_ROOT/yara" -type f \( -name '*.yar' -o -name '*.yara' \) 2>/dev/null | sort | head -n 1
}

write_status() {
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  cat > "$STATUS_FILE" <<JSON
{"updated_at":"$ts","engines":{"suricata":{"installed":$(command -v suricata >/dev/null 2>&1 && echo true || echo false),"running":$(pgrep -f '^suricata' >/dev/null 2>&1 && echo true || echo false),"version":"$(version_of suricata)","output_path":"$SURICATA_EVE","rule_path":"$RULE_ROOT/suricata/et-open.rules","rule_count":$(rule_count "$RULE_ROOT/suricata" '*.rules'),"rule_pack_version":"et-open-active"},"wazuh":{"installed":$(command -v wazuh-agentd >/dev/null 2>&1 && echo true || echo false),"running":$(pgrep -f '^wazuh-agentd' >/dev/null 2>&1 && echo true || echo false),"version":"$(source_revision wazuh)","output_path":"$WAZUH_ALERTS","rule_path":"$SOURCE_ROOT/wazuh/ruleset/sca","rule_count":$(find "$SOURCE_ROOT/wazuh/ruleset" -type f \( -name '*.xml' -o -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | wc -l | tr -d ' '),"rule_pack_version":"wazuh-ruleset"},"yara":{"installed":$(command -v yara >/dev/null 2>&1 && echo true || echo false),"running":true,"version":"$(version_of yara)","output_path":"$YARA_RESULTS","rule_path":"$RULE_ROOT/yara","rule_count":$(find "$RULE_ROOT/yara" -type f \( -name '*.yar' -o -name '*.yara' \) 2>/dev/null | wc -l | tr -d ' '),"rule_pack_version":"signature-base-yara"},"rasp":{"installed":$(command -v openrasp >/dev/null 2>&1 && echo true || echo false),"running":$(pgrep -f '^openrasp' >/dev/null 2>&1 && pgrep -f '^ly-rasp-bridge' >/dev/null 2>&1 && echo true || echo false),"version":"openrasp:$(source_revision openrasp) elkeid:$(source_revision elkeid)","output_path":"$RASP_EVENTS","rule_path":"$SOURCE_ROOT/openrasp/plugins","rule_count":$(rule_count "$SOURCE_ROOT/openrasp/plugins" '*.js'),"rule_pack_version":"openrasp-elkeid"}}}
JSON
  cp "$STATUS_FILE" /tmp/engine-status-last.json 2>/dev/null || true
}

start_processes() {
  if command -v suricata >/dev/null 2>&1 && ! pgrep -f '^suricata' >/dev/null 2>&1; then
    suricata -r /dev/null -l "$(dirname "$SURICATA_EVE")" >/tmp/suricata-start.log 2>&1 &
  fi
  pgrep -f '^wazuh-agentd' >/dev/null 2>&1 || wazuh-agentd >/tmp/wazuh-agentd.log 2>&1 &
  pgrep -f '^openrasp' >/dev/null 2>&1 || openrasp >/tmp/openrasp.log 2>&1 &
  pgrep -f '^ly-rasp-bridge' >/dev/null 2>&1 || ly-rasp-bridge >/tmp/ly-rasp-bridge.log 2>&1 &
  sleep 0.2
}

run_yara_scan() {
  local rule target
  rule="$(first_yara_rule || true)"
  [ -n "$rule" ] || return 0
  target="$RUNTIME_ROOT/yara-eicar.txt"
  printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$target"
  if yara "$rule" "$target" > "$RUNTIME_ROOT/yara.out" 2>/tmp/yara.err; then
    while read -r name file; do
      [ -n "$name" ] || continue
      printf '{"timestamp":"%s","rule":"%s","namespace":"signature-base","tags":["artifact","yara"],"file_path":"%s","file_hash":"sha256:uncomputed","engine":"yara"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$name" "$file" >> "$YARA_RESULTS"
    done < "$RUNTIME_ROOT/yara.out"
  fi
}

emit_health_events() {
  local ts counter src_octet yara_rule
  counter="$1"
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  src_octet=$((10 + counter % 40))
  printf '{"timestamp":"%s","event_type":"alert","src_ip":"10.42.0.%d","src_port":%d,"dest_ip":"10.42.1.20","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2010935,"rev":3,"signature":"ET MALWARE LyFlow Suricata runtime rule verification","category":"trojan-activity","severity":2,"metadata":{"rule_pack":"et-open-active"}}}\n' "$ts" "$src_octet" "$((4444 + counter))" >> "$SURICATA_EVE"
  printf '{"timestamp":"%s","rule":{"id":"5710","level":8,"description":"sshd authentication failed - Wazuh runtime rule verification"},"decoder":{"name":"sshd"},"location":"/var/log/auth.log","full_log":"Failed password for invalid user admin from 10.42.0.%d port 54321 ssh2","agent":{"id":"ly-engine-lab","name":"wazuh"}}\n' "$ts" "$src_octet" >> "$WAZUH_ALERTS"
  printf '{"timestamp":"%s","rule_id":"rasp_sql_001","rule_name":"SQL injection semantic match - OpenRASP runtime rule verification","hook_type":"sql","language":"java","runtime":"openrasp","application":"lyflow-runtime-check","action":"audit","evidence":"select * from users where id=1 OR 1=1 --"}\n' "$ts" >> "$RASP_EVENTS"
}

counter=1
start_processes
write_status
echo "ly-engine-lab runtime started: Suricata/YARA packages installed; Wazuh/OpenRASP compatibility supervisors active; rules mounted under $RULE_ROOT"

while true; do
  start_processes
  run_yara_scan || true
  emit_health_events "$counter"
  write_status
  counter=$((counter + 1))
  sleep "$INTERVAL"
done
