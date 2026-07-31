#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
if [[ -z ${LYFLOW_TEST_REDIS_ADDR:-} || -z ${LYFLOW_TEST_POSTGRES_DSN:-} || -z ${LYFLOW_TEST_CLICKHOUSE_HTTP:-} ]]; then
  exec "$root/scripts/qa/with-disposable-redis.sh" \
    "$root/scripts/qa/with-disposable-event-stores.sh" \
    bash "$root/scripts/qa/t12-live-ui_test.sh"
fi

evidence=$root/acceptance-evidence/T12/ui
replay=$root/acceptance-evidence/T12/replay
admin_username=admin
initial_admin_password='T12Initial1!'
admin_password='T12Changed2!'
server_port=18080
spool_key=3031323334353637383961626364656630313233343536373839616263646566
temp=$(mktemp -d /tmp/lyflow-t12-live-ui.XXXXXX)
server_pid=

cleanup() {
  [[ -z $server_pid ]] || kill "$server_pid" >/dev/null 2>&1 || true
  rm -rf "$temp"
}
trap cleanup EXIT INT TERM

for tool in curl go jq npm psql; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'T12 live UI missing tool: %s\n' "$tool" >&2; exit 1; }
done
for input in "$replay/four-source/eve.json" "$replay/stamus/eve.json"; do
  [[ -s $input ]] || { printf 'T12 live UI missing replay EVE: %s\n' "$input" >&2; exit 1; }
done

rm -rf "$evidence"
mkdir -p "$evidence" "$temp/server-spool" "$temp/agent-spool"
git -C "$root" status --short >"$evidence/worktree-status.txt"
git -C "$root" rev-parse HEAD >"$evidence/start-commit.txt"

for _ in {1..50}; do
  psql "$LYFLOW_TEST_POSTGRES_DSN" -c 'SELECT 1' >/dev/null 2>&1 && break
  sleep 0.1
done
psql "$LYFLOW_TEST_POSTGRES_DSN" -v ON_ERROR_STOP=1 \
  -f "$root/scripts/init-db.sql" -f "$root/server/sql/asset_tables.sql" >"$evidence/postgres-init.log"

dsn=${LYFLOW_TEST_POSTGRES_DSN#postgres://}
auth=${dsn%%@*}
location=${dsn#*@}
host_port=${location%%/*}
database_query=${location#*/}
db_user=${auth%%:*}
db_password=${auth#*:}
db_host=${host_port%%:*}
db_port=${host_port##*:}
db_name=${database_query%%\?*}

env GOWORK=off GOTOOLCHAIN=auto GOSUMDB=sum.golang.org \
  go -C "$root/server" build -o "$temp/ly-server" ./cmd
env \
  DB_HOST="$db_host" DB_PORT="$db_port" DB_USER="$db_user" DB_PASSWORD="$db_password" DB_NAME="$db_name" DB_SSLMODE=disable \
  REDIS_ADDR="$LYFLOW_TEST_REDIS_ADDR" \
  CLICKHOUSE_ADDR="$LYFLOW_TEST_CLICKHOUSE_HTTP" CLICKHOUSE_DB=default \
  CLICKHOUSE_USER="$LYFLOW_TEST_CLICKHOUSE_USER" CLICKHOUSE_PASSWORD="$LYFLOW_TEST_CLICKHOUSE_PASSWORD" \
  SERVER_PORT="$server_port" JWT_SECRET=t12-live-jwt-secret \
  DEFAULT_ADMIN_PASSWORD="$initial_admin_password" \
  LYFLOW_RESET_ADMIN_PASSWORD=true LYFLOW_FORCE_FIRST_LOGIN_PASSWORD_CHANGE=false \
  AGENT_ID=t12-packet-sensor AGENT_KEY=t12-agent-key \
  SECURITY_ENGINE_ENABLED=false SECURITY_ENGINE_RELOAD_URL=http://127.0.0.1:9/reload \
  SECURITY_ENGINE_CONTROL_TOKEN=t12-control-token INCIDENT_LIFECYCLE_LEGACY_MODE=true \
  RULE_LIFECYCLE_DIR="$temp/lifecycle" RULE_BASELINE_BUNDLE="$root/rules/security-engine/active-bundle.json" \
  ENGINE_RULE_ROOT="$root/rules" XDR_RULES_DIR="$root/rules/xdr" \
  POLICY_TRUST_DIR="$temp/policy" POLICY_KEY_DIR="$temp/keys" CONTROL_AUDIT_DIR="$temp/audit" \
  XDR_RESPONSE_POLICY_PATH="$temp/xdr-response-policy.json" LYFLOW_SERVICE_LOCK_PATH="$temp/server.lock" \
  LYFLOW_TRANSPORT_SPOOL_KEY="$spool_key" LYFLOW_TRANSPORT_SPOOL_DIR="$temp/server-spool" \
  "$temp/ly-server" >"$evidence/server.log" 2>&1 &
server_pid=$!

for _ in {1..240}; do
  if curl --fail --silent "http://127.0.0.1:$server_port/api/v1/health" >/dev/null 2>&1; then
    break
  fi
  kill -0 "$server_pid" 2>/dev/null || { printf 'T12 temporary server exited\n' >&2; exit 1; }
  sleep 0.25
done
curl --fail --silent "http://127.0.0.1:$server_port/api/v1/health" >"$evidence/server-health.json"

login_response=$(curl --fail --silent --show-error \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg username "$admin_username" --arg password "$initial_admin_password" '{username:$username,password:$password}')" \
  "http://127.0.0.1:$server_port/api/v1/auth/login")
admin_token=$(jq -er '.data.token' <<<"$login_response")
curl --fail --silent --show-error \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $admin_token" \
  -d "$(jq -nc --arg old "$initial_admin_password" --arg new "$admin_password" '{old_password:$old,new_password:$new}')" \
  "http://127.0.0.1:$server_port/api/v1/auth/change-password" >/dev/null

env \
T12_REAL_DETECTION_EVE_DIR="$replay" \
	T12_REAL_DETECTION_MANIFEST="$root/fixtures/real-detections/v1/manifest.json" \
  T12_REAL_DETECTION_API="http://127.0.0.1:$server_port" T12_REAL_DETECTION_AGENT_KEY=t12-agent-key \
  LYFLOW_TRANSPORT_SPOOL_KEY="$spool_key" GOWORK=off GOTOOLCHAIN=auto GOSUMDB=sum.golang.org \
  go -C "$root/agent" test -race -count=1 ./cmd -run '^TestRealDetectionEVE_publishesFiveNativeSourcesToRedis$' \
  >"$evidence/agent-integration.log" 2>&1

for _ in {1..240}; do
  read -r event_count source_count < <(psql "$LYFLOW_TEST_POSTGRES_DSN" -Atc \
    "SELECT COUNT(*), COUNT(DISTINCT raw_event->'native_rule'->>'source') FROM threat_events WHERE source_engine='suricata'" | tr '|' ' ')
  if [[ $event_count -eq 9 && $source_count -eq 5 ]]; then
    break
  fi
  sleep 0.25
done
[[ ${event_count:-0} -eq 9 && ${source_count:-0} -eq 5 ]] || {
  printf 'T12 live persistence mismatch: events=%s sources=%s\n' "${event_count:-0}" "${source_count:-0}" >&2
  exit 1
}

env \
  CI=true VITE_API_TARGET="http://127.0.0.1:$server_port" \
  T12_UI_BASE_URL=http://127.0.0.1:3000 T12_UI_USERNAME="$admin_username" T12_UI_PASSWORD="$admin_password" \
  T12_UI_EVIDENCE_DIR="$evidence/screenshots" \
  npm --prefix "$root/frontend" exec -- playwright test \
  --config "$root/frontend/playwright.config.js" t12-real-detections.spec.js --project chromium \
  >"$evidence/playwright.log" 2>&1 || {
    cat "$evidence/playwright.log" >&2
    exit 1
  }

jq -e '.sources | length == 5' "$evidence/screenshots/t12-real-detections.json" >/dev/null
jq -n --slurpfile detections "$evidence/screenshots/t12-real-detections.json" \
  --argjson event_count "$event_count" --argjson source_count "$source_count" '
    {
      schema_version: "lyflow.t12.live_ui_result/v1",
      status: "PASS",
      persisted_event_count: $event_count,
      persisted_source_count: $source_count,
      browser_sources: $detections[0].sources
    }
  ' >"$evidence/result.json"
printf 'T12 live UI PASS: %s\n' "$evidence/result.json"
