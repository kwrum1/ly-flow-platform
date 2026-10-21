#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
compose_file="$root/docker-compose.yml"
retired_compose_file="$root/docker-compose.redis-retired.yml"
default_inventory="$root/scripts/qa/redis-client-inventory.txt"
inventory=$default_inventory
phase=''
mode='enforce'

usage() {
  printf 'usage: %s --phase <bridge|retired> [--mode <enforce|report>] [--compose-file <path>] [--retired-compose-file <path>] [--inventory <path>]\n' "$0" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      phase=$2
      shift 2
      ;;
    --mode)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      mode=$2
      shift 2
      ;;
    --compose-file)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      compose_file=$2
      shift 2
      ;;
    --retired-compose-file)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      retired_compose_file=$2
      shift 2
      ;;
    --inventory)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      inventory=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ "$phase" == 'bridge' || "$phase" == 'retired' ]] || { usage; exit 2; }
[[ "$mode" == 'enforce' || "$mode" == 'report' ]] || { usage; exit 2; }
[[ -f "$compose_file" ]] || { printf 'compose file not found: %s\n' "$compose_file" >&2; exit 2; }
if [[ "$phase" == 'retired' && ! -f "$retired_compose_file" ]]; then
  printf 'retired Compose file not found: %s\n' "$retired_compose_file" >&2
  exit 2
fi
[[ -f "$inventory" ]] || { printf 'inventory not found: %s\n' "$inventory" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { printf 'docker is required\n' >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { printf 'jq is required\n' >&2; exit 2; }

rendered=$(mktemp)
trap 'rm -f "$rendered"' EXIT INT TERM
compose_args=(--profile '*' -f "$compose_file")
if [[ "$phase" == 'retired' ]]; then
  compose_args+=(-f "$retired_compose_file")
fi
docker compose "${compose_args[@]}" config --format json >"$rendered"
jq -e '.services | type == "object"' "$rendered" >/dev/null

findings=0
finding() {
  findings=$((findings + 1))
  printf 'FAIL: %s\n' "$*" >&2
}

is_bad_secret() {
  local value=$1
  local lower=${value,,}
  if [[ ${#value} -lt 16 ]]; then
    return 0
  fi
  case "$lower" in
    password|redis|secret|default|changeme|change_me|change-me|*change*production*|*default*password*|*redis*password*|*secret*password*)
      return 0
      ;;
  esac
  return 1
}

env_has() {
  local service=$1
  local key=$2
  jq -e --arg service "$service" --arg key "$key" \
    '.services[$service].environment // {} | has($key)' "$rendered" >/dev/null
}

env_value() {
  local service=$1
  local key=$2
  jq -r --arg service "$service" --arg key "$key" \
    '.services[$service].environment[$key] // ""' "$rendered"
}

service_exists() {
  local service=$1
  jq -e --arg service "$service" '.services | has($service)' "$rendered" >/dev/null
}

port_is_loopback() {
  local service=$1
  local target=$2
  jq -e --arg service "$service" --argjson target "$target" '
    [(.services[$service].ports // [])[]
      | select(.target == $target)
      | select(.host_ip == "127.0.0.1" or .host_ip == "::1")] | length > 0
  ' "$rendered" >/dev/null
}

while IFS='|' read -r service host_ip published; do
  case "$host_ip" in
    127.0.0.1|::1) ;;
    *) finding "data service $service publishes $published on non-loopback host IP '${host_ip:-all interfaces}'" ;;
  esac
done < <(jq -r '
  .services | to_entries[]
  | select(.key == "redis" or .key == "postgres" or .key == "clickhouse")
  | .key as $service
  | (.value.ports // [])[]
  | [$service, (.host_ip // ""), (.published // "")] | join("|")
' "$rendered")

if [[ "$phase" == 'retired' ]]; then
  while IFS= read -r service; do
    finding "retired service $service still renders REDIS_PASSWORD"
  done < <(jq -r '
    .services | to_entries[]
    | select((.value.environment // {}) | has("REDIS_PASSWORD"))
    | .key
  ' "$rendered")
fi

if ! service_exists 'ly-local-mirror'; then
  finding 'ly-local-mirror service is missing'
else
  mirror_mode=$(jq -r '.services["ly-local-mirror"].network_mode // ""' "$rendered")
  [[ "$mirror_mode" == 'host' ]] || finding 'ly-local-mirror must retain host network mode'
  mirror_redis=$(env_value 'ly-local-mirror' 'REDIS_SERVER')
  mirror_api=$(env_value 'ly-local-mirror' 'API_SERVER')
  [[ "$mirror_redis" == 127.0.0.1:* ]] || finding 'ly-local-mirror REDIS_SERVER must use 127.0.0.1'
  [[ "$mirror_api" == http://127.0.0.1:* || "$mirror_api" == https://127.0.0.1:* ]] || finding 'ly-local-mirror API_SERVER must use 127.0.0.1'
fi

port_is_loopback 'redis' 6379 || finding 'Redis must retain a 127.0.0.1/::1 publication for ly-local-mirror'
port_is_loopback 'ly-server' 8080 || finding 'ly-server API must retain a 127.0.0.1/::1 publication for ly-local-mirror'

redis_command=$(jq -r '(.services.redis.command // []) | join(" ")' "$rendered")
for key in REDIS_ACL_USERNAME REDIS_ACL_PASSWORD; do
  if ! env_has 'redis' "$key" || [[ -z "$(env_value 'redis' "$key")" ]]; then
    finding "Redis service lacks non-empty $key"
  fi
done
if is_bad_secret "$(env_value 'redis' 'REDIS_ACL_PASSWORD')"; then
  finding 'Redis service has an empty, weak, or default ACL password'
fi
[[ "$redis_command" == *'--user'* && "$redis_command" == *'REDIS_ACL_USERNAME'* && "$redis_command" == *'REDIS_ACL_PASSWORD'* ]] \
  || finding 'Redis service command lacks named ACL user authentication metadata'
if [[ "$phase" == 'bridge' ]]; then
  if ! env_has 'redis' 'REDIS_PASSWORD' || is_bad_secret "$(env_value 'redis' 'REDIS_PASSWORD')"; then
    finding 'Redis service lacks a non-default legacy bridge password'
  fi
  [[ "$redis_command" == *'--requirepass'* && "$redis_command" == *'REDIS_PASSWORD'* ]] \
    || finding 'Redis service command lacks legacy bridge authentication metadata'
elif env_has 'redis' 'REDIS_PASSWORD' || [[ "$redis_command" == *'REDIS_PASSWORD'* || "$redis_command" == *'--requirepass'* ]]; then
  finding 'retired Redis service still exposes legacy authentication metadata'
fi

declare -A seen_ids=()
inventory_rows=0
while IFS='|' read -r id class source service address_path new_username_path new_password_path legacy_password_path extra; do
  [[ -z "$id" || "$id" == \#* ]] && continue
  inventory_rows=$((inventory_rows + 1))
  if [[ -n "${extra:-}" || -z "$class" || -z "$source" || -z "$service" || -z "$address_path" || -z "$new_username_path" || -z "$new_password_path" || -z "$legacy_password_path" ]]; then
    finding "malformed inventory row: $id"
    continue
  fi
  if [[ -n "${seen_ids[$id]:-}" ]]; then
    finding "duplicate inventory id: $id"
  fi
  seen_ids[$id]=1
  [[ -e "$root/$source" ]] || finding "inventory source does not exist for $id: $source"

  if [[ "$class" == 'none' ]]; then
    [[ "$service" == '-' && "$address_path" == '-' && "$new_username_path" == '-' && "$new_password_path" == '-' && "$legacy_password_path" == '-' ]] \
      || finding "Redis-free inventory row $id must use dashes for all client paths"
    continue
  fi

  if [[ "$class" == 'inactive' ]]; then
    [[ "$service" == '-' && "$address_path" != '-' && "$new_username_path" == '-' && "$new_password_path" == '-' && "$legacy_password_path" == '-' ]] \
      || finding "inactive Redis inventory row $id must declare only its dormant address path"
    continue
  fi

  [[ "$address_path" != '-' ]] || finding "Redis client $id has no address config path"
  [[ "$new_username_path" != '-' ]] || finding "Redis client $id has no new username config path"
  [[ "$new_password_path" != '-' ]] || finding "Redis client $id has no new credential config path"

  if [[ "$service" == '-' ]]; then
    continue
  fi
  if ! service_exists "$service"; then
    finding "inventory client $id references missing rendered service $service"
    continue
  fi
  if [[ "$class" == 'healthcheck' ]]; then
    healthcheck=$(jq -r --arg service "$service" '(.services[$service].healthcheck.test // []) | join(" ")' "$rendered")
    [[ "$new_username_path" != '-' && "$healthcheck" == *"$new_username_path"* ]] \
      || finding "Redis healthcheck $id lacks new username authentication metadata"
    [[ "$new_password_path" != '-' && "$healthcheck" == *"$new_password_path"* ]] \
      || finding "Redis healthcheck $id lacks new credential authentication metadata"
    if [[ "$phase" == 'retired' && "$legacy_password_path" != '-' && "$healthcheck" == *"$legacy_password_path"* ]]; then
      finding "retired Redis healthcheck $id still exposes legacy authentication metadata"
    fi
    continue
  fi

  for key in "$address_path" "$new_username_path" "$new_password_path"; do
    [[ "$key" == '-' ]] && continue
    if ! env_has "$service" "$key" || [[ -z "$(env_value "$service" "$key")" ]]; then
      finding "rendered service $service lacks non-empty $key for client $id"
    fi
  done
  if [[ "$new_password_path" != '-' ]]; then
    new_secret=$(env_value "$service" "$new_password_path")
    if is_bad_secret "$new_secret"; then
      finding "rendered service $service has an empty, weak, or default new Redis secret for client $id"
    fi
  fi

  if [[ "$phase" == 'bridge' ]]; then
    if [[ "$legacy_password_path" != '-' ]]; then
      legacy_secret=$(env_value "$service" "$legacy_password_path")
      if ! env_has "$service" "$legacy_password_path" || is_bad_secret "$legacy_secret"; then
        finding "bridge service $service lacks a non-default legacy Redis credential for client $id"
      fi
    fi
  elif [[ "$legacy_password_path" != '-' ]] && env_has "$service" "$legacy_password_path"; then
    finding "retired service $service still exposes legacy Redis credential path $legacy_password_path for client $id"
  fi
done <"$inventory"

[[ $inventory_rows -gt 0 ]] || finding 'Redis client inventory is empty'

if [[ "$inventory" == "$default_inventory" ]]; then
  required_ids=(
    server-main server-xdr agent-center security-engine
    agent-main-publishers agent-local-mirror agent-afpacket-linux
    python-rasp java-rasp redis-healthcheck script-test-e2e script-test-perf
    script-validate-stream-bus agent-spool-integration-test engine-lab-adapters
  )
  for id in "${required_ids[@]}"; do
    [[ -n "${seen_ids[$id]:-}" ]] || finding "known Redis surface missing from inventory: $id"
  done
fi

if [[ $findings -eq 0 ]]; then
  printf 'SECURE_COMPOSE_RESULT=PASS phase=%s inventory_rows=%d\n' "$phase" "$inventory_rows"
  exit 0
fi

printf 'SECURE_COMPOSE_RESULT=FAIL phase=%s findings=%d inventory_rows=%d\n' "$phase" "$findings" "$inventory_rows" >&2
if [[ "$mode" == 'report' ]]; then
  exit 0
fi
exit 1
