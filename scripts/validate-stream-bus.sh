#!/usr/bin/env bash
set -euo pipefail

STREAMS=(
  "flows:raw"
  "flows:semantic"
  "sessions:semantic"
  "alerts:dpi"
  "alerts:runtime"
  "alerts:rasp"
  "alerts:xdr"
  "events:xdr"
)

REDIS_CONTAINER="${REDIS_CONTAINER:-ly-redis}"
REDIS_ADDR="${REDIS_ADDR:-}"

redis_cli() {
  if [[ -n "$REDIS_CONTAINER" ]]; then
    docker exec "$REDIS_CONTAINER" redis-cli "$@"
    return
  fi

  if [[ -z "$REDIS_ADDR" ]]; then
    printf 'ERROR: set REDIS_CONTAINER or REDIS_ADDR\n' >&2
    return 2
  fi

  local host="${REDIS_ADDR%:*}"
  local port="${REDIS_ADDR##*:}"
  redis-cli -h "$host" -p "$port" "$@"
}

stream_latest_id() {
  local stream="$1"
  redis_cli XREVRANGE "$stream" + - COUNT 1 2>/dev/null | sed -n '1p'
}

stream_group_summary() {
  local stream="$1"
  local groups
  if ! groups="$(redis_cli XINFO GROUPS "$stream" 2>/dev/null)"; then
    printf 'consumer_groups=none'
    return
  fi
  if [[ -z "$groups" ]]; then
    printf 'consumer_groups=none'
    return
  fi
  if [[ "$groups" == ERR* ]]; then
    printf 'consumer_groups=none'
    return
  fi
  printf '%s' "$groups" | tr '\n' ' '
}

main() {
  printf '# Redis Stream Bus Validation\n\n'
  printf 'redis_container=%s\n' "${REDIS_CONTAINER:-none}"
  printf 'redis_addr=%s\n\n' "${REDIS_ADDR:-none}"

  if ! redis_cli PING >/dev/null; then
    printf 'ERROR: Redis ping failed\n' >&2
    return 1
  fi

  printf '| stream | length | latest_id | consumer_groups |\n'
  printf '|---|---:|---|---|\n'
  local stream length latest groups
  for stream in "${STREAMS[@]}"; do
    length="$(redis_cli XLEN "$stream")"
    latest="$(stream_latest_id "$stream")"
    groups="$(stream_group_summary "$stream")"
    if [[ -z "$latest" ]]; then
      latest='none'
    fi
    printf '| %s | %s | %s | %s |\n' "$stream" "$length" "$latest" "$groups"
  done
}

main "$@"
