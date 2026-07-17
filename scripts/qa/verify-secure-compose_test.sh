#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
verifier="$root/scripts/qa/verify-secure-compose.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

write_inventory() {
  local path=$1
  local new_password_path=${2:-REDIS_ACL_PASSWORD}
  printf '%s\n' \
    '# id|class|source|compose_service|address_path|new_username_path|new_password_path|legacy_password_path' \
    "server-main|active|server/cmd/main.go|ly-server|REDIS_ADDR|REDIS_ACL_USERNAME|${new_password_path}|REDIS_PASSWORD" \
    'redis-healthcheck|healthcheck|docker-compose.yml|redis|redis service|--user|--pass|-' \
    >"$path"
}

write_compose() {
  local path=$1
  local redis_host_ip=$2
  local new_secret=$3
  local legacy_secret=$4
  local legacy_line=''
  local redis_command='    command: [/bin/sh, -ec, '\''exec redis-server --user "$$REDIS_ACL_USERNAME" on ">$$REDIS_ACL_PASSWORD"'\'']'
  if [[ -n "$legacy_secret" ]]; then
    legacy_line="      REDIS_PASSWORD: '$legacy_secret'"
    redis_command='    command: [/bin/sh, -ec, '\''exec redis-server --requirepass "$$REDIS_PASSWORD" --user "$$REDIS_ACL_USERNAME" on ">$$REDIS_ACL_PASSWORD"'\'']'
  fi
  if [[ "${5:-secure}" == 'missing' ]]; then
    redis_command=''
  fi

  cat >"$path" <<EOF
services:
  redis:
    image: scratch
    environment:
      REDIS_ADDR: redis:6379
      REDIS_ACL_USERNAME: lyflow
      REDIS_ACL_PASSWORD: '$new_secret'
$legacy_line
$redis_command
    ports:
      - host_ip: '$redis_host_ip'
        published: '6379'
        target: 6379
    healthcheck:
      test: [CMD, redis-cli, --user, lyflow, --pass, '$new_secret', ping]
  ly-server:
    image: scratch
    environment:
      REDIS_ADDR: redis:6379
      REDIS_ACL_USERNAME: lyflow
      REDIS_ACL_PASSWORD: '$new_secret'
$legacy_line
    ports:
      - host_ip: 127.0.0.1
        published: '8080'
        target: 8080
  ly-local-mirror:
    image: scratch
    network_mode: host
    environment:
      API_SERVER: http://127.0.0.1:8080
      REDIS_SERVER: 127.0.0.1:6379
      REDIS_ACL_USERNAME: lyflow
      REDIS_ACL_PASSWORD: '$new_secret'
$legacy_line
EOF
}

write_retired_override() {
  local path=$1
  local preserve_legacy=${2:-false}
  local client_reset='      REDIS_PASSWORD: !reset null'
  if [[ "$preserve_legacy" == 'true' ]]; then
    client_reset=''
  fi

  cat >"$path" <<EOF
services:
  redis:
    environment:
      REDIS_PASSWORD: !reset null
    command: [/bin/sh, -ec, 'exec redis-server --user "\$\$REDIS_ACL_USERNAME" on ">\$\$REDIS_ACL_PASSWORD"']
  ly-server:
    environment:
$client_reset
  ly-local-mirror:
    environment:
      REDIS_PASSWORD: !reset null
EOF
}

expect_rejected() {
  local name=$1
  shift
  if bash "$verifier" "$@" >/dev/null 2>&1; then
    printf 'self-test failed: %s was accepted\n' "$name" >&2
    exit 1
  fi
}

expect_accepted() {
  local name=$1
  shift
  if ! bash "$verifier" "$@" >/dev/null 2>&1; then
    printf 'self-test failed: %s was rejected\n' "$name" >&2
    bash "$verifier" "$@" || true
    exit 1
  fi
}

inventory="$tmp/inventory.txt"
compose="$tmp/compose.yml"
retired_override="$tmp/compose.retired.yml"
common=(--compose-file "$compose" --inventory "$inventory" --mode enforce)
strong_new='8f97b65d1a2c43e0b4d5690f8a7c6e51'
strong_old='742ac30891ef56d4b7083c2e19fa65bd'

write_inventory "$inventory"
write_compose "$compose" 127.0.0.1 '' "$strong_old"
expect_rejected 'empty Redis secret' --phase bridge "${common[@]}"

write_compose "$compose" 127.0.0.1 'change_me_in_production' "$strong_old"
expect_rejected 'default Redis secret' --phase bridge "${common[@]}"

write_compose "$compose" 0.0.0.0 "$strong_new" "$strong_old"
expect_rejected 'non-loopback Redis publication' --phase bridge "${common[@]}"

write_compose "$compose" 127.0.0.1 "$strong_new" "$strong_old"
write_inventory "$inventory" '-'
expect_rejected 'missing client credential path' --phase bridge "${common[@]}"

write_inventory "$inventory"
write_compose "$compose" 127.0.0.1 "$strong_new" "$strong_old"
write_compose "$compose" 127.0.0.1 "$strong_new" "$strong_old" missing
expect_rejected 'missing Redis startup authentication' --phase bridge "${common[@]}"

write_compose "$compose" 127.0.0.1 "$strong_new" "$strong_old"
write_retired_override "$retired_override" true
expect_rejected 'legacy credential surviving retired override' --phase retired --retired-compose-file "$retired_override" "${common[@]}"

expect_accepted 'old and new bridge metadata' --phase bridge "${common[@]}"

write_retired_override "$retired_override"
expect_accepted 'retired override removes legacy metadata' --phase retired --retired-compose-file "$retired_override" "${common[@]}"

printf 'secure Compose harness self-test passed\n'
