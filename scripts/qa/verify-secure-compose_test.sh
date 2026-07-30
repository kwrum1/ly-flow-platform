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

test_default_service_set_characterization() {
  local actual expected
  expected=$'agent-center\nclickhouse\nly-agent\nly-dpi-engine\nly-engine-lab\nly-local-mirror\nly-security-engine\nly-server\nly-suricata-sensor\nly-vis\npostgres\nredis'
  actual=$(REDIS_ACL_USERNAME=lyflow \
    REDIS_ACL_PASSWORD="$strong_new" \
    SECURITY_ENGINE_CONTROL_TOKEN="$strong_new" \
    docker compose --profile '*' -f "$root/docker-compose.yml" config --services | LC_ALL=C sort)
  [[ "$actual" == "$expected" ]] || {
    printf 'self-test failed: default Compose service set changed\nexpected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    exit 1
  }
}

render_production_compose() (
  local project=$1 output=$2
  shift 2
  export REDIS_ACL_USERNAME=lyflow
  export REDIS_ACL_PASSWORD=$strong_new
  export SECURITY_ENGINE_CONTROL_TOKEN=$strong_new
  if (( $# > 0 )); then
    export "$@"
  fi
  docker compose -p "$project" --profile '*' -f "$root/docker-compose.yml" config --format json >"$output"
)

assert_published_port() {
  local rendered=$1 service=$2 target=$3 published=$4
  jq -e --arg service "$service" --argjson target "$target" --arg published "$published" '
    any(.services[$service].ports[]?;
      .target == $target and (.published | tostring) == $published)
  ' "$rendered" >/dev/null || {
    printf 'self-test failed: %s target %s was not published on %s\n' "$service" "$target" "$published" >&2
    exit 1
  }
}

test_production_compose_project_isolation() {
  local project_a="$tmp/project-a.json" project_b="$tmp/project-b.json"
  render_production_compose lyflow-rc-a "$project_a"
  render_production_compose lyflow-rc-b "$project_b" \
    POSTGRES_BIND_PORT=15432 \
    REDIS_BIND_PORT=16379 \
    CLICKHOUSE_HTTP_BIND_PORT=18123 \
    CLICKHOUSE_NATIVE_BIND_PORT=19000 \
    SERVER_BIND_PORT=18080 \
    HTTPS_BIND_PORT=18443 \
    AGENT_CENTER_BIND_PORT=18081

  jq -e 'all(.services[]; has("container_name") | not)' "$project_a" >/dev/null \
    || { printf 'self-test failed: production Compose contains fixed container_name\n' >&2; exit 1; }
  jq -e 'all(.services[]; has("container_name") | not)' "$project_b" >/dev/null \
    || { printf 'self-test failed: alternate project contains fixed container_name\n' >&2; exit 1; }
  [[ "$(jq -cS '.services | keys' "$project_a")" == "$(jq -cS '.services | keys' "$project_b")" ]] \
    || { printf 'self-test failed: project service sets differ\n' >&2; exit 1; }
  [[ $(jq -r '.networks["ly-network"].name' "$project_a") == lyflow-rc-a_ly-network ]] \
    || { printf 'self-test failed: project A network is not project-scoped\n' >&2; exit 1; }
  [[ $(jq -r '.networks["ly-network"].name' "$project_b") == lyflow-rc-b_ly-network ]] \
    || { printf 'self-test failed: project B network is not project-scoped\n' >&2; exit 1; }

  assert_published_port "$project_a" postgres 5432 5432
  assert_published_port "$project_a" redis 6379 6379
  assert_published_port "$project_a" clickhouse 8123 8123
  assert_published_port "$project_a" clickhouse 9000 9000
  assert_published_port "$project_a" ly-server 8080 8080
  assert_published_port "$project_a" ly-vis 443 443
  assert_published_port "$project_a" agent-center 8081 8081

  assert_published_port "$project_b" postgres 5432 15432
  assert_published_port "$project_b" redis 6379 16379
  assert_published_port "$project_b" clickhouse 8123 18123
  assert_published_port "$project_b" clickhouse 9000 19000
  assert_published_port "$project_b" ly-server 8080 18080
  assert_published_port "$project_b" ly-vis 443 18443
  assert_published_port "$project_b" agent-center 8081 18081

  jq -e '.services["ly-local-mirror"].environment.API_SERVER == "http://127.0.0.1:18080"' "$project_b" >/dev/null \
    || { printf 'self-test failed: local mirror API_SERVER ignores SERVER_BIND_PORT\n' >&2; exit 1; }
  jq -e '.services["ly-local-mirror"].environment.REDIS_SERVER == "127.0.0.1:16379"' "$project_b" >/dev/null \
    || { printf 'self-test failed: local mirror REDIS_SERVER ignores REDIS_BIND_PORT\n' >&2; exit 1; }
}

test_explicit_inherited_data_volumes() {
  local project_a="$tmp/volume-project-a.json" project_b="$tmp/volume-project-b.json"
  render_production_compose lyflow-volume-a "$project_a"
  render_production_compose lyflow-volume-b "$project_b"

  jq -e --arg root "$root" '
    def mounts($service):
      [.services[$service].volumes[]? | {
        type,
        source,
        target,
        read_only: (.read_only // false)
      }] | sort_by(.target);
    def bind($source; $target; $read_only):
      {type: "bind", source: ($root + $source), target: $target, read_only: $read_only};
    def volume($source; $target; $read_only):
      {type: "volume", source: $source, target: $target, read_only: $read_only};

    mounts("ly-server") == ([
      bind("/rules"; "/etc/ly/rules"; true),
      bind("/rules"; "/app/rules"; false),
      bind("/.sisyphus"; "/app/.sisyphus"; false),
      {type: "bind", source: "/sys", target: "/host/sys", read_only: true},
      volume("policy_trust"; "/var/lib/lyflow/policy"; false),
      volume("ly_server_data"; "/data"; false)
    ] | sort_by(.target)) and
    mounts("agent-center") == ([
      volume("agent_center_data"; "/data"; false)
    ] | sort_by(.target)) and
    mounts("ly-security-engine") == ([
      bind("/rules"; "/app/rules"; true),
      volume("policy_trust"; "/var/lib/lyflow/policy"; true),
      volume("security_engine_audit"; "/var/lib/lyflow/audit"; false),
      volume("security_engine_data"; "/data"; false)
    ] | sort_by(.target)) and
    mounts("ly-engine-lab") == ([
      bind("/.sisyphus/runtime/engine-outputs/suricata"; "/var/log/suricata"; false),
      bind("/.sisyphus/runtime/engine-outputs/wazuh"; "/var/ossec/logs/alerts"; false),
      bind("/.sisyphus/runtime/engine-outputs/yara"; "/opt/ly-agent/yara"; false),
      bind("/.sisyphus/runtime/engine-outputs/rasp"; "/opt/ly-agent/rasp"; false),
      bind("/.sisyphus/runtime/engine-outputs/status"; "/opt/ly-engine-lab/runtime"; false),
      bind("/rules"; "/opt/ly-engine-lab/rules"; true),
      volume("engine_lab_data"; "/data"; false)
    ] | sort_by(.target)) and
    mounts("ly-local-mirror") == ([
      volume("agent_spool"; "/opt/ly-agent/data"; false),
      volume("policy_trust"; "/var/lib/lyflow/policy"; true),
      volume("local_mirror_data"; "/data"; false)
    ] | sort_by(.target))
  ' "$project_a" >/dev/null || {
    printf 'self-test failed: explicit /data mappings changed or existing mounts were not preserved\n' >&2
    exit 1
  }

  local project rendered volume_name
  for project in lyflow-volume-a lyflow-volume-b; do
    if [[ "$project" == lyflow-volume-a ]]; then
      rendered=$project_a
    else
      rendered=$project_b
    fi
    for volume_name in \
      ly_server_data \
      agent_center_data \
      security_engine_data \
      engine_lab_data \
      local_mirror_data; do
      [[ $(jq -r --arg volume "$volume_name" '.volumes[$volume].name // ""' "$rendered") == "${project}_${volume_name}" ]] || {
        printf 'self-test failed: volume %s is absent or not project-scoped for %s\n' "$volume_name" "$project" >&2
        exit 1
      }
    done
    [[ $(jq -r '[.volumes.ly_server_data.name, .volumes.agent_center_data.name, .volumes.security_engine_data.name, .volumes.engine_lab_data.name, .volumes.local_mirror_data.name] | unique | length' "$rendered") -eq 5 ]] || {
      printf 'self-test failed: explicit /data volumes are not distinct for %s\n' "$project" >&2
      exit 1
    }
  done
}

inventory="$tmp/inventory.txt"
compose="$tmp/compose.yml"
retired_override="$tmp/compose.retired.yml"
common=(--compose-file "$compose" --inventory "$inventory" --mode enforce)
strong_new='8f97b65d1a2c43e0b4d5690f8a7c6e51'
strong_old='742ac30891ef56d4b7083c2e19fa65bd'

case "${1:-}" in
  --explicit-data-volumes)
    test_explicit_inherited_data_volumes
    exit 0
    ;;
  '')
    ;;
  *)
    printf 'self-test failed: unknown argument: %s\n' "$1" >&2
    exit 1
    ;;
esac

test_default_service_set_characterization
test_production_compose_project_isolation
test_explicit_inherited_data_volumes

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
