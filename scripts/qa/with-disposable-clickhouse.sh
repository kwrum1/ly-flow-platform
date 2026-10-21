#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  printf 'usage: %s <command> [args...]\n' "$0" >&2
  exit 2
fi

if [[ -n ${LYFLOW_TEST_CLICKHOUSE_HTTP:-} ]]; then
  exec "$@"
fi

image=clickhouse/clickhouse-server:24.8-alpine
archive=/opt/ly-flow-platform-release-test/images/lyflow-images.tar.gz
loaded_tags=(
  postgres:16-alpine redis:7-alpine clickhouse/clickhouse-server:24.8-alpine
  ly-flow/server:latest ly-flow/frontend:latest ly-flow/security-engine:latest
  ly-flow/security-engines:latest ly-flow/agent:latest
)
new_tags=()
if ! docker image inspect "$image" >/dev/null 2>&1; then
  if [[ ! -r $archive ]]; then
    printf 'cached exact ClickHouse image unavailable; refusing network pull\n' >&2
    exit 1
  fi
  for tag in "${loaded_tags[@]}"; do
    if ! docker image inspect "$tag" >/dev/null 2>&1; then
      new_tags+=("$tag")
    fi
  done
  docker load -i "$archive" >/dev/null
fi

name="lyflow-todo7-clickhouse-$$-$RANDOM"
network="$name-network"
username=todo7
password=todo7-test-password
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  if [[ ${#new_tags[@]} -gt 0 ]]; then
    docker image rm "${new_tags[@]}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

docker network create --internal "$network" >/dev/null
docker run -d --rm --name "$name" --network "$network" \
  -e CLICKHOUSE_USER="$username" -e CLICKHOUSE_PASSWORD="$password" \
  --tmpfs /var/lib/clickhouse --tmpfs /var/log/clickhouse-server \
  "$image" >/dev/null
address=$(docker inspect -f "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}" "$name")
for _ in {1..100}; do
  if docker exec "$name" clickhouse-client --query 'SELECT 1' >/dev/null 2>&1; then
    NO_PROXY="${NO_PROXY:-},$address" LYFLOW_TEST_CLICKHOUSE_HTTP="http://$address:8123/" \
      LYFLOW_TEST_CLICKHOUSE_USER="$username" LYFLOW_TEST_CLICKHOUSE_PASSWORD="$password" "$@"
    exit $?
  fi
  sleep 0.1
done
printf 'disposable ClickHouse failed to become ready\n' >&2
exit 1
