#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  printf 'usage: %s <command> [args...]\n' "$0" >&2
  exit 2
fi

if [[ -n ${LYFLOW_TEST_CLICKHOUSE_HTTP:-} && -n ${LYFLOW_TEST_POSTGRES_DSN:-} ]]; then
  exec "$@"
fi

clickhouse_image=clickhouse/clickhouse-server:24.8-alpine
postgres_image=postgres:16-alpine
archive=/opt/ly-flow-platform-release-test/images/lyflow-images.tar.gz
loaded_tags=(
  postgres:16-alpine redis:7-alpine clickhouse/clickhouse-server:24.8-alpine
  ly-flow/server:latest ly-flow/frontend:latest ly-flow/security-engine:latest
  ly-flow/security-engines:latest ly-flow/agent:latest
)
new_tags=()
for image in "$clickhouse_image" "$postgres_image"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    if [[ ! -r $archive ]]; then
      printf 'cached exact event-store image unavailable: %s; refusing network pull\n' "$image" >&2
      exit 1
    fi
    for tag in "${loaded_tags[@]}"; do
      if ! docker image inspect "$tag" >/dev/null 2>&1; then
        new_tags+=("$tag")
      fi
    done
    docker load -i "$archive" >/dev/null
    break
  fi
done

prefix="lyflow-todo10-event-stores-$$-$RANDOM"
network="$prefix-network"
clickhouse_name="$prefix-clickhouse"
postgres_name="$prefix-postgres"
clickhouse_user=todo10
clickhouse_password=todo10-clickhouse-password
postgres_user=todo10
postgres_password=todo10-postgres-password
cleanup() {
  docker rm -f "$clickhouse_name" "$postgres_name" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  if [[ ${#new_tags[@]} -gt 0 ]]; then
    docker image rm "${new_tags[@]}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

docker network create --internal "$network" >/dev/null
docker run -d --rm --pull=never --name "$clickhouse_name" --network "$network" \
  -e CLICKHOUSE_USER="$clickhouse_user" -e CLICKHOUSE_PASSWORD="$clickhouse_password" \
  --tmpfs /var/lib/clickhouse:rw,size=256m --tmpfs /var/log/clickhouse-server:rw,size=32m \
  "$clickhouse_image" >/dev/null
docker run -d --rm --pull=never --name "$postgres_name" --network "$network" \
  -e POSTGRES_DB=todo10 -e POSTGRES_USER="$postgres_user" -e POSTGRES_PASSWORD="$postgres_password" \
  --tmpfs /var/lib/postgresql/data:rw,size=256m "$postgres_image" >/dev/null

clickhouse_address=$(docker inspect -f "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}" "$clickhouse_name")
postgres_address=$(docker inspect -f "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}" "$postgres_name")
for _ in {1..150}; do
  if docker exec "$clickhouse_name" clickhouse-client --query 'SELECT 1' >/dev/null 2>&1 && \
    docker exec "$postgres_name" pg_isready -U "$postgres_user" -d todo10 >/dev/null 2>&1; then
    NO_PROXY="${NO_PROXY:-},$clickhouse_address,$postgres_address" \
      LYFLOW_TEST_CLICKHOUSE_HTTP="http://$clickhouse_address:8123/" \
      LYFLOW_TEST_CLICKHOUSE_USER="$clickhouse_user" \
      LYFLOW_TEST_CLICKHOUSE_PASSWORD="$clickhouse_password" \
      LYFLOW_TEST_POSTGRES_DSN="postgres://$postgres_user:$postgres_password@$postgres_address:5432/todo10?sslmode=disable" \
      "$@"
    exit $?
  fi
  sleep 0.1
done
printf 'disposable ClickHouse/Postgres event stores failed to become ready\n' >&2
exit 1
