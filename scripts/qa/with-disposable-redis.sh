#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  printf 'usage: %s <command> [args...]\n' "$0" >&2
  exit 2
fi

if [[ -n ${LYFLOW_TEST_REDIS_ADDR:-} ]]; then
  exec "$@"
fi

image=redis:7-alpine
archive=/opt/ly-flow-platform-release-test/images/lyflow-images.tar.gz
loaded=false
loaded_tags=(
  postgres:16-alpine redis:7-alpine clickhouse/clickhouse-server:24.8-alpine
  ly-flow/server:latest ly-flow/frontend:latest ly-flow/security-engine:latest
  ly-flow/security-engines:latest ly-flow/agent:latest
)
if ! docker image inspect "$image" >/dev/null 2>&1; then
  if [[ ! -r $archive ]]; then
    printf 'cached Redis image unavailable; refusing network pull\n' >&2
    exit 1
  fi
  docker load -i "$archive" >/dev/null
  loaded=true
fi

name="lyflow-todo6-redis-$$-$RANDOM"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  if [[ $loaded == true ]]; then
    docker image rm "${loaded_tags[@]}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

docker run -d --rm --name "$name" -p 127.0.0.1::6379 "$image" redis-server --save '' --appendonly no >/dev/null
port=$(docker port "$name" 6379/tcp | cut -d: -f2)
for _ in {1..50}; do
  if [[ $(docker exec "$name" redis-cli ping 2>/dev/null | tr -d '\r') == PONG ]]; then
    LYFLOW_TEST_REDIS_ADDR="127.0.0.1:$port" "$@"
    exit $?
  fi
  sleep 0.1
done
printf 'disposable Redis failed to become ready\n' >&2
exit 1
