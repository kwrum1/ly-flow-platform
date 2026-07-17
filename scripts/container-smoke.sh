#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SMOKE_TIMEOUT_SECONDS=${LYFLOW_SMOKE_TIMEOUT_SECONDS:-180}
SMOKE_BUILD_TIMEOUT_SECONDS=${LYFLOW_SMOKE_BUILD_TIMEOUT_SECONDS:-300}
SMOKE_INTERVAL_SECONDS=${LYFLOW_SMOKE_INTERVAL_SECONDS:-2}
SMOKE_PROJECT=${LYFLOW_SMOKE_PROJECT:-lyflow-smoke-$(date +%s)-$$}
SMOKE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/lyflow-smoke.XXXXXX")
ENV_FILE="$SMOKE_DIR/smoke.env"
OVERRIDE_FILE="$SMOKE_DIR/compose.override.yml"
RUNTIME_DIR="$SMOKE_DIR/runtime"
SERVER_CONTEXT="$SMOKE_DIR/server-context"
FRONTEND_CONTEXT="$SMOKE_DIR/frontend-context"
SERVER_DOCKERFILE="$SMOKE_DIR/server.Dockerfile"
SERVER_IMAGE="${SMOKE_PROJECT}-server:smoke"
FRONTEND_IMAGE="${SMOKE_PROJECT}-frontend:smoke"
SERVER_BASE_IMAGE="${SMOKE_PROJECT}-server-base:smoke"
FRONTEND_BASE_IMAGE="${SMOKE_PROJECT}-frontend-base:smoke"
DEADLINE=0

log() { printf '[lyflow-smoke] %s\n' "$*"; }

compose() {
  docker compose --project-name "$SMOKE_PROJECT" --env-file "$ENV_FILE" \
    -f "$ROOT/docker-compose.yml" -f "$OVERRIDE_FILE" "$@"
}

diagnose() {
  log "smoke failed; collecting project diagnostics"
  compose ps >&2 || true
  compose logs --tail 100 >&2 || true
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if (( status != 0 )); then
    diagnose
  fi
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker image rm "$SERVER_IMAGE" "$FRONTEND_IMAGE" "$SERVER_BASE_IMAGE" "$FRONTEND_BASE_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$SMOKE_DIR"
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_service() {
  local service=$1 container state
  while (( SECONDS < DEADLINE )); do
    container=$(compose ps -q "$service")
    if [[ -n "$container" ]]; then
      state=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container")
      case "$state" in
        healthy|running) return 0 ;;
        exited|dead|unhealthy) return 1 ;;
      esac
    fi
    sleep "$SMOKE_INTERVAL_SECONDS"
  done
  log "timed out waiting for service: $service" >&2
  return 1
}

wait_for_url() {
  local name=$1 url=$2
  while (( SECONDS < DEADLINE )); do
    if curl --insecure --fail --silent --show-error --max-time 5 "$url" >/dev/null; then
      return 0
    fi
    sleep "$SMOKE_INTERVAL_SECONDS"
  done
  log "timed out waiting for $name: $url" >&2
  return 1
}

require_local_image() {
  docker image inspect "$1" >/dev/null 2>&1 || {
    log "required local image is missing: $1" >&2
    return 1
  }
}

mkdir -p "$RUNTIME_DIR"/{suricata,wazuh,yara,rasp,status}
umask 077
postgres_password=$(openssl rand -hex 32)
clickhouse_password=$(openssl rand -hex 32)
redis_password=$(openssl rand -hex 32)
jwt_secret=$(openssl rand -hex 32)
admin_password=$(openssl rand -hex 32)
control_token=$(openssl rand -hex 32)
cat >"$ENV_FILE" <<EOF
POSTGRES_PASSWORD=$postgres_password
CLICKHOUSE_PASSWORD=$clickhouse_password
REDIS_ACL_USERNAME=lyflow-smoke
REDIS_ACL_PASSWORD=$redis_password
REDIS_PASSWORD=
JWT_SECRET=$jwt_secret
DEFAULT_ADMIN_PASSWORD=$admin_password
SECURITY_ENGINE_CONTROL_TOKEN=$control_token
LYFLOW_RESET_ADMIN_PASSWORD=true
LYFLOW_FORCE_FIRST_LOGIN_PASSWORD_CHANGE=true
AGENT_SELF_ENROLL=false
EOF

cat >"$OVERRIDE_FILE" <<EOF
services:
  postgres:
    container_name: ${SMOKE_PROJECT}-postgres
    ports: !override []
  redis:
    container_name: ${SMOKE_PROJECT}-redis
    ports: !override []
  clickhouse:
    container_name: ${SMOKE_PROJECT}-clickhouse
    ports: !override []
  ly-server:
    container_name: ${SMOKE_PROJECT}-server
    image: ${SERVER_IMAGE}
    environment:
      INCIDENT_LIFECYCLE_LEGACY_MODE: "true"
    ports: !override
      - "127.0.0.1::8080"
    volumes: !override
      - "$ROOT/rules:/etc/ly/rules:ro"
      - "$ROOT/rules:/app/rules"
      - "$RUNTIME_DIR:/app/.sisyphus/runtime/engine-outputs"
      - "/sys:/host/sys:ro"
      - "policy_trust:/var/lib/lyflow/policy"
  ly-vis:
    container_name: ${SMOKE_PROJECT}-frontend
    image: ${FRONTEND_IMAGE}
    ports: !override
      - "127.0.0.1::443"
networks:
  ly-network:
    name: ${SMOKE_PROJECT}-network
EOF

command -v docker >/dev/null 2>&1 || { log 'docker is unavailable' >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { log 'curl is unavailable' >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { log 'openssl is unavailable' >&2; exit 1; }
command -v go >/dev/null 2>&1 || { log 'go is unavailable' >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { log 'npm is unavailable' >&2; exit 1; }
command -v timeout >/dev/null 2>&1 || { log 'timeout is unavailable' >&2; exit 1; }
docker info >/dev/null 2>&1 || { log 'Docker daemon is unavailable' >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { log 'docker compose plugin is unavailable' >&2; exit 1; }

for image in postgres:16-alpine redis:7-alpine clickhouse/clickhouse-server:24.8-alpine \
  redis@sha256:9de71018be8413f419688ac34e19dbac432d1c6d9593d2ded99a82eebefeb18f \
  ly-flow/frontend@sha256:98767ee96d258cdd023b6a620a4b1b44a2239a8f2742f51dc91d240615740707; do
  require_local_image "$image"
done

GO_BIN=${LYFLOW_SMOKE_GO_BIN:-go}
if [[ $($GO_BIN version) != *'go1.26.5 '* ]]; then
  cached_go="$(go env GOMODCACHE)/golang.org/toolchain@v0.0.1-go1.26.5.$(go env GOOS)-$(go env GOARCH)/bin/go"
  [[ -x "$cached_go" && $($cached_go version) == *'go1.26.5 '* ]] || {
    log 'Go 1.26.5 is not installed or present in the local toolchain cache' >&2
    exit 1
  }
  GO_BIN=$cached_go
fi

mkdir -p "$SERVER_CONTEXT" "$FRONTEND_CONTEXT/frontend/docker-entrypoint.d"
(cd "$ROOT/server" && GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 \
  timeout "$SMOKE_BUILD_TIMEOUT_SECONDS" "$GO_BIN" build -trimpath -buildvcs=false -o "$SERVER_CONTEXT/ly-server" ./cmd)
(cd "$ROOT" && timeout "$SMOKE_BUILD_TIMEOUT_SECONDS" npm --prefix frontend run build -- --outDir "$FRONTEND_CONTEXT/frontend/dist" --emptyOutDir)
chmod -R a+rX "$FRONTEND_CONTEXT/frontend/dist"
cp "$ROOT/frontend/docker-entrypoint.d/40-lyflow-tls.sh" "$FRONTEND_CONTEXT/frontend/docker-entrypoint.d/"
cat >"$SERVER_DOCKERFILE" <<'EOF'
ARG RUNTIME_IMAGE
FROM ${RUNTIME_IMAGE}
USER root
WORKDIR /app
COPY ly-server /app/ly-server
RUN chmod 0755 /app/ly-server
EXPOSE 8080
CMD ["/app/ly-server"]
EOF
docker image tag redis@sha256:9de71018be8413f419688ac34e19dbac432d1c6d9593d2ded99a82eebefeb18f "$SERVER_BASE_IMAGE"
docker image tag ly-flow/frontend@sha256:98767ee96d258cdd023b6a620a4b1b44a2239a8f2742f51dc91d240615740707 "$FRONTEND_BASE_IMAGE"
timeout "$SMOKE_BUILD_TIMEOUT_SECONDS" docker build --pull=false --network=none --build-arg RUNTIME_IMAGE="$SERVER_BASE_IMAGE" -t "$SERVER_IMAGE" -f "$SERVER_DOCKERFILE" "$SERVER_CONTEXT"
timeout "$SMOKE_BUILD_TIMEOUT_SECONDS" docker build --pull=false --network=none --build-arg RUNTIME_IMAGE="$FRONTEND_BASE_IMAGE" -t "$FRONTEND_IMAGE" -f "$ROOT/frontend/Dockerfile" "$FRONTEND_CONTEXT"

compose config >/dev/null
DEADLINE=$((SECONDS + SMOKE_TIMEOUT_SECONDS))
log "starting isolated project $SMOKE_PROJECT"
compose up -d --no-build --pull never postgres redis clickhouse ly-server ly-vis
for service in postgres redis clickhouse ly-server ly-vis; do
  wait_for_service "$service"
done

api_address=$(compose port ly-server 8080)
frontend_address=$(compose port ly-vis 443)
api_port=${api_address##*:}
frontend_port=${frontend_address##*:}
api_url="http://127.0.0.1:${api_port}/api/v1/health"
frontend_url="https://127.0.0.1:${frontend_port}/"
wait_for_url API "$api_url"
wait_for_url frontend "$frontend_url"

log 'restarting API service'
compose restart ly-server
wait_for_service ly-server
api_address=$(compose port ly-server 8080)
api_port=${api_address##*:}
api_url="http://127.0.0.1:${api_port}/api/v1/health"
wait_for_url API "$api_url"
wait_for_url frontend "$frontend_url"
log "smoke passed: API $api_url, frontend $frontend_url"
