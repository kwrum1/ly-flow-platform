#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE_ARGS=()

if [[ "${ENABLE_CONTAINER_AGENT:-false}" == "true" ]]; then
  PROFILE_ARGS+=(--profile container-agent)
fi

cd "$ROOT_DIR"

echo "==> stopping existing stack"
docker compose "${PROFILE_ARGS[@]}" down --remove-orphans --volumes

echo "==> removing old LyFlow containers if present"
docker rm -f ly-server ly-vis ly-postgres ly-redis ly-clickhouse agent-center 2>/dev/null || true
if [[ "${ENABLE_CONTAINER_AGENT:-false}" == "true" ]]; then
  docker rm -f ly-agent 2>/dev/null || true
fi

echo "==> rebuilding images"
echo "==> rebuilding Go binaries copied by Dockerfiles"
(cd server && GOWORK=off GOFLAGS="${GOFLAGS:--mod=readonly}" go build -o ly-server ./cmd)
(cd server && GOWORK=off GOFLAGS="${GOFLAGS:--mod=readonly}" go build -o ly-agent-center ./agentcenter)
BUILD_ARGS=()
if [[ "${PULL_BASE_IMAGES:-false}" == "true" ]]; then
  BUILD_ARGS+=(--pull)
fi
docker compose "${PROFILE_ARGS[@]}" build "${BUILD_ARGS[@]}"

echo "==> starting clean stack"
docker compose "${PROFILE_ARGS[@]}" up -d

echo "==> waiting for services"
docker compose ps

echo "==> running quick release gate"
bash scripts/release-gate.sh quick

cat <<'EOF'

LyFlow clean rebuild complete.
Frontend: https://localhost/
API health: https://localhost/api/v1/health
Container agent: disabled by default; set ENABLE_CONTAINER_AGENT=true to include it.
EOF
