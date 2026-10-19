#!/usr/bin/env bash
# Build the lean core images from locally built binaries and frontend dist.
# Run on the build host after: go build server/ly-server, server/ly-agent-center,
# security-engine/ly-security-engine and npm run build in frontend/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bash "$ROOT/scripts/build-agent-binaries.sh"
for file in \
  "$ROOT/server/ly-server" \
  "$ROOT/server/ly-agent-center" \
  "$ROOT/security-engine/ly-security-engine" \
  "$ROOT/frontend/dist/index.html" \
  "$ROOT/agent/ly-agent" \
  "$ROOT/agent/ly-agent-linux-arm64" \
  "$ROOT/agent/ly-agent-windows-amd64"; do
  [ -e "$file" ] || { echo "missing core build artifact: $file" >&2; exit 1; }
done

docker build --network host -f "$ROOT/deploy/docker/server-lean.Dockerfile" \
  -t "${LY_SERVER_IMAGE:-ly-flow/server:latest}" "$ROOT"
docker build --network host -f "$ROOT/deploy/docker/security-engine-lean.Dockerfile" \
  -t "${LY_SECURITY_ENGINE_IMAGE:-ly-flow/security-engine:latest}" "$ROOT"
docker build --network host -f "$ROOT/deploy/docker/pingora-frontend.Dockerfile" \
  -t "${LY_FRONTEND_IMAGE:-ly-flow/frontend:latest}" "$ROOT"
docker build --network host -f "$ROOT/deploy/docker/redis-lean.Dockerfile" \
  -t "${LY_REDIS_IMAGE:-ly-flow/redis:7.2}" "$ROOT"
docker build --network host -f "$ROOT/deploy/docker/suricata-lean.Dockerfile" \
  -t "${LY_SURICATA_IMAGE:-ly-flow/suricata:latest}" "$ROOT"

docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | \
  grep -E 'ly-flow/(server|security-engine|frontend|redis|suricata):' || true
