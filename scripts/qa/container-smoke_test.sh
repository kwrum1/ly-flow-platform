#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
smoke="$root/scripts/container-smoke.sh"
compose="$root/docker-compose.yml"

fail() {
  printf 'container-smoke test failed: %s\n' "$*" >&2
  exit 1
}

[[ -x "$smoke" ]] || fail 'scripts/container-smoke.sh is missing or not executable'
bash -n "$smoke"

grep -Fq 'INCIDENT_LIFECYCLE_LEGACY_MODE: "true"' "$compose" || fail 'fresh-only legacy mode is missing from ly-server'
grep -Fq 'http://127.0.0.1:8080/api/v1/health' "$compose" || fail 'ly-server healthcheck is missing'
python3 - "$compose" <<'PY' || fail 'security-engine does not wait for healthy ly-server'
import sys
import yaml

with open(sys.argv[1], encoding="utf-8") as source:
    services = yaml.safe_load(source)["services"]
dependency = services["ly-security-engine"]["depends_on"].get("ly-server", {})
if dependency.get("condition") != "service_healthy":
    raise SystemExit(1)
PY

for contract in \
  '--project-name' \
  'mktemp -d' \
  'trap cleanup' \
  '127.0.0.1::8080' \
  '127.0.0.1::443' \
  '!override' \
  'build -trimpath -buildvcs=false' \
  'npm --prefix frontend run build' \
  'docker build --pull=false' \
  '--no-build' \
  '--pull never' \
  'wait_for_service' \
  'ly-security-engine' \
  'api_base' \
  'https://127.0.0.1' \
  'restart ly-server' \
  'down --volumes --remove-orphans'; do
  grep -Fq -- "$contract" "$smoke" || fail "missing contract: $contract"
done

grep -Eq 'SMOKE_TIMEOUT_SECONDS.*:-[0-9]+' "$smoke" || fail 'bounded timeout default is missing'
grep -Fq 'openssl rand' "$smoke" || fail 'generated test credentials are missing'
grep -Fq 'LYFLOW_RESET_ADMIN_PASSWORD=false' "$smoke" || fail 'smoke does not preserve changed admin passwords'
grep -Fq 'original admin password returned HTTP' "$smoke" || fail 'smoke does not reject the original admin password after restart'
grep -Fq 'changed admin password returned HTTP' "$smoke" || fail 'smoke does not verify the changed admin password after restart'
grep -Fq 'go1.26.5' "$smoke" || fail 'pinned Go toolchain selection is missing'
grep -Fq 'docker image tag' "$smoke" || fail 'local base images are not isolated from registry resolution'
grep -Fq 'docker image rm "$SERVER_IMAGE" "$FRONTEND_IMAGE"' "$smoke" || fail 'temporary source images are not cleaned'
grep -Fq 'docker volume create "${SMOKE_PROJECT}_rules_runtime"' "$smoke" || fail 'shared rules volume is not created'
grep -Fq 'docker cp "$ROOT/rules/." "$RULES_SEED_CONTAINER:/app/rules/"' "$smoke" || fail 'rules are not streamed into the Docker volume'
if grep -Fq 'INCIDENT_LIFECYCLE_LEGACY_MODE' "$smoke"; then
  fail 'source smoke still overrides canonical fresh-only lifecycle mode'
fi
[[ $(grep -Fc 'compose port ly-server 8080' "$smoke") -ge 2 ]] || fail 'API port is not resolved again after restart'
if grep -Eq 'docker (system|container|volume|network) prune|docker compose down( |$)' "$smoke"; then
  fail 'cleanup is not scoped to the smoke project'
fi

printf 'container-smoke contract tests passed\n'
