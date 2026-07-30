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
grep -Fq 'pg_isready -h 127.0.0.1 -U lyflow -d lyflow' "$compose" || fail 'PostgreSQL healthcheck can accept the temporary init server'
python3 - "$compose" <<'PY' || fail 'security-engine does not wait for healthy ly-server'
import sys
import yaml

with open(sys.argv[1], encoding="utf-8") as source:
    services = yaml.safe_load(source)["services"]
dependency = services["ly-security-engine"]["depends_on"].get("ly-server", {})
if dependency.get("condition") != "service_healthy":
    raise SystemExit(1)
PY

test_first_party_health_contracts() {
  python3 - "$compose" <<'PY' || fail 'first-party service healthcheck contract mismatch'
import re
import sys

import yaml

with open(sys.argv[1], encoding="utf-8") as source:
    services = yaml.safe_load(source)["services"]

required_healthchecks = ("agent-center", "ly-engine-lab", "ly-local-mirror")
missing_healthchecks = [
    service_name
    for service_name in required_healthchecks
    if not isinstance(services[service_name].get("healthcheck"), dict)
]
assert not missing_healthchecks, f"missing healthchecks: {', '.join(missing_healthchecks)}"


def healthcheck(service_name):
    health = services[service_name].get("healthcheck")
    test = health.get("test")
    assert isinstance(test, list) and test and test[0] == "CMD", f"{service_name} must use CMD healthcheck"
    command = " ".join(str(part) for part in test)
    assert "kill -0" not in command, f"{service_name} healthcheck is process-only"
    for field in ("interval", "timeout", "start_period"):
        value = str(health.get(field, ""))
        assert re.fullmatch(r"[1-9][0-9]*(?:\.[0-9]+)?(?:ns|us|ms|s|m|h)", value), (
            f"{service_name} {field} is absent, zero, or unbounded"
        )
    assert isinstance(health.get("retries"), int) and health["retries"] > 0, (
        f"{service_name} retries must be positive and finite"
    )
    return test, command


agent_test, agent_command = healthcheck("agent-center")
assert agent_test == ["CMD", "/app/ly-agent-center", "healthcheck"], (
    "agent-center does not use its exact gRPC healthcheck command"
)

engine_test, engine_command = healthcheck("ly-engine-lab")
assert len(engine_test) >= 3 and engine_test[1] == "python3", "ly-engine-lab healthcheck is not a Python probe"
engine_probe = " ".join(str(part) for part in engine_test[2:])
compact_probe = re.sub(r"\s+", "", engine_probe)
assert "status.json" in engine_probe, "ly-engine-lab probe does not inspect status.json"
assert "isfile" in engine_probe.lower() or "S_ISREG" in engine_probe, "ly-engine-lab probe does not require a regular file"
assert "st_size>0" in compact_probe or "getsize(" in compact_probe, "ly-engine-lab probe accepts an empty status file"
assert (
    "0<=age<=120" in compact_probe
    or ("age>=0" in compact_probe and "age<=120" in compact_probe)
), "ly-engine-lab probe does not bound status age from 0 through 120 seconds"

mirror_test, mirror_command = healthcheck("ly-local-mirror")
assert mirror_test[1:] == [
    "/app/ly-agent",
    "healthcheck",
    "local-mirror",
], (
    "ly-local-mirror does not use the static Agent capture-watchdog health checker"
)
PY
}

test_engine_lab_stale_status_ordering() {
  python3 - "$root/containers/security-engines/bin/engine-output-bridge.sh" <<'PY' \
    || fail 'engine-lab does not remove stale status before process start and first status write'
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    script = source.read()

remove_status = script.find('rm -f "$STATUS_FILE"')
start_processes = script.find("\nstart_processes\n", max(remove_status, 0))
first_status_write = script.find("\nwrite_status\n", max(start_processes, 0))
assert 0 <= remove_status < start_processes < first_status_write
PY
}

case "${1:-}" in
  --first-party-health-contracts)
    test_first_party_health_contracts
    exit 0
    ;;
  --engine-lab-stale-status-ordering)
    test_engine_lab_stale_status_ordering
    exit 0
    ;;
  '')
    ;;
  *)
    fail "unknown argument: $1"
    ;;
esac

test_first_party_health_contracts
test_engine_lab_stale_status_ordering

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
