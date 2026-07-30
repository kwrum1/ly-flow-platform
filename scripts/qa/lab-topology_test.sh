#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
compose="$root/docker-compose.yml"
acceptance_compose="$root/docker-compose.acceptance.yml"
contract="$root/contracts/product-acceptance/v1/lab-topology.json"
role_entrypoint="$root/containers/acceptance-lab/role-agent-entrypoint.sh"
sensor_entrypoint="$root/containers/acceptance-lab/packet-sensor-entrypoint.sh"
workload_response="$root/containers/acceptance-lab/workload-response.sh"

fail() {
  printf 'lab-topology test failed: %s\n' "$*" >&2
  exit 1
}

characterize_default() {
  python3 - "$compose" <<'PY' || fail 'default single-agent topology changed unexpectedly'
import sys

import yaml

with open(sys.argv[1], encoding="utf-8") as source:
    document = yaml.safe_load(source)

agent = document["services"]["ly-agent"]
assert set(agent["profiles"]) == {"container-agent", "suricata-profile"}
assert "container_name" not in agent
assert agent["environment"]["AGENT_ID"] == "ly-container-agent"
assert agent["environment"]["AGENT_KEY"] == "ly-container-agent-key"
assert agent["environment"]["SPOOL_DIR"] == "/opt/ly-agent/data/spool"
assert "agent_spool:/opt/ly-agent/data" in agent["volumes"]
assert "./.sisyphus/runtime/engine-outputs/status:/opt/ly-engine-lab/runtime:ro" in agent["volumes"]
assert "ly-suricata-sensor" in document["services"]
assert "suricata-profile" in document["services"]["ly-suricata-sensor"]["profiles"]
assert "acceptance-lab" not in agent["profiles"]
PY
  printf 'default single-agent topology characterization passed\n'
}

validate_acceptance_topology() {
  [[ -f "$acceptance_compose" ]] || fail 'docker-compose.acceptance.yml is missing'
  [[ -f "$contract" ]] || fail 'lab topology contract is missing'
  [[ -f "$role_entrypoint" ]] || fail 'role agent entrypoint is missing'
  [[ -f "$sensor_entrypoint" ]] || fail 'packet sensor entrypoint is missing'
  [[ -f "$workload_response" ]] || fail 'workload response script is missing'

  local rendered tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  rendered="$tmp/compose.json"

  local -a base_env=(
    REDIS_ACL_USERNAME=acceptance-config
    REDIS_ACL_PASSWORD=acceptance-config-password
    SECURITY_ENGINE_CONTROL_TOKEN=acceptance-config-control-token
  )
  local -a token_env=(
    ACCEPTANCE_WEB_ENROLL_TOKEN=acceptance-test-web-token
    ACCEPTANCE_DATABASE_ENROLL_TOKEN=acceptance-test-database-token
    ACCEPTANCE_WORKER_ENROLL_TOKEN=acceptance-test-worker-token
    ACCEPTANCE_SENSOR_ENROLL_TOKEN=acceptance-test-sensor-token
  )

  local missing assignment
  local -a filtered_token_env=()
  for missing in \
    ACCEPTANCE_WEB_ENROLL_TOKEN \
    ACCEPTANCE_DATABASE_ENROLL_TOKEN \
    ACCEPTANCE_WORKER_ENROLL_TOKEN \
    ACCEPTANCE_SENSOR_ENROLL_TOKEN; do
    filtered_token_env=()
    for assignment in "${token_env[@]}"; do
      [[ "$assignment" == "$missing="* ]] || filtered_token_env+=("$assignment")
    done
    if env -u "$missing" "${base_env[@]}" "${filtered_token_env[@]}" \
        docker compose --profile acceptance-lab -f "$compose" -f "$acceptance_compose" config >/dev/null 2>&1; then
      fail "missing enrollment token was accepted: $missing"
    fi
  done

  env "${base_env[@]}" "${token_env[@]}" \
    docker compose --profile acceptance-lab -f "$compose" -f "$acceptance_compose" config --format json >"$rendered"

  default_services=$(env "${base_env[@]}" "${token_env[@]}" \
    docker compose -f "$compose" -f "$acceptance_compose" config --services)
  if grep -Fq 'acceptance-' <<<"$default_services"; then
    fail 'acceptance service entered the default Compose service set'
  fi

  python3 - "$rendered" "$contract" <<'PY' || fail 'acceptance topology contract mismatch'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    compose = json.load(source)
with open(sys.argv[2], encoding="utf-8") as source:
    contract = json.load(source)

assert contract["schema_version"] == "lyflow.acceptance.lab-topology.v1"
assert contract["profile"] == "acceptance-lab"
assert contract["network"] == "acceptance-lab"

services = compose["services"]
entries = contract["agents"]
assert {entry["role"] for entry in entries} == {"web", "database", "worker", "packet-sensor"}

hostnames = set()
token_names = set()
token_values = set()
identity_paths = set()
spool_paths = set()
engine_paths = set()
identity_volumes = set()
spool_volumes = set()
engine_volumes = set()

for entry in entries:
    service = services[entry["service"]]
    environment = service["environment"]
    assert service["profiles"] == ["acceptance-lab"]
    assert service.get("privileged", False) is False
    assert service["hostname"] == entry["hostname"]
    assert environment["LAB_ROLE"] == entry["role"]
    assert environment["AGENT_IDENTITY_CONFIG"] == entry["identity_path"]
    assert environment["SPOOL_DIR"] == entry["spool_path"]
    assert environment["ENGINE_OUTPUT_DIR"] == entry["engine_output_path"]
    assert service["networks"] == {"acceptance-lab": None}
    assert "healthcheck" in service
    health_command = " ".join(str(part) for part in service["healthcheck"].get("test", []))
    assert "kill -0" not in health_command, f'{entry["service"]} uses process-only health proof'

    hostnames.add(service["hostname"])
    token_names.add(entry["enrollment_token_env"])
    token_values.add(environment["AGENT_ENROLL_TOKEN"])
    identity_paths.add(entry["identity_path"])
    spool_paths.add(entry["spool_path"])
    engine_paths.add(entry["engine_output_path"])

    mounts = {mount["target"]: mount["source"] for mount in service["volumes"]}
    identity_volumes.add(mounts[os.path.dirname(entry["identity_path"])])
    spool_volumes.add(mounts[entry["spool_path"]])
    engine_volumes.add(mounts[entry["engine_output_path"]])

    if entry["role"] == "packet-sensor":
        assert sorted(service["cap_add"]) == ["NET_ADMIN", "NET_RAW", "SYS_NICE"]
        assert entry["capture_interface"] == environment["CAPTURE_INTERFACE"] == "eth0"
    else:
        assert service.get("cap_add", []) == []

expected_count = len(entries)
for values in (
    hostnames,
    token_names,
    token_values,
    identity_paths,
    spool_paths,
    engine_paths,
    identity_volumes,
    spool_volumes,
    engine_volumes,
):
    assert len(values) == expected_count

assert compose["networks"]["acceptance-lab"]["name"].endswith("_acceptance-lab")
assert compose["services"]["ly-engine-lab"]["environment"]["ENGINE_LAB_EMIT_SAMPLE_EVENTS"] == "false"
PY

  local role token_name port
  for role in web database worker; do
    case "$role" in
      web) token_name=ACCEPTANCE_WEB_ENROLL_TOKEN; port=8080 ;;
      database) token_name=ACCEPTANCE_DATABASE_ENROLL_TOKEN; port=15432 ;;
      worker) token_name=ACCEPTANCE_WORKER_ENROLL_TOKEN; port=18080 ;;
    esac
    if env -u AGENT_ENROLL_TOKEN LAB_VALIDATE_ONLY=1 LAB_ROLE="$role" ENROLLMENT_TOKEN_ENV="$token_name" \
        WORKLOAD_PORT="$port" AGENT_IDENTITY_CONFIG=/tmp/identity SPOOL_DIR=/tmp/spool ENGINE_OUTPUT_DIR=/tmp/engine \
        bash "$role_entrypoint" >/dev/null 2>&1; then
      fail "missing enrollment token was accepted by $role entrypoint"
    fi
    if LAB_VALIDATE_ONLY=1 LAB_ROLE="$role" ENROLLMENT_TOKEN_ENV="$token_name" \
        AGENT_ENROLL_TOKEN='bad token' WORKLOAD_PORT="$port" \
        AGENT_IDENTITY_CONFIG=/tmp/identity SPOOL_DIR=/tmp/spool ENGINE_OUTPUT_DIR=/tmp/engine \
        bash "$role_entrypoint" >/dev/null 2>&1; then
      fail "malformed enrollment token was accepted by $role entrypoint"
    fi
  done
  if env -u AGENT_ENROLL_TOKEN LAB_VALIDATE_ONLY=1 LAB_ROLE=packet-sensor \
      ENROLLMENT_TOKEN_ENV=ACCEPTANCE_SENSOR_ENROLL_TOKEN CAPTURE_INTERFACE=eth0 \
      AGENT_IDENTITY_CONFIG=/tmp/identity SPOOL_DIR=/tmp/spool ENGINE_OUTPUT_DIR=/tmp/engine \
      bash "$sensor_entrypoint" >/dev/null 2>&1; then
    fail 'missing enrollment token was accepted by packet sensor entrypoint'
  fi
  if LAB_VALIDATE_ONLY=1 LAB_ROLE=packet-sensor ENROLLMENT_TOKEN_ENV=ACCEPTANCE_SENSOR_ENROLL_TOKEN \
      AGENT_ENROLL_TOKEN='bad token' CAPTURE_INTERFACE=eth0 \
      AGENT_IDENTITY_CONFIG=/tmp/identity SPOOL_DIR=/tmp/spool ENGINE_OUTPUT_DIR=/tmp/engine \
      bash "$sensor_entrypoint" >/dev/null 2>&1; then
    fail 'malformed enrollment token was accepted by packet sensor entrypoint'
  fi

  bash -n "$role_entrypoint"
  bash -n "$sensor_entrypoint"
  bash -n "$workload_response"
  printf 'acceptance lab topology contract passed\n'
}

case "${1:-}" in
  --characterize-default)
    characterize_default
    ;;
  '')
    characterize_default
    validate_acceptance_topology
    ;;
  *)
    fail "unknown argument: $1"
    ;;
esac
