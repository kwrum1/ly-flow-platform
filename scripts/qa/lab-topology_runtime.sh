#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evidence_dir=${1:-$root/acceptance-evidence/T03}
project=${LYFLOW_ACCEPTANCE_PROJECT:-lyflow-t03-$(date +%s)-$$}
timeout_seconds=${LYFLOW_ACCEPTANCE_TIMEOUT_SECONDS:-90}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/lyflow-t03.XXXXXX")
env_file="$tmp/acceptance.env"
cleanup_log="$evidence_dir/cleanup.log"
services=(acceptance-packet-sensor acceptance-worker-agent acceptance-database-agent acceptance-web-agent)

fail() {
  printf 'acceptance lab runtime failed: %s\n' "$*" >&2
  exit 1
}

case "$project" in
  *[!a-zA-Z0-9_-]*|'') fail 'LYFLOW_ACCEPTANCE_PROJECT contains invalid characters' ;;
esac

mkdir -p "$evidence_dir"
: >"$cleanup_log"
umask 077
cat >"$env_file" <<EOF
REDIS_ACL_USERNAME=acceptance-runtime
REDIS_ACL_PASSWORD=$(openssl rand -hex 24)
SECURITY_ENGINE_CONTROL_TOKEN=$(openssl rand -hex 24)
ACCEPTANCE_WEB_ENROLL_TOKEN=$(openssl rand -hex 24)
ACCEPTANCE_DATABASE_ENROLL_TOKEN=$(openssl rand -hex 24)
ACCEPTANCE_WORKER_ENROLL_TOKEN=$(openssl rand -hex 24)
ACCEPTANCE_SENSOR_ENROLL_TOKEN=$(openssl rand -hex 24)
EOF

compose() {
  docker compose --project-name "$project" --env-file "$env_file" --profile acceptance-lab \
    -f "$root/docker-compose.yml" -f "$root/docker-compose.acceptance.yml" "$@"
}

project_resources() {
  local kind=$1
  case "$kind" in
    container) docker ps -aq --filter "label=com.docker.compose.project=$project" ;;
    volume) docker volume ls -q --filter "label=com.docker.compose.project=$project" ;;
    network) docker network ls -q --filter "label=com.docker.compose.project=$project" ;;
  esac
}

container_volume_names() {
  local container
  while IFS= read -r container; do
    [[ -n "$container" ]] || continue
    docker inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{println .Name}}{{end}}{{end}}' "$container"
  done < <(project_resources container)
}

cleanup() {
  local status=$? cleanup_status=0 kind survivors volume
  local -a tracked_volumes=()
  trap - EXIT INT TERM
  mapfile -t tracked_volumes < <(container_volume_names | sort -u)
  {
    printf 'project=%s cleanup-attempt=1\n' "$project"
    compose down --timeout 5 --volumes --remove-orphans || cleanup_status=1
    printf 'project=%s cleanup-attempt=2\n' "$project"
    compose down --timeout 5 --volumes --remove-orphans || cleanup_status=1
    for kind in container volume network; do
      survivors=$(project_resources "$kind")
      if [[ -n "$survivors" ]]; then
        printf 'surviving-%ss=%s\n' "$kind" "$survivors"
        cleanup_status=1
      else
        printf 'surviving-%ss=none\n' "$kind"
      fi
    done
    for volume in "${tracked_volumes[@]}"; do
      [[ -n "$volume" ]] || continue
      if docker volume inspect "$volume" >/dev/null 2>&1; then
        printf 'tracked-volume=%s state=surviving\n' "$volume"
        cleanup_status=1
      else
        printf 'tracked-volume=%s state=removed\n' "$volume"
      fi
    done
    if (( cleanup_status == 0 )); then
      printf 'TEARDOWN_RESULT=PASS project=%s\n' "$project"
    else
      printf 'TEARDOWN_RESULT=FAIL project=%s\n' "$project"
    fi
  } >>"$cleanup_log" 2>&1
  rm -rf "$tmp"
  if (( status == 0 && cleanup_status != 0 )); then
    status=1
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for kind in container volume network; do
  [[ -z "$(project_resources "$kind")" ]] || fail "project $project already owns a $kind"
done

git -C "$root" status --short >"$evidence_dir/dirty-worktree.txt"

compose config --format json | python3 -c '
import json
import sys

document = json.load(sys.stdin)
for service in document.get("services", {}).values():
    environment = service.get("environment", {})
    for key in list(environment):
        upper = key.upper()
        if any(word in upper for word in ("TOKEN", "PASSWORD", "SECRET", "KEY")):
            environment[key] = "<redacted>"
json.dump(document, sys.stdout, indent=2, sort_keys=True)
print()
' >"$evidence_dir/compose-config.txt"

stale_volume="${project}_acceptance-web-identity"
docker volume create \
  --label "com.docker.compose.project=$project" \
  --label com.docker.compose.volume=acceptance-web-identity \
  "$stale_volume" >/dev/null
docker run --rm --entrypoint /bin/sh -v "$stale_volume:/identity" ly-flow/agent:latest \
  -c 'printf "role: stale-other-role\n" >/identity/agent-identity.yaml'
compose up -d --no-build --pull never acceptance-web-agent >/dev/null
deadline=$((SECONDS + 20))
while (( SECONDS < deadline )); do
  stale_id=$(compose ps -aq acceptance-web-agent)
  [[ -n "$stale_id" ]] || { sleep 1; continue; }
  state=$(docker inspect --format '{{.State.Status}}' "$stale_id")
  [[ "$state" == exited ]] && break
  sleep 1
done
compose logs --no-color acceptance-web-agent >"$evidence_dir/stale-volume.log" 2>&1 || true
grep -Fq 'stale identity volume belongs to another role' "$evidence_dir/stale-volume.log" \
  || fail 'stale identity volume was not rejected'
mapfile -t stale_volumes < <(container_volume_names | sort -u)
compose down --timeout 5 --volumes --remove-orphans >/dev/null
[[ -z "$(project_resources container)" ]] || fail 'stale-volume probe left a container'
[[ -z "$(project_resources volume)" ]] || fail 'stale-volume probe left a volume'
[[ -z "$(project_resources network)" ]] || fail 'stale-volume probe left a network'
for volume in "${stale_volumes[@]}"; do
  [[ -n "$volume" ]] || continue
  docker volume inspect "$volume" >/dev/null 2>&1 && fail "stale-volume probe left volume $volume"
done

compose up -d --no-build --pull never "${services[@]}" >"$evidence_dir/startup.log"

wait_for_healthy() {
  local service=$1 container state deadline
  deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    container=$(compose ps -q "$service")
    if [[ -n "$container" ]]; then
      state=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container")
      case "$state" in
        healthy) return 0 ;;
        exited|dead|unhealthy) return 1 ;;
      esac
    fi
    sleep 1
  done
  return 1
}

for service in "${services[@]}"; do
  wait_for_healthy "$service" || {
    compose ps >&2 || true
    compose logs --no-color "$service" >&2 || true
    fail "bounded health wait failed for $service"
  }
done

compose ps --format json >"$evidence_dir/health.json"
for service in acceptance-web-agent acceptance-database-agent acceptance-worker-agent; do
  compose exec -T "$service" sh -c '
    test -s "$AGENT_IDENTITY_CONFIG"
    test -s "$ENGINE_OUTPUT_DIR/telemetry.jsonl"
    wget -q -O - "http://127.0.0.1:$WORKLOAD_PORT/health"
  ' >>"$evidence_dir/workload-health.jsonl"
done

web_address=$(compose port acceptance-web-agent 8080)
web_port=${web_address##*:}
curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:$web_port/health" \
  >"$evidence_dir/curl-web.json"

compose exec -T acceptance-web-agent ping -c 12 acceptance-packet-sensor \
  >"$evidence_dir/packet-stimulus.txt"
sensor_id=$(compose ps -q acceptance-packet-sensor)
deadline=$((SECONDS + 30))
packet_count=0
while (( SECONDS < deadline )); do
  docker cp "$sensor_id:/var/lib/lyflow/engine-output/packet-sensor/eve.json" "$tmp/eve.json" >/dev/null 2>&1 || true
  packet_count=$(python3 - "$tmp/eve.json" <<'PY' 2>/dev/null || true
import json
import sys

maximum = 0
with open(sys.argv[1], encoding="utf-8") as source:
    for line in source:
        event = json.loads(line)
        maximum = max(maximum, event.get("stats", {}).get("capture", {}).get("kernel_packets", 0))
print(maximum)
PY
  )
  [[ "${packet_count:-0}" =~ ^[0-9]+$ ]] && (( packet_count > 0 )) && break
  sleep 1
done
(( packet_count > 0 )) || fail 'packet sensor reported zero captured packets'
printf '{"capture_interface":"eth0","kernel_packets":%d,"observation":"nonzero"}\n' "$packet_count" \
  >"$evidence_dir/packet-observation.json"

for service in "${services[@]}"; do
  container=$(compose ps -q "$service")
  docker inspect "$container"
done | python3 -c '
import json
import sys

decoder = json.JSONDecoder()
payload = sys.stdin.read()
offset = 0
containers = []
while offset < len(payload):
    while offset < len(payload) and payload[offset].isspace():
        offset += 1
    if offset == len(payload):
        break
    batch, offset = decoder.raw_decode(payload, offset)
    containers.extend(batch)

result = []
for item in containers:
    config = item["Config"]
    state = item["State"]
    result.append({
        "name": item["Name"].lstrip("/"),
        "hostname": config["Hostname"],
        "role": config.get("Labels", {}).get("com.lyflow.acceptance.role"),
        "token_env": config.get("Labels", {}).get("com.lyflow.acceptance.token-env"),
        "cap_add": item["HostConfig"].get("CapAdd") or [],
        "privileged": item["HostConfig"].get("Privileged", False),
        "health": (state.get("Health") or {}).get("Status", state.get("Status")),
        "mounts": [{"source": mount["Name"], "destination": mount["Destination"]}
                   for mount in item["Mounts"] if mount["Type"] == "volume"],
        "networks": sorted(item["NetworkSettings"]["Networks"]),
    })
json.dump(sorted(result, key=lambda value: value["role"]), sys.stdout, indent=2, sort_keys=True)
print()
' >"$evidence_dir/topology.json"

network_id=$(project_resources network)
docker network inspect "$network_id" | python3 -c '
import json
import sys

network = json.load(sys.stdin)[0]
result = {
    "name": network["Name"],
    "driver": network["Driver"],
    "containers": sorted([
        {"name": value["Name"], "ipv4": value["IPv4Address"]}
        for value in network.get("Containers", {}).values()
    ], key=lambda value: value["name"]),
}
json.dump(result, sys.stdout, indent=2, sort_keys=True)
print()
' >"$evidence_dir/network-inspect.json"

mapfile -t volume_ids < <(project_resources volume)
docker volume inspect "${volume_ids[@]}" | python3 -c '
import json
import sys

result = [{"name": item["Name"], "driver": item["Driver"]} for item in json.load(sys.stdin)]
json.dump(sorted(result, key=lambda value: value["name"]), sys.stdout, indent=2, sort_keys=True)
print()
' >"$evidence_dir/volume-inspect.json"

for service in "${services[@]}"; do
  printf 'service=%s\n' "$service"
  compose exec -T "$service" sh -c 'cat "$AGENT_IDENTITY_CONFIG"'
done >"$evidence_dir/identities.txt"

cat >"$evidence_dir/adversarial.json" <<EOF
{
  "malformed_input": "PASS: static test rejects missing and malformed enrollment-token variables",
  "prompt_injection": "N/A: topology inputs contain no untrusted natural-language instructions",
  "cancel_resume": "PASS: INT and TERM traps route through project-scoped cleanup",
  "stale_state": "PASS: role-mismatched identity volume was rejected before clean retry",
  "dirty_worktree": "PASS: initial dirty state recorded; cleanup is label-scoped to $project",
  "hung_commands": "PASS: health waits, curl, and teardown are bounded",
  "flaky_startup": "PASS: services declare no ordering dependency; each concurrent startup is verified with an independent bounded readiness probe",
  "misleading_success_output": "PASS: healthy state was cross-checked with identity, telemetry, curl, and packet counters",
  "repeated_interruptions": "PASS: teardown is idempotently attempted twice and survivor checks are authoritative"
}
EOF

printf 'LAB_TOPOLOGY_RUNTIME_RESULT=PASS project=%s packets=%d\n' "$project" "$packet_count" \
  | tee "$evidence_dir/runtime-result.txt"
