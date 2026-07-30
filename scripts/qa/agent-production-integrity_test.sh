#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp=$(mktemp -d)
release_dir="agent/dist/release-fixture-$$"
image="ly-flow/agent:todo15-integrity-fixture"
install_dir="$tmp/installed"
package="$tmp/package"
compose_project=$(basename "$install_dir")

cleanup() {
  if [[ -f "$install_dir/docker-compose.yml" ]]; then
    docker compose -p "$compose_project" -f "$install_dir/docker-compose.yml" down --remove-orphans >/dev/null 2>&1 || true
  fi
  docker image rm "$image" >/dev/null 2>&1 || true
  rm -rf "$root/$release_dir" "$tmp"
}
report_failure() {
  local status=$?
  printf 'agent production integrity fixture failed at line %s (status %s)\n' "${BASH_LINENO[0]}" "$status" >&2
  exit "$status"
}
trap cleanup EXIT INT TERM
trap report_failure ERR

openssl genpkey -algorithm ED25519 -out "$tmp/release-signer.key" >/dev/null 2>&1
openssl pkey -in "$tmp/release-signer.key" -pubout -out "$tmp/release-root.pem" >/dev/null 2>&1

(cd "$root/agent" && GOWORK=off GOTOOLCHAIN=auto GOSUMDB=sum.golang.org CGO_ENABLED=0 go build -o "$tmp/ly-agent" ./cmd)
AGENT_RELEASE_BINARY="$tmp/ly-agent" AGENT_RELEASE_OUTPUT="$root/$release_dir" RELEASE_SIGNING_KEY="$tmp/release-signer.key" \
  "$root/scripts/prepare-agent-release.sh"

runtime_id=$(docker image inspect ly-flow/server:latest --format '{{.Id}}')
docker build --no-cache --build-arg "RUNTIME_IMAGE=ly-flow/server@${runtime_id}" --build-arg "AGENT_RELEASE_DIR=$release_dir" \
  -f "$root/agent/Dockerfile" -t "$image" "$root" >/dev/null

mkdir -p "$package/images" "$package/rules" "$package/scripts"
printf "amd64\n" >"$package/ARCH"
docker save "$image" | gzip -n >"$package/images/lyflow-images.tar.gz"
cp "$root/scripts/install-offline.sh" "$package/scripts/install-offline.sh"
printf '{"fixture":true}\n' >"$package/rules/active.json"
cat >"$package/docker-compose.yml" <<EOF
services:
  agent:
    image: $image
    container_name: ly-agent-todo15-integrity-fixture
    restart: "no"
    network_mode: none
    cap_add: [NET_RAW, NET_ADMIN]
    environment:
      AGENT_MODE: local-mirror
      API_SERVER: http://127.0.0.1:1
      TRAFFIC_INTERFACE: lo
      LOG_FILE: /tmp/agent.log
EOF
"$root/scripts/release-provenance.sh" sign --package "$package" --key "$tmp/release-signer.key"

LYFLOW_INSTALL_DIR="$install_dir" LYFLOW_TRUST_DIR="$tmp/trust" \
  bash "$package/scripts/install-offline.sh" --trust-root "$tmp/release-root.pem" --generate-admin-password >/dev/null

container=ly-agent-todo15-integrity-fixture
running=$(docker inspect "$container" --format '{{.State.Running}}')
boot_logs=$(docker logs "$container" 2>&1)
if [[ "$running" != true ]]; then
  printf '%s\n' "$boot_logs" >&2
  exit 1
fi
[[ "$boot_logs" == *'Local mirror capture starting'* ]]

if binary_tamper=$(docker run --rm --entrypoint /bin/sh -e AGENT_BINARY_PATH=/tmp/ly-agent "$image" -ec \
  'cp /app/ly-agent /tmp/ly-agent; printf X >>/tmp/ly-agent; exec /tmp/ly-agent' 2>&1); then
  binary_status=0
else
  binary_status=$?
fi
if config_tamper=$(docker run --rm --entrypoint /bin/sh -e AGENT_CONFIG=/tmp/agent.yaml "$image" -ec \
  'cp /opt/ly-agent/etc/agent.yaml /tmp/agent.yaml; printf X >>/tmp/agent.yaml; exec /app/ly-agent' 2>&1); then
  config_status=0
else
  config_status=$?
fi

if [[ $binary_status -eq 0 || "$binary_tamper" != *binary_integrity_failed* ]]; then
  printf '%s\n' "$binary_tamper" >&2
  exit 1
fi
if [[ $config_status -eq 0 || "$config_tamper" != *signed_config_integrity_failed* ]]; then
  printf '%s\n' "$config_tamper" >&2
  exit 1
fi

printf 'agent production image/offline install boot and tamper fixture passed\n'
