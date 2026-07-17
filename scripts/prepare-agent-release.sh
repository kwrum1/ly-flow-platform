#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary=${AGENT_RELEASE_BINARY:-$root/agent/ly-agent}
output=${AGENT_RELEASE_OUTPUT:-$root/agent/dist/release}
key=${RELEASE_SIGNING_KEY:-}

[[ -x "$binary" ]] || { printf '[agent-release] ERROR: executable Agent binary missing: %s\n' "$binary" >&2; exit 1; }
[[ -f "$key" ]] || { printf '[agent-release] ERROR: RELEASE_SIGNING_KEY must name an Ed25519 private key\n' >&2; exit 1; }

rm -rf "$output"
mkdir -p "$output"
install -m 0755 "$binary" "$output/ly-agent"
cat >"$output/agent.yaml" <<'EOF'
# Signed release defaults. Deployment-specific values are supplied by environment.
agent:
  log_level: info
runtime:
  telemetry_stream: telemetry:runtime
EOF
openssl pkey -in "$key" -pubout -out "$output/agent-integrity-root.pem"
chmod 0644 "$output/agent-integrity-root.pem"
"$root/scripts/release-provenance.sh" sign-artifact --artifact "$output/ly-agent" --output "$output/agent-binary.digest.json" --key "$key"
"$root/scripts/release-provenance.sh" sign-artifact --artifact "$output/agent.yaml" --output "$output/agent-config.digest.json" --key "$key"

printf '[agent-release] signed Agent runtime prepared in %s\n' "$output"
