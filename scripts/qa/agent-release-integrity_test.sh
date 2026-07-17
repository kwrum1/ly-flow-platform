#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tool="$root/scripts/release-provenance.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

openssl genpkey -algorithm ED25519 -out "$tmp/release-signer.key" >/dev/null 2>&1
openssl pkey -in "$tmp/release-signer.key" -pubout -out "$tmp/release-root.pem" >/dev/null 2>&1
printf 'signed agent fixture\n' >"$tmp/ly-agent"

bash "$tool" sign-artifact --artifact "$tmp/ly-agent" --output "$tmp/agent-binary.digest.json" --key "$tmp/release-signer.key"
jq -e '
  .payload.schema_version == "lyflow.signed_digest.v1" and
  .payload.artifact == "ly-agent" and
  (.payload.digest | test("^[0-9a-f]{64}$")) and
  (.payload.signer_fingerprint | test("^[0-9a-f]{64}$")) and
  (.signature | test("^[0-9a-f]{128}$"))
' "$tmp/agent-binary.digest.json" >/dev/null

jq -cj '.payload' "$tmp/agent-binary.digest.json" >"$tmp/payload.json"
jq -r '.signature' "$tmp/agent-binary.digest.json" | xxd -r -p >"$tmp/signature.bin"
openssl pkeyutl -verify -pubin -inkey "$tmp/release-root.pem" -rawin -in "$tmp/payload.json" -sigfile "$tmp/signature.bin" >/dev/null

printf 'agent release integrity signer self-test passed\n'
