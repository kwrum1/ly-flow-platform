#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

jq -e '.generated_eve_records > 0' "$root/third_party/security-engines/suricata-profile.lock.json" >/dev/null
timeout 60s "$root/scripts/qa/verify-suricata-profile.sh" >"$tmp/pass.out"
grep -Eq '^SURICATA_PROFILE_CONFIG_CHECK=PASS version=7\.0\.11 coverage=flow,alert,dns,http,tls native_check=pass image_digest=sha256:73cf099d6299f75dda2d9d6edcfb8238b7a7322566d6189a69d46442a366b7fa pcap_sha256=[0-9a-f]{64} eve_sha256=[0-9a-f]{64} generated_eve_records=[1-9][0-9]* network_pull=false$' "$tmp/pass.out"

jq '.valid_until = "2026-01-01T00:00:00Z"' "$root/rules/suricata/suricata-profile.rules.json" >"$tmp/stale-rules.json"
if SURICATA_PROFILE_RULES_METADATA="$tmp/stale-rules.json" timeout 30s "$root/scripts/qa/verify-suricata-profile.sh" >"$tmp/stale.out" 2>&1; then
  printf 'stale Suricata rules metadata was accepted\n' >&2
  exit 1
fi
grep -Fq 'Suricata rules metadata is stale' "$tmp/stale.out"

cp "$root/agent/cmd/testdata/suricata/7.0.11/inert.pcap" "$tmp/drift.pcap"
printf x >>"$tmp/drift.pcap"
if SURICATA_PROFILE_PCAP="$tmp/drift.pcap" timeout 30s "$root/scripts/qa/verify-suricata-profile.sh" >"$tmp/drift.out" 2>&1; then
  printf 'drifted Suricata inert pcap was accepted\n' >&2
  exit 1
fi
grep -Fq 'Suricata inert pcap digest drift' "$tmp/drift.out"

printf 'Suricata profile QA self-test passed\n'
