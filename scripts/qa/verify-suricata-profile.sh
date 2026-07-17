#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
lock=${SURICATA_PROFILE_LOCK:-$root/third_party/security-engines/suricata-profile.lock.json}
config=${SURICATA_PROFILE_CONFIG:-$root/rules/suricata/suricata-profile.yaml}
rules=${SURICATA_PROFILE_RULES:-$root/rules/suricata/et-open.rules}
rules_metadata=${SURICATA_PROFILE_RULES_METADATA:-$root/rules/suricata/suricata-profile.rules.json}
fixtures=${SURICATA_PROFILE_FIXTURES:-$root/agent/cmd/testdata/suricata/7.0.11/eve.jsonl}
golden=${SURICATA_PROFILE_GOLDEN:-$root/agent/cmd/testdata/suricata/7.0.11/canonical.golden.json}
pcap=${SURICATA_PROFILE_PCAP:-$root/agent/cmd/testdata/suricata/7.0.11/inert.pcap}
normalizer=$root/scripts/qa/normalize-suricata-eve.jq
generator=$root/agent/cmd/suricata_pcap_fixture_test.go

for path in "$lock" "$config" "$rules" "$rules_metadata" "$fixtures" "$golden" "$pcap" "$normalizer" "$generator"; do
  [[ -f "$path" ]] || { printf 'missing Suricata profile artifact: %s\n' "$path" >&2; exit 1; }
done
for command in cmp docker go jq sha256sum timeout; do
  command -v "$command" >/dev/null 2>&1 || { printf 'required local command unavailable: %s\n' "$command" >&2; exit 2; }
done

jq -e '
  .schema_version == "lyflow.suricata_profile_lock.v1" and
  .engine_version == "7.0.11" and
  .native_schema == "suricata.eve.v7.0.11" and
  .image == "docker.io/jasonish/suricata@sha256:73cf099d6299f75dda2d9d6edcfb8238b7a7322566d6189a69d46442a366b7fa" and
  .image_digest == "sha256:73cf099d6299f75dda2d9d6edcfb8238b7a7322566d6189a69d46442a366b7fa" and
  .image_platform == "linux/amd64" and
  .image_platform_digest == "sha256:84c672480ff73520c4d5deef001243542b0fdcdd68ab8ca09bd0ab31851a52ff" and
  .source_tag_object == "f8c635860940b336d976224887e50d9713c12022" and
  .source_release_commit == "98b12d1c30e6f8db1e38f3c34abf965a4d03b062" and
  .source_tag_signer_fingerprint == "1DBF03667457EB6AED9E0DF9C1F495E3926856B4" and
  .source_archive_sha256 == "dd732464af4336298696fe102ff18285140895646990be74b4865f4c90b66738" and
  .source_archive_signature_sha256 == "b5540f3eb063a675e56e8fb3560f2e129f40c942ef0d5e8966e82633518cd537" and
  .source_archive_signer_fingerprint == "B36FDAF2607E10E8FFA89E5E2BA9C98CCDF1E93A" and
  .vendored_source_commit == "367ca7f430f85be01a6cdc65ddaa1636a50ddefc" and
  .generated_eve_records == 8 and
  .generated_eve_type_counts == {"alert": 1, "dns": 2, "flow": 3, "http": 1, "tls": 1} and
  .rule_pack_version == "lyflow-suricata-profile-rules-v1" and
  .enabled_by_default == false and
  .coverage == ["flow", "alert", "dns", "http", "tls"] and
  ([.coverage[] | select(. == "ssh" or . == "smb" or . == "kerberos")] | length == 0)
' "$lock" >/dev/null

config_sha=$(sha256sum "$config" | cut -d' ' -f1)
rules_sha=$(sha256sum "$rules" | cut -d' ' -f1)
pcap_sha=$(sha256sum "$pcap" | cut -d' ' -f1)
fixture_sha=$(sha256sum "$fixtures" | cut -d' ' -f1)
golden_sha=$(sha256sum "$golden" | cut -d' ' -f1)
generator_sha=$(sha256sum "$generator" | cut -d' ' -f1)
normalizer_sha=$(sha256sum "$normalizer" | cut -d' ' -f1)
[[ "$config_sha" == "$(jq -r '.config_sha256' "$lock")" ]] || { printf 'Suricata config digest drift\n' >&2; exit 1; }
[[ "$rules_sha" == "$(jq -r '.rules_sha256' "$lock")" ]] || { printf 'Suricata rules digest drift\n' >&2; exit 1; }
[[ "$pcap_sha" == "$(jq -r '.pcap_sha256' "$lock")" ]] || { printf 'Suricata inert pcap digest drift\n' >&2; exit 1; }
[[ "$fixture_sha" == "$(jq -r '.generated_eve_sha256' "$lock")" ]] || { printf 'Suricata normalized EVE digest drift\n' >&2; exit 1; }
[[ "$golden_sha" == "$(jq -r '.golden_sha256' "$lock")" ]] || { printf 'Suricata canonical golden digest drift\n' >&2; exit 1; }
[[ "$generator_sha" == "$(jq -r '.pcap_generator_sha256' "$lock")" ]] || { printf 'Suricata PCAP generator digest drift\n' >&2; exit 1; }
[[ "$normalizer_sha" == "$(jq -r '.normalizer_sha256' "$lock")" ]] || { printf 'Suricata EVE normalizer digest drift\n' >&2; exit 1; }
gopacket_version=$(cd "$root/agent" && GOWORK=off GOPROXY=off go list -m -f '{{.Version}}' github.com/google/gopacket)
toolchain="$(go env GOVERSION) github.com/google/gopacket@$gopacket_version"
[[ "$toolchain" == "$(jq -r '.pcap_generator_toolchain' "$lock")" ]] || { printf 'Suricata PCAP generator toolchain drift\n' >&2; exit 1; }
jq -e --arg digest "$rules_sha" '
  .schema_version == "lyflow.suricata_rules.v1" and
  .engine_version == "7.0.11" and
  .rule_pack_version == "lyflow-suricata-profile-rules-v1" and
  .rules_sha256 == $digest and
  .enabled_by_default == false
' "$rules_metadata" >/dev/null
valid_until=$(jq -r '.valid_until' "$rules_metadata")
[[ $(date -u -d "$valid_until" +%s) -gt $(date -u +%s) ]] || { printf 'Suricata rules metadata is stale: %s\n' "$valid_until" >&2; exit 1; }

for token in '        - flow' '        - alert:' '        - dns:' '        - http:' '        - tls:'; do
  grep -Fqx "$token" "$config" || { printf 'Suricata EVE config lacks pinned coverage token: %s\n' "$token" >&2; exit 1; }
done
for token in '    ssh:' '    smb:' '    krb5:'; do
  line=$(grep -Fn "$token" "$config" | cut -d: -f1)
  [[ -n "$line" ]] || { printf 'Suricata config lacks explicit disabled protocol: %s\n' "$token" >&2; exit 1; }
  next=$((line + 1))
  [[ $(sed -n "${next}p" "$config") == '      enabled: no' ]] || { printf 'unsupported protocol is not disabled: %s\n' "$token" >&2; exit 1; }
done

jq -e -s '
  length == 8 and
  (group_by(.event_type) | map({key: .[0].event_type, value: length}) | from_entries) ==
    {"alert": 1, "dns": 2, "flow": 3, "http": 1, "tls": 1} and
  all(.[]; .suricata_version == "7.0.11")
' "$fixtures" >/dev/null
jq -e '
  length == 8 and
  ([.[].kind] | map(select(. == "alert")) | length) == 1
' "$golden" >/dev/null

tmp=$(mktemp -d)
compose_json=$tmp/compose.json
trap 'rm -rf "$tmp"' EXIT INT TERM
timeout 60s "$root/scripts/qa/verify-suricata-provenance.sh" >"$tmp/provenance-check.log"
(
	cd "$root/agent"
	SURICATA_PCAP_OUTPUT="$tmp/generated.pcap" GOWORK=off GOPROXY=off timeout 60s go test -run '^TestGenerateSuricataProfilePCAP$' ./cmd >"$tmp/pcap-generation.log"
)
cmp -s "$tmp/generated.pcap" "$pcap" || { printf 'Suricata generated pcap differs from pinned fixture\n' >&2; exit 1; }
REDIS_ACL_USERNAME=lyflow REDIS_ACL_PASSWORD=lyflow-suricata-profile-qa REDIS_PASSWORD=lyflow-suricata-legacy-qa \
  SECURITY_ENGINE_CONTROL_TOKEN=lyflow-suricata-profile-control-qa \
  timeout 20s docker compose --profile suricata-profile -f "$root/docker-compose.yml" config --format json >"$compose_json"
jq -e '
  .services["ly-suricata-sensor"].profiles == ["suricata-profile"] and
  .services["ly-suricata-sensor"].build.target == "suricata-profile" and
  .services["ly-suricata-sensor"].build.args.SURICATA_PROFILE_IMAGE == "docker.io/jasonish/suricata@sha256:73cf099d6299f75dda2d9d6edcfb8238b7a7322566d6189a69d46442a366b7fa" and
  .services["ly-agent"].environment.SURICATA_PROFILE_ENABLED == "true"
' "$compose_json" >/dev/null

image=$(jq -r '.image' "$lock")
timeout 30s docker run --rm --pull never --network none --entrypoint suricata \
  -v "$config:/evidence/suricata-profile.yaml:ro" \
  -v "$rules:/evidence/et-open.rules:ro" \
  "$image" -T -c /evidence/suricata-profile.yaml -S /evidence/et-open.rules >"$tmp/config-check.log" 2>&1
mkdir "$tmp/eve"
timeout 30s docker run --rm --pull never --network none --user 0:0 --entrypoint suricata \
  -v "$config:/evidence/suricata-profile.yaml:ro" \
  -v "$rules:/evidence/et-open.rules:ro" \
  -v "$pcap:/evidence/inert.pcap:ro" \
  -v "$tmp/eve:/var/log/suricata" \
  "$image" -c /evidence/suricata-profile.yaml -S /evidence/et-open.rules -r /evidence/inert.pcap -l /var/log/suricata --runmode single >"$tmp/eve-generation.log" 2>&1
jq -csS -f "$normalizer" "$tmp/eve/eve.json" >"$tmp/eve.normalized.jsonl"
generated_records=$(jq -s 'length' "$tmp/eve.normalized.jsonl")
[[ "$generated_records" == "$(jq -r '.generated_eve_records' "$lock")" ]] || { printf 'Suricata generated EVE record count drift\n' >&2; exit 1; }
jq -e -s --argjson expected "$(jq '.generated_eve_type_counts' "$lock")" '
  (group_by(.event_type) | map({key: .[0].event_type, value: length}) | from_entries) == $expected
' "$tmp/eve.normalized.jsonl" >/dev/null || { printf 'Suricata generated EVE type coverage drift\n' >&2; exit 1; }
cmp -s "$tmp/eve.normalized.jsonl" "$fixtures" || { printf 'Suricata generated normalized EVE differs from pinned fixture\n' >&2; exit 1; }
eve_sha=$(sha256sum "$tmp/eve.normalized.jsonl" | cut -d' ' -f1)
(
  cd "$root/agent"
  GOWORK=off GOPROXY=off timeout 60s go test -run '^TestSuricataProfileGoldenReplayNormalizesPinnedEVE$' ./cmd >"$tmp/golden-check.log"
)

printf 'SURICATA_PROFILE_CONFIG_CHECK=PASS version=7.0.11 coverage=flow,alert,dns,http,tls native_check=pass image_digest=%s pcap_sha256=%s eve_sha256=%s generated_eve_records=%s network_pull=false\n' \
  "$(jq -r '.image_digest' "$lock")" "$pcap_sha" "$eve_sha" "$generated_records"
