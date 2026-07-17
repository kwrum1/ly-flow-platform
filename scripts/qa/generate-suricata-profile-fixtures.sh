#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
lock="$root/third_party/security-engines/suricata-profile.lock.json"
config="$root/rules/suricata/suricata-profile.yaml"
rules="$root/rules/suricata/et-open.rules"
fixture_dir="$root/agent/cmd/testdata/suricata/7.0.11"
normalizer="$root/scripts/qa/normalize-suricata-eve.jq"
image=$(jq -r '.image' "$lock")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

for command in docker go jq; do
	command -v "$command" >/dev/null 2>&1 || { printf 'required local command unavailable: %s\n' "$command" >&2; exit 2; }
done

mkdir "$tmp/eve"
(
	cd "$root/agent"
	SURICATA_PCAP_OUTPUT="$tmp/inert.pcap" GOWORK=off go test -run '^TestGenerateSuricataProfilePCAP$' ./cmd
)
timeout 30s docker run --rm --pull never --network none --user 0:0 --entrypoint suricata \
	-v "$config:/evidence/suricata-profile.yaml:ro" \
	-v "$rules:/evidence/et-open.rules:ro" \
	-v "$tmp/inert.pcap:/evidence/inert.pcap:ro" \
	-v "$tmp/eve:/var/log/suricata" \
	"$image" -c /evidence/suricata-profile.yaml -S /evidence/et-open.rules \
	-r /evidence/inert.pcap -l /var/log/suricata --runmode single >"$tmp/suricata.log" 2>&1

jq -csS -f "$normalizer" "$tmp/eve/eve.json" >"$tmp/eve.normalized.jsonl"

jq -e -s '
	length == 8 and
	(group_by(.event_type) | map({key: .[0].event_type, value: length}) | from_entries) ==
	{"alert": 1, "dns": 2, "flow": 3, "http": 1, "tls": 1}
' "$tmp/eve.normalized.jsonl" >/dev/null

cp "$tmp/inert.pcap" "$fixture_dir/inert.pcap"
cp "$tmp/eve.normalized.jsonl" "$fixture_dir/eve.jsonl"
(
	cd "$root/agent"
	UPDATE_SURICATA_PROFILE_GOLDEN=1 GOWORK=off go test -run '^TestSuricataProfileGoldenReplayNormalizesPinnedEVE$' ./cmd
)

sha256sum "$fixture_dir/inert.pcap" "$fixture_dir/eve.jsonl" "$fixture_dir/canonical.golden.json"
