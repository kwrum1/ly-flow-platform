#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
lock="$root/rules/traffic-corpus.lock.json"
signatures="$root/acceptance-evidence/T09/signature-provenance.json"
counts="$root/acceptance-evidence/T09/source-counts.json"
evidence="$root/acceptance-evidence/T10"
tmp=$(mktemp -d /tmp/lyflow-t10.XXXXXX)
mkdir -p "$evidence"
trap 'rm -rf "$tmp"' EXIT INT TERM
exec > >(tee "$evidence/command.log") 2>&1

git -C "$root" status --short >"$evidence/worktree-status.txt"
git -C "$root" rev-parse HEAD >"$evidence/start-commit.txt"
for input in "$lock" "$signatures" "$counts"; do
  [[ -s $input ]] || { printf 'missing provenance input: %s\n' "$input" >&2; exit 1; }
done

openssl genpkey -algorithm ED25519 -out "$tmp/provenance.key" >/dev/null 2>&1
openssl pkey -in "$tmp/provenance.key" -pubout -out "$evidence/provenance-root.pem" >/dev/null 2>&1
fingerprint=$(openssl pkey -pubin -in "$evidence/provenance-root.pem" -outform DER | sha256sum)
fingerprint=${fingerprint%% *}
bundle_digest=$(sha256sum "$signatures")
bundle_digest=${bundle_digest%% *}
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

jq -n -S --slurpfile lock "$lock" --slurpfile signatures "$signatures" --slurpfile counts "$counts" \
  --arg bundle_digest "$bundle_digest" --arg signer "$fingerprint" --arg generated_at "$generated_at" '
  {
    schema_version:"lyflow.signed-traffic-provenance/v1",
    status:"candidate",
    generated_at:$generated_at,
    bundle_digest:$bundle_digest,
    signer_fingerprint:$signer,
    signature_count:$signatures[0].signature_count,
    sources:[$lock[0].sources[]|{
      source_id,vendor,license,provenance,revision_or_payload_pin,parser,converter,
      deduplication_policy,attribution,payload_raw_sha256:.payload.raw_sha256,
      payload_hash_stage:.payload.hash_stage
    }],
    stage_counts:$counts[0].totals,
    signatures:$signatures[0].signatures
  }' >"$evidence/candidate-traffic-ledger.json"

validate_ledger() {
  jq -e '
    .schema_version == "lyflow.signed-traffic-provenance/v1" and .status == "candidate" and
    (.generated_at | type == "string" and length > 0) and
    (.bundle_digest | test("^[0-9a-f]{64}$")) and
    (.signer_fingerprint | test("^[0-9a-f]{64}$")) and
    (.sources | length == 5) and
    (all(.sources[];
      (.source_id|length>0) and (.vendor|length>0) and (.license|length>0) and (.provenance|length>0) and
      (.revision_or_payload_pin|type == "string" and test("^(payload-sha256:[0-9a-f]{64}|[A-Za-z0-9._-]+)$")) and
      (.payload_raw_sha256|type == "string" and test("^[0-9a-f]{64}$")) and
      .payload_hash_stage == "raw_before_decompression_or_parsing" and
      (.parser|length>0) and (.converter|length>0) and (.deduplication_policy|length>0))) and
    ([.sources[].source_id] as $known |
      .signature_count == (.signatures|length) and .signature_count > 0 and
      all(.signatures[]; (.rule_id|type == "string" and length>0) and (.content_sha256|type == "string" and test("^[0-9a-f]{64}$")) and
        (.source_ids|length>0) and all(.source_ids[]; IN($known[]))))
  ' "$1" >/dev/null
}

validate_ledger "$evidence/candidate-traffic-ledger.json"
openssl pkeyutl -sign -rawin -inkey "$tmp/provenance.key" -in "$evidence/candidate-traffic-ledger.json" -out "$evidence/candidate-traffic-ledger.sig"
openssl pkeyutl -verify -rawin -pubin -inkey "$evidence/provenance-root.pem" -in "$evidence/candidate-traffic-ledger.json" -sigfile "$evidence/candidate-traffic-ledger.sig" >/dev/null

reject_invalid() {
  if validate_ledger "$1"; then
    printf 'invalid provenance ledger accepted: %s\n' "$1" >&2
    exit 1
  fi
}
jq 'del(.sources[0].revision_or_payload_pin)' "$evidence/candidate-traffic-ledger.json" >"$tmp/missing-revision.json"
reject_invalid "$tmp/missing-revision.json"
jq 'del(.sources[0].payload_raw_sha256)' "$evidence/candidate-traffic-ledger.json" >"$tmp/missing-raw-digest.json"
reject_invalid "$tmp/missing-raw-digest.json"
jq '.signatures[0].source_ids=["unknown-source"]' "$evidence/candidate-traffic-ledger.json" >"$tmp/untraceable.json"
reject_invalid "$tmp/untraceable.json"
jq '.signatures[0].content_sha256=("0"*64)' "$evidence/candidate-traffic-ledger.json" >"$tmp/altered-converted.json"
if openssl pkeyutl -verify -rawin -pubin -inkey "$evidence/provenance-root.pem" -in "$tmp/altered-converted.json" -sigfile "$evidence/candidate-traffic-ledger.sig" >/dev/null 2>&1; then
  printf 'altered converted signature was accepted\n' >&2
  exit 1
fi
if openssl pkeyutl -verify -rawin -pubin -inkey "$evidence/provenance-root.pem" -in "$evidence/candidate-traffic-ledger.json" -sigfile /dev/null >/dev/null 2>&1; then
  printf 'unsigned ledger was accepted\n' >&2
  exit 1
fi

bash "$root/scripts/qa/verify-suricata-provenance.sh"
bash "$root/scripts/qa/release-provenance_test.sh"
jq '{status:"PASS",ledger_status:.status,signature_count,source_count:(.sources|length),bundle_digest,signer_fingerprint,generated_at}' "$evidence/candidate-traffic-ledger.json" >"$evidence/provenance-chain.json"
printf 'PROVENANCE_RESULT=PASS status=candidate sources=5 signatures=%s offline_signature=true\n' "$(jq -r .signature_count "$evidence/candidate-traffic-ledger.json")"
