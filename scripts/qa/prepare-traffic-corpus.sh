#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cache_dir=
lock_out=

fail() {
  printf '[prepare-traffic-corpus] ERROR: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --cache-dir)
      [[ $# -ge 2 ]] || fail '--cache-dir requires a value'
      cache_dir=$2
      shift 2
      ;;
    --lock-out)
      [[ $# -ge 2 ]] || fail '--lock-out requires a value'
      lock_out=$2
      shift 2
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n $cache_dir ]] || fail '--cache-dir is required'
[[ -n $lock_out ]] || fail '--lock-out is required'
[[ $cache_dir = /* ]] || fail '--cache-dir must be absolute'

manifests=(
  "$root/rules/subscriptions/suricata/manifest.json"
  "$root/rules/subscriptions/trafficid/manifest.json"
  "$root/rules/subscriptions/snort-community/manifest.json"
  "$root/rules/subscriptions/stamus-lateral/manifest.json"
  "$root/rules/subscriptions/pt-attackdetection/manifest.json"
)

python3 "$root/scripts/validate-rule-manifests.py" "${manifests[@]}" >/dev/null
mkdir -p "$cache_dir"
[[ -d $cache_dir && ! -L $cache_dir ]] || fail 'cache directory must be a real directory'
cache_dir=$(realpath "$cache_dir")

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
hash_inputs="$tmp/raw-byte-sha256.tsv"
: >"$hash_inputs"

for manifest in "${manifests[@]}"; do
  source_id=$(jq -er '.source_id | select(type == "string" and length > 0)' "$manifest") \
    || fail "missing source_id: $manifest"
  payload_url=$(jq -er '.payload_url | select(type == "string" and startswith("https://"))' "$manifest") \
    || fail "missing HTTPS payload_url: $manifest"
  payload="$cache_dir/$source_id.raw"
  if [[ -e $payload ]]; then
    [[ -f $payload && ! -L $payload && -s $payload ]] || fail "cached payload is not a nonempty regular file: $payload"
    printf 'cache_hit=%s\n' "$payload"
  else
    download=$(mktemp "$cache_dir/.$source_id.download.XXXXXX")
    if ! curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        --retry 3 --retry-all-errors --connect-timeout 30 --max-time 600 \
        "$payload_url" --output "$download"; then
      rm -f "$download"
      fail "unable to materialize vendor payload: $source_id from $payload_url"
    fi
    [[ -s $download ]] || {
      rm -f "$download"
      fail "vendor payload is empty: $source_id"
    }
    chmod 0444 "$download"
    mv "$download" "$payload"
    printf 'materialized=%s source=%s\n' "$payload" "$payload_url"
  fi

  digest_line=$(sha256sum "$payload")
  digest=${digest_line%% *}
  printf '%s\t%s\t%s\n' "$manifest" "$payload" "$digest" >>"$hash_inputs"
  printf 'raw_sha256=%s source_id=%s bytes=%s\n' "$digest" "$source_id" "$(stat -c %s "$payload")"
done

lock_parent=$(dirname "$lock_out")
mkdir -p "$lock_parent"
lock_tmp=$(mktemp "$lock_parent/.traffic-corpus.lock.XXXXXX")

if ! python3 - "$root" "$cache_dir" "$hash_inputs" "$lock_tmp" <<'PY'
import hashlib
import io
import json
import re
import sys
import tarfile
from pathlib import Path

root = Path(sys.argv[1]).resolve()
cache_dir = Path(sys.argv[2]).resolve()
hash_input_path = Path(sys.argv[3])
output_path = Path(sys.argv[4])
signature_pattern = re.compile(rb"^\s*(?:alert|drop|reject|pass)\s", re.MULTILINE)
required_metadata = (
    "payload_url",
    "provenance",
    "minimum_retained_signatures",
    "format",
    "parser",
    "deduplication_policy",
    "attribution",
)
counter_names = (
    "raw_signature_count",
    "parsed_signature_count",
    "converted_signature_count",
    "persisted_signature_count",
    "signed_active_signature_count",
    "runtime_loaded_signature_count",
    "ui_displayed_signature_count",
    "rule_file_count",
)


def fail(message):
    raise ValueError(message)


def archive_counts(raw, source_id):
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            members = [member for member in archive.getmembers() if member.isfile() and member.name.endswith(".rules")]
            if not members:
                fail(f"archive contains no rule files: {source_id}")
            signature_count = 0
            for member in members:
                stream = archive.extractfile(member)
                if stream is None:
                    fail(f"cannot read archive member: {source_id}:{member.name}")
                signature_count += len(signature_pattern.findall(stream.read()))
            return len(members), signature_count
    except tarfile.TarError as exc:
        fail(f"invalid tar+gzip payload: {source_id}: {exc}")


sources = []
manifest_inputs = []
for line in hash_input_path.read_text(encoding="utf-8").splitlines():
    manifest_name, payload_name, shell_digest = line.split("\t")
    manifest_path = Path(manifest_name).resolve()
    payload_path = Path(payload_name).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    source_id = manifest.get("source_id")
    if not isinstance(source_id, str) or not source_id:
        fail(f"missing source_id: {manifest_path}")
    for name in required_metadata:
        if name not in manifest or manifest[name] in (None, ""):
            fail(f"missing {name}: {source_id}")
    minimum = manifest["minimum_retained_signatures"]
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum <= 0:
        fail(f"minimum_retained_signatures must be nonzero: {source_id}")

    raw = payload_path.read_bytes()
    raw_digest = hashlib.sha256(raw).hexdigest()
    if raw_digest != shell_digest:
        fail(f"raw payload changed after pre-decompression hash: {source_id}")
    payload_format = manifest["format"]
    if payload_format.startswith("tar+gzip/"):
        rule_file_count, raw_signature_count = archive_counts(raw, source_id)
    elif payload_format == "text/suricata-rules":
        rule_file_count = 1
        raw_signature_count = len(signature_pattern.findall(raw))
    else:
        fail(f"unsupported payload format: {source_id}: {payload_format}")
    if raw_signature_count < minimum:
        fail(f"source below nonzero minimum: {source_id}: {raw_signature_count} < {minimum}")

    relative_manifest = manifest_path.relative_to(root).as_posix()
    manifest_inputs.append(relative_manifest)
    counters = {
        "raw_signature_count": raw_signature_count,
        "parsed_signature_count": 0,
        "converted_signature_count": 0,
        "persisted_signature_count": 0,
        "signed_active_signature_count": 0,
        "runtime_loaded_signature_count": 0,
        "ui_displayed_signature_count": 0,
        "rule_file_count": rule_file_count,
    }
    sources.append({
        "source_id": source_id,
        "name": manifest["name"],
        "vendor": manifest["vendor"],
        "manifest_path": relative_manifest,
        "source_url": manifest["source_url"],
        "payload_url": manifest["payload_url"],
        "revision_or_payload_pin": f"payload-sha256:{raw_digest}",
        "license": manifest["license"],
        "provenance": manifest["provenance"],
        "minimum_retained_signatures": minimum,
        "format": payload_format,
        "parser": manifest["parser"],
        "converter": manifest["conversion"]["converter"],
        "deduplication_policy": manifest["deduplication_policy"],
        "attribution": manifest["attribution"],
        "payload": {
            "cache_path": str(payload_path),
            "byte_count": len(raw),
            "raw_sha256": raw_digest,
            "hash_stage": "raw_before_decompression_or_parsing",
        },
        "stage_counters": counters,
    })

stage_totals = {
    name: sum(source["stage_counters"][name] for source in sources)
    for name in counter_names
}
document = {
    "schema_version": "lyflow.traffic-corpus-lock/v1",
    "cache_dir": str(cache_dir),
    "manifest_inputs": manifest_inputs,
    "hash_authority": {
        "algorithm": "sha256",
        "input": "raw_payload_bytes",
        "stage": "before_decompression_or_parsing",
    },
    "sources": sources,
    "stage_totals": stage_totals,
}
output_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
then
  rm -f "$lock_tmp"
  fail 'corpus lock generation failed'
fi

chmod 0644 "$lock_tmp"
mv "$lock_tmp" "$lock_out"
printf 'lock_generated=%s sha256=%s\n' "$lock_out" "$(sha256sum "$lock_out" | cut -d' ' -f1)"
