#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
lock=${1:-}

fail() {
  printf '[traffic-corpus-contract] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -n $lock ]] || fail 'usage: traffic-corpus-contract_test.sh <traffic-corpus.lock.json>'
[[ -f $lock ]] || fail "lock does not exist: $lock"

python3 - "$root" "$lock" <<'PY'
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
lock_path = Path(sys.argv[2]).resolve()
expected_ids = (
    "suricata-et-open",
    "oisf-trafficid",
    "snort-community",
    "stamus-lateral",
    "ptresearch-attackdetection",
)
counter_names = {
    "raw_signature_count",
    "parsed_signature_count",
    "converted_signature_count",
    "persisted_signature_count",
    "signed_active_signature_count",
    "runtime_loaded_signature_count",
    "ui_displayed_signature_count",
    "rule_file_count",
}
metadata_names = (
    "license",
    "provenance",
    "format",
    "parser",
    "converter",
    "deduplication_policy",
    "attribution",
)
pin_pattern = re.compile(r"^payload-sha256:([0-9a-f]{64})$")
digest_pattern = re.compile(r"^[0-9a-f]{64}$")


def error(errors, code, source_id=""):
    errors.append(f"{code}{':' + source_id if source_id else ''}")


def validate(document, check_files):
    errors = []
    if document.get("schema_version") != "lyflow.traffic-corpus-lock/v1":
        error(errors, "invalid_schema_version")
    authority = document.get("hash_authority")
    if authority != {
        "algorithm": "sha256",
        "input": "raw_payload_bytes",
        "stage": "before_decompression_or_parsing",
    }:
        error(errors, "invalid_raw_hash_semantics")

    sources = document.get("sources")
    if not isinstance(sources, list):
        error(errors, "invalid_sources")
        return errors
    by_id = {
        source.get("source_id"): source
        for source in sources
        if isinstance(source, dict) and isinstance(source.get("source_id"), str)
    }
    if len(by_id) != len(sources):
        error(errors, "duplicate_or_invalid_source_id")
    for source_id in expected_ids:
        if source_id not in by_id:
            error(errors, "missing_source", source_id)
    for source_id in sorted(set(by_id) - set(expected_ids)):
        error(errors, "unexpected_source", source_id)

    for source_id in expected_ids:
        source = by_id.get(source_id)
        if source is None:
            continue
        manifest_value = source.get("manifest_path")
        if not isinstance(manifest_value, str):
            error(errors, "invalid_manifest_path", source_id)
            continue
        manifest_path = (root / manifest_value).resolve()
        try:
            manifest_path.relative_to(root)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            error(errors, "invalid_manifest", source_id)
            continue
        if manifest.get("source_id") != source_id:
            error(errors, "manifest_source_mismatch", source_id)
        for name in metadata_names:
            value = source.get(name)
            if not isinstance(value, str) or not value.strip():
                error(errors, f"missing_{name}", source_id)
        if source.get("license") != manifest.get("license"):
            error(errors, "manifest_license_mismatch", source_id)
        conversion = manifest.get("conversion")
        if not isinstance(conversion, dict) or source.get("converter") != conversion.get("converter"):
            error(errors, "manifest_converter_mismatch", source_id)
        for name in (
            "payload_url",
            "provenance",
            "minimum_retained_signatures",
            "format",
            "parser",
            "deduplication_policy",
            "attribution",
        ):
            if source.get(name) != manifest.get(name):
                error(errors, f"manifest_{name}_mismatch", source_id)

        minimum = source.get("minimum_retained_signatures")
        if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum <= 0:
            error(errors, "invalid_nonzero_minimum", source_id)
        pin_match = pin_pattern.fullmatch(source.get("revision_or_payload_pin", ""))
        if pin_match is None:
            error(errors, "invalid_payload_pin", source_id)

        payload = source.get("payload")
        if not isinstance(payload, dict):
            error(errors, "invalid_payload", source_id)
            continue
        raw_sha256 = payload.get("raw_sha256")
        if not isinstance(raw_sha256, str) or digest_pattern.fullmatch(raw_sha256) is None:
            error(errors, "invalid_raw_sha256", source_id)
        if pin_match is not None and raw_sha256 != pin_match.group(1):
            error(errors, "pin_raw_digest_mismatch", source_id)
        if payload.get("hash_stage") != "raw_before_decompression_or_parsing":
            error(errors, "invalid_hash_stage", source_id)
        if any(name in payload for name in ("metadata_sha256", "decompressed_sha256")):
            error(errors, "non_raw_digest_authority", source_id)

        counters = source.get("stage_counters")
        if not isinstance(counters, dict) or set(counters) != counter_names:
            error(errors, "invalid_stage_counters", source_id)
        else:
            if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counters.values()):
                error(errors, "invalid_stage_counter_value", source_id)
            elif isinstance(minimum, int) and counters["raw_signature_count"] < minimum:
                error(errors, "source_below_minimum", source_id)
            if counters["rule_file_count"] <= 0:
                error(errors, "invalid_rule_file_count", source_id)
        if any(name in source for name in ("rule_count", "file_count", "signature_count")):
            error(errors, "conflated_file_signature_count", source_id)

        if check_files:
            cache_value = payload.get("cache_path")
            if not isinstance(cache_value, str):
                error(errors, "invalid_cache_path", source_id)
                continue
            cache_path = Path(cache_value)
            try:
                raw = cache_path.read_bytes()
            except OSError:
                error(errors, "missing_cached_payload", source_id)
                continue
            if payload.get("byte_count") != len(raw):
                error(errors, "payload_size_mismatch", source_id)
            if hashlib.sha256(raw).hexdigest() != raw_sha256:
                error(errors, "payload_raw_digest_mismatch", source_id)

    totals = document.get("stage_totals")
    if not isinstance(totals, dict) or set(totals) != counter_names:
        error(errors, "invalid_stage_totals")
    elif all(source_id in by_id for source_id in expected_ids):
        for name in counter_names:
            expected = sum(by_id[source_id].get("stage_counters", {}).get(name, -1) for source_id in expected_ids)
            if totals.get(name) != expected:
                error(errors, f"stage_total_mismatch:{name}")
    return errors


try:
    lock_document = json.loads(lock_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"invalid lock JSON: {exc}")

valid_errors = validate(lock_document, True)
if valid_errors:
    raise SystemExit("lock rejected: " + ", ".join(valid_errors))

mutations = {
    "missing-source": lambda value: value["sources"].pop(),
    "metadata-hash": lambda value: value["sources"][0].__setitem__("revision_or_payload_pin", "metadata-sha256:" + "0" * 64),
    "post-decompression-hash": lambda value: value["sources"][0]["payload"].__setitem__("hash_stage", "after_decompression"),
    "missing-raw-hash-semantics": lambda value: value.__setitem__("hash_authority", {"algorithm": "sha256", "input": "catalog_metadata", "stage": "before_fetch"}),
    "missing-license": lambda value: value["sources"][0].pop("license"),
    "missing-provenance": lambda value: value["sources"][0].pop("provenance"),
    "zero-minimum": lambda value: value["sources"][0].__setitem__("minimum_retained_signatures", 0),
    "file-signature-conflation": lambda value: value["sources"][0].__setitem__("rule_count", value["sources"][0]["stage_counters"].pop("rule_file_count")),
}
for name, mutate in mutations.items():
    candidate = copy.deepcopy(lock_document)
    mutate(candidate)
    rejection = validate(candidate, False)
    if not rejection:
        raise SystemExit(f"invalid ledger accepted: {name}")
    print(f"rejected_invalid_ledger={name} reason={rejection[0]}")

print(f"traffic_corpus_contract=PASS sources={len(expected_ids)} lock={lock_path}")
PY

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
cache_dir=$(jq -er '.cache_dir' "$lock") || fail 'lock cache_dir is missing'
bash "$root/scripts/qa/prepare-traffic-corpus.sh" --cache-dir "$cache_dir" --lock-out "$tmp/traffic-corpus.lock.json" >/dev/null
cmp -s "$lock" "$tmp/traffic-corpus.lock.json" || fail 'bootstrap output is not deterministic for the same cached bytes'
printf 'deterministic_bootstrap=PASS\n'
