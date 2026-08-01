#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=${1:-${RUNNER_TEMP:-/tmp}/lyflow-rule-build}
downloads="$work/downloads"
lock="$work/traffic-corpus.lock.json"
snapshot="$root/rules/cloud-snapshot"

rm -rf "$work" "$snapshot"
mkdir -p "$downloads" "$snapshot/raw" "$snapshot/converted" "$snapshot/reports" "$snapshot/compiled"

bash "$root/scripts/qa/prepare-traffic-corpus.sh" --cache-dir "$downloads" --lock-out "$lock"

inputs=()
while IFS=$'\t' read -r source_id payload format manifest; do
  source="$snapshot/raw/$source_id.rules"
  output="$snapshot/converted/$source_id"
  report="$snapshot/reports/$source_id.json"
  quarantine="$snapshot/reports/$source_id-quarantine.json"
  mkdir -p "$output"

  python3 - "$payload" "$format" "$source" <<'PY'
import sys
import tarfile
from pathlib import Path

payload = Path(sys.argv[1])
payload_format = sys.argv[2]
destination = Path(sys.argv[3])
if payload_format.startswith("tar+gzip/"):
    with tarfile.open(payload, mode="r:gz") as archive:
        members = sorted(
            (member for member in archive.getmembers() if member.isfile() and member.name.endswith(".rules")),
            key=lambda member: member.name,
        )
        if not members:
            raise RuntimeError("rule archive contains no .rules files")
        content = []
        for member in members:
            stream = archive.extractfile(member)
            if stream is None:
                raise RuntimeError(f"cannot read {member.name}")
            content.append(stream.read())
    destination.write_bytes(b"\n".join(content))
elif payload_format == "text/suricata-rules":
    destination.write_bytes(payload.read_bytes())
else:
    raise RuntimeError(f"unsupported payload format: {payload_format}")
PY

  python3 "$root/scripts/convert-suricata-dpi.py" \
    --source "$source" \
    --manifest "$root/$manifest" \
    --output-dir "$output" \
    --report "$report" \
    --quarantine-report "$quarantine"
  jq -e '.parsed > 0 and .converted > 0 and (.parsed == (.converted + .unsupported + .deduplicated))' "$report" >/dev/null
  inputs+=(--input-dir "$output")
done < <(jq -r '.sources[] | [.source_id,.payload.cache_path,.format,.manifest_path] | @tsv' "$lock")

python3 "$root/scripts/deduplicate-rule-ir.py" \
  --output-dir "$snapshot/compiled" \
  --report "$snapshot/reports/deduplication.json" \
  "${inputs[@]}"
jq -e '.input_rules > 0 and .output_rules > 0' "$snapshot/reports/deduplication.json" >/dev/null

python3 - "$lock" "$snapshot" "${GITHUB_SHA:-$(git -C "$root" rev-parse HEAD)}" <<'PY'
import datetime
import json
import sys
from pathlib import Path

lock_path = Path(sys.argv[1])
snapshot = Path(sys.argv[2])
source_commit = sys.argv[3]
document = json.loads(lock_path.read_text(encoding="utf-8"))
document["generated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
document["source_commit"] = source_commit
document["cache_policy"] = "fresh-download-no-cross-run-cache"

for source in document["sources"]:
    source_id = source["source_id"]
    report = json.loads((snapshot / "reports" / f"{source_id}.json").read_text(encoding="utf-8"))
    raw_path = snapshot / "raw" / f"{source_id}.rules"
    source["payload"]["cache_path"] = f"rules/cloud-snapshot/raw/{source_id}.rules"
    source["payload"]["decoded_byte_count"] = raw_path.stat().st_size
    counters = source["stage_counters"]
    counters["parsed_signature_count"] = report["parsed"]
    counters["converted_signature_count"] = report["converted"]
    counters["persisted_signature_count"] = report["converted"]

for name in document["stage_totals"]:
    document["stage_totals"][name] = sum(source["stage_counters"][name] for source in document["sources"])

(snapshot / "manifest.json").write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

find "$snapshot/compiled" -type f -name '*.json' -print0 | sort -z | xargs -0 sha256sum > "$snapshot/compiled.sha256"
jq -n \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg source_commit "${GITHUB_SHA:-$(git -C "$root" rev-parse HEAD)}" \
  --argjson source_count "$(jq '.sources | length' "$snapshot/manifest.json")" \
  --argjson compiled_count "$(find "$snapshot/compiled" -type f -name '*.json' | wc -l)" \
  '{schema_version:"lyflow.cloud-rule-build/v1",generated_at:$generated_at,source_commit:$source_commit,cache_policy:"fresh-download-no-cross-run-cache",source_count:$source_count,compiled_rule_count:$compiled_count}' \
  > "$snapshot/build.json"

echo "Fresh rule snapshot built: $(jq -r '.compiled_rule_count' "$snapshot/build.json") compiled rules"
