#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
lock="$root/rules/traffic-corpus.lock.json"
evidence="$root/acceptance-evidence/T09"
tmp=$(mktemp -d /tmp/lyflow-t09.XXXXXX)
mkdir -p "$evidence"
trap 'rm -rf "$tmp"' EXIT INT TERM
exec > >(tee "$evidence/command.log") 2>&1

git -C "$root" status --short >"$evidence/worktree-status.txt"
git -C "$root" rev-parse HEAD >"$evidence/start-commit.txt"
: >"$tmp/summaries.jsonl"
input_args=()

tree_hash() {
  python3 - "$1" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
digest = hashlib.sha256()
for path in sorted(root.glob("*.json")):
    digest.update(path.name.encode())
    digest.update(path.read_bytes())
print(digest.hexdigest())
PY
}

while IFS=$'\t' read -r source_id payload format manifest; do
  source="$tmp/$source_id.rules"
  output="$tmp/$source_id-output"
  report="$tmp/$source_id-report.json"
  quarantine="$tmp/$source_id-quarantine.json"
  mkdir -p "$output"
  python3 - "$payload" "$format" "$source" <<'PY'
import sys
import tarfile
from pathlib import Path

payload = Path(sys.argv[1])
payload_format = sys.argv[2]
destination = Path(sys.argv[3])
match payload_format:
    case value if value.startswith("tar+gzip/"):
        with tarfile.open(payload, mode="r:gz") as archive:
            members = sorted((member for member in archive.getmembers() if member.isfile() and member.name.endswith(".rules")), key=lambda member: member.name)
            contents = []
            for member in members:
                stream = archive.extractfile(member)
                if stream is None:
                    raise RuntimeError(f"unreadable archive member: {member.name}")
                contents.append(stream.read())
        destination.write_bytes(b"\n".join(contents))
    case "text/suricata-rules":
        destination.write_bytes(payload.read_bytes())
    case unsupported:
        raise RuntimeError(f"unsupported traffic format: {unsupported}")
PY
  python3 "$root/scripts/convert-suricata-dpi.py" --source "$source" --manifest "$root/$manifest" \
    --output-dir "$output" --report "$report" --quarantine-report "$quarantine"
  first_hash=$(tree_hash "$output")
  python3 "$root/scripts/convert-suricata-dpi.py" --source "$source" --manifest "$root/$manifest" \
    --output-dir "$output" --report "$report" --quarantine-report "$quarantine" >/dev/null
  second_hash=$(tree_hash "$output")
  [[ $first_hash == "$second_hash" ]] || { printf 'nondeterministic source=%s\n' "$source_id" >&2; exit 1; }
  jq -e --arg source "$source_id" '.source_id == $source and .parsed > 0 and .converted > 0 and (.parsed == (.converted + .unsupported + .deduplicated))' "$report" >/dev/null
  python3 - "$output" "$source_id" <<'PY'
import json
import sys
from pathlib import Path

for path in Path(sys.argv[1]).glob("*.json"):
    rule = json.loads(path.read_text(encoding="utf-8"))
    if rule["source"]["source_id"] != sys.argv[2] or rule["provenance"][0]["source_id"] != sys.argv[2]:
        raise RuntimeError(f"lost source attribution: {path}")
PY
  jq -c --arg hash "$first_hash" '{source_id,candidates,parsed,converted,unsupported,rejected,deduplicated,deterministic_sha256:$hash}' "$report" >>"$tmp/summaries.jsonl"
  input_args+=(--input-dir "$output")
  printf 'source=%s parsed=%s converted=%s unsupported=%s rejected=%s hash=%s\n' "$source_id" "$(jq -r .parsed "$report")" "$(jq -r .converted "$report")" "$(jq -r .unsupported "$report")" "$(jq -r .rejected "$report")" "$first_hash"
done < <(jq -r '.sources[] | [.source_id,.payload.cache_path,.format,.manifest_path] | @tsv' "$lock")

python3 "$root/scripts/deduplicate-rule-ir.py" --output-dir "$tmp/deduplicated" --report "$tmp/dedup-report.json" "${input_args[@]}"
jq -e '.input_rules > 0 and .output_rules > 0' "$tmp/dedup-report.json" >/dev/null
python3 - "$tmp/deduplicated" "$evidence/signature-provenance.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

records = []
for path in sorted(Path(sys.argv[1]).glob("*.json")):
    content = path.read_bytes()
    rule = json.loads(content)
    source_ids = sorted({entry.get("source_id") for entry in rule.get("provenance", []) if entry.get("source_id")})
    if not source_ids:
        raise RuntimeError(f"missing source lineage: {path}")
    records.append({"rule_id": rule["id"], "source_ids": source_ids, "content_sha256": hashlib.sha256(content).hexdigest()})
Path(sys.argv[2]).write_text(json.dumps({"schema_version": "lyflow.signature-provenance/v1", "signature_count": len(records), "signatures": records}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
jq -s '{status:"PASS",sources:.,totals:{parsed:(map(.parsed)|add),converted:(map(.converted)|add),unsupported:(map(.unsupported)|add),rejected:(map(.rejected)|add),deduplicated_within_source:(map(.deduplicated)|add)}}' \
  "$tmp/summaries.jsonl" >"$evidence/source-counts.json"
jq '{input_rules,output_rules,merged_group_count:(.merged_groups|length),conflict_count:(.conflicts|length)}' "$tmp/dedup-report.json" >"$evidence/deduplication.json"

malformed="$tmp/malformed.rules"
printf 'alert tcp malformed\n' >"$malformed"
if python3 "$root/scripts/convert-suricata-dpi.py" --source "$malformed" --manifest "$root/rules/subscriptions/trafficid/manifest.json" --output-dir "$tmp/malformed-output" --report "$tmp/malformed-report.json" --quarantine-report "$tmp/malformed-quarantine.json" >"$evidence/malformed-input.log" 2>&1; then
  printf 'malformed-only input unexpectedly succeeded\n' >&2
  exit 1
fi

printf 'TRAFFIC_PARSERS_RESULT=PASS sources=5 deterministic=true attributed=true\n'
