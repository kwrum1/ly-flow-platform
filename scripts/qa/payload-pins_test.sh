#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
lock="$root/rules/traffic-corpus.lock.json"
evidence="$root/acceptance-evidence/T07"
mkdir -p "$evidence"
exec > >(tee "$evidence/command.log") 2>&1

export GOSUMDB=sum.golang.org
export GOTOOLCHAIN=auto

git -C "$root" status --short >"$evidence/worktree-status.txt"
git -C "$root" rev-parse HEAD >"$evidence/start-commit.txt"

(
  cd "$root/server"
  go test -race -shuffle=on -count=1 ./rulelifecycle
)

jq -e '
  .hash_authority.input == "raw_payload_bytes" and
  .hash_authority.stage == "before_decompression_or_parsing" and
  (.sources | length == 5) and
  all(.sources[];
    .revision_or_payload_pin == ("payload-sha256:" + .payload.raw_sha256) and
    .payload.hash_stage == "raw_before_decompression_or_parsing")
' "$lock" >/dev/null

while IFS=$'\t' read -r source_id cache_path expected; do
  actual=$(sha256sum "$cache_path")
  actual=${actual%% *}
  if [[ $actual != "$expected" ]]; then
    printf 'raw payload mismatch source=%s expected=%s actual=%s\n' "$source_id" "$expected" "$actual" >&2
    exit 1
  fi
  printf 'raw_payload_verified=%s sha256=%s\n' "$source_id" "$actual"
done < <(jq -r '.sources[] | [.source_id,.payload.cache_path,.payload.raw_sha256] | @tsv' "$lock")

jq '{status:"PASS",hash_authority:.hash_authority,sources:[.sources[]|{source_id,revision_or_payload_pin,raw_sha256:.payload.raw_sha256,byte_count:.payload.byte_count,cache_path:.payload.cache_path}]}' \
  "$lock" >"$evidence/raw-hashes.json"

printf 'PAYLOAD_PINS_RESULT=PASS sources=5 hash_stage=raw_before_decompression_or_parsing\n'
