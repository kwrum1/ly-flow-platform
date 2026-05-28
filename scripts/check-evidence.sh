#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  printf 'usage: %s <evidence-file> [<evidence-file> ...]\n' "$0" >&2
  exit 2
fi

missing=0
for evidence_path in "$@"; do
  if [[ ! -s "$evidence_path" ]]; then
    printf 'missing_or_empty=%s\n' "$evidence_path" >&2
    missing=1
    continue
  fi
  printf 'ok=%s\n' "$evidence_path"
done

exit "$missing"
