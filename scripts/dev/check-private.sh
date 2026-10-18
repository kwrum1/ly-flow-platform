#!/usr/bin/env bash
# Enforce the private-module boundary for public builds.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

fail() { echo "ERROR: $*" >&2; exit 1; }

if git ls-files private | grep -q .; then
  fail "private/ is tracked by git; keep Elkeid private modules outside the public tree"
fi

grep -qx 'private/' .gitignore || fail ".gitignore must contain 'private/'"
grep -qx 'private/' .dockerignore || fail ".dockerignore must contain 'private/'"

for file in docker-compose.yml deploy/compose/lean.yml; do
  [[ -f "$file" ]] || continue
  if grep -Eq 'private/|elkeid-hub|elkeid-console|elkeid_hub' "$file"; then
    fail "$file references a private Elkeid component"
  fi
done

echo "ok: private module boundary intact"
