#!/usr/bin/env bash
# Generate a lightweight SBOM/dependency inventory for the current tree.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-$ROOT/artifacts/sbom}"
mkdir -p "$OUT"

export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
export GOSUMDB="${GOSUMDB:-sum.golang.org}"

for module in pkg server agent security-engine; do
  (cd "$ROOT/$module" && go list -m -json all >"$OUT/go-$module.json")
done

if command -v npm >/dev/null 2>&1 && [ -d "$ROOT/frontend/node_modules" ]; then
  (cd "$ROOT/frontend" && npm ls --omit=dev --all --json >"$OUT/frontend-npm.json" 2>/dev/null || true)
  if command -v npx >/dev/null 2>&1; then
    (cd "$ROOT/frontend" && npx --yes license-checker --production --json >"$OUT/frontend-licenses.json" 2>/dev/null || true)
  fi
fi

if command -v docker >/dev/null 2>&1; then
  docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Size}}' |
    grep '^ly-flow/' >"$OUT/docker-images.txt" || true
fi

{
  echo "generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_revision=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "go_version=$(go version 2>/dev/null || echo unknown)"
  echo "node_version=$(node --version 2>/dev/null || echo unknown)"
} >"$OUT/metadata.txt"

echo "SBOM written to $OUT"
ls -lh "$OUT"
