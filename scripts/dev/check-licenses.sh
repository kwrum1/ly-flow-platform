#!/usr/bin/env bash
# License boundary checks for the public LyFlow tree.
# Full SPDX scanning is delegated to go-licenses / license-checker when present.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

fail() { echo "ERROR: $*" >&2; exit 1; }

[[ -f docs/legal/THIRD_PARTY_NOTICES.md ]] || fail "missing third-party notices"
[[ -f docs/legal/GPL-SOURCE-OFFER.md ]] || fail "missing GPL source offer"

# 1. Forbidden dependencies in Go modules.
FORBIDDEN_GO='(Elkeid-HUB|Velocidex/velociraptor|grafana/grafana|minio/minio)'
if grep -RInE "$FORBIDDEN_GO" --include='go.mod' --include='go.sum' . >/tmp/lyflow-forbidden-go.txt 2>/dev/null; then
  cat /tmp/lyflow-forbidden-go.txt >&2
  fail "forbidden Go dependency detected"
fi

# 2. Forbidden dependencies in frontend manifests.
FORBIDDEN_NODE='(velociraptor|grafana|minio)'
if grep -nE "$FORBIDDEN_NODE" frontend/package.json frontend/package-lock.json >/tmp/lyflow-forbidden-node.txt 2>/dev/null; then
  cat /tmp/lyflow-forbidden-node.txt >&2
  fail "forbidden frontend dependency detected"
fi

# 3. Public compose must not reference private Elkeid components.
for file in docker-compose.yml deploy/compose/lean.yml; do
  [[ -f "$file" ]] || continue
  if grep -Eq 'private/|elkeid-hub|elkeid-console|elkeid_hub' "$file"; then
    fail "$file references a private Elkeid component"
  fi
done

# 3b. Redis changed license after 7.2; public lean must pin the BSD release.
if grep -Eq 'redis:(latest|7-alpine|7\.4|8)' deploy/compose/lean.yml deploy/compose/lean.env.example 2>/dev/null; then
  fail "public compose must pin Redis 7.2 (BSD) or Valkey; post-7.2 Redis licenses are not OSI"
fi

# 4. Optional SPDX scan.
if command -v go-licenses >/dev/null 2>&1; then
  echo "==> go-licenses report (pkg)"
  (cd pkg && go-licenses report ./... > /tmp/lyflow-go-licenses.txt)
  if grep -Ei 'GPL-3\.0|AGPL-3\.0|SSPL|BSL' /tmp/lyflow-go-licenses.txt >/tmp/lyflow-go-forbidden.txt; then
    cat /tmp/lyflow-go-forbidden.txt >&2
    fail "forbidden license in Go dependency report"
  fi
else
  echo "skip: go-licenses not installed"
fi

if command -v npx >/dev/null 2>&1 && [[ -d frontend/node_modules ]]; then
  echo "==> license-checker report (frontend production)"
  (cd frontend && npx --yes license-checker --production --json > /tmp/lyflow-node-licenses.json)
  if grep -Ei 'GPL-3\.0|AGPL-3\.0|SSPL' /tmp/lyflow-node-licenses.json >/tmp/lyflow-node-forbidden.txt; then
    cat /tmp/lyflow-node-forbidden.txt >&2
    fail "forbidden license in frontend dependency report"
  fi
else
  echo "skip: frontend license-checker not available"
fi

echo "ok: license boundary checks passed"
