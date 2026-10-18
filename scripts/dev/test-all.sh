#!/usr/bin/env bash
# LyFlow developer test entrypoint.
# Usage: scripts/dev/test-all.sh [fast|full]
#   fast: unit tests that do not require external services (CI default)
#   full: every Go module + frontend; still requires services for integration tests
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-fast}"

export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
export GOSUMDB="${GOSUMDB:-sum.golang.org}"

section() { printf '\n==> %s\n' "$*"; }

run_go() {
  local dir="$1"
  shift
  section "go test $dir $*"
  (cd "$ROOT_DIR/$dir" && go test "$@")
}

case "$MODE" in
  fast)
    run_go pkg ./...
    run_go server ./analytics ./cmd ./ingestv2 -run 'TestV2|TestLoadFeatureFlags|TestRouteAPIContract|TestStageForTactic|TestFromCanonicalV1|TestEventV2|TestHandler|TestClickHouseEventV2RowFrom'
    ;;
  full)
    for module in pkg server agent security-engine dpi-engine; do
      run_go "$module" ./...
    done
    ;;
  *)
    echo "usage: $0 [fast|full]" >&2
    exit 2
    ;;
esac

section "frontend"
if [[ ! -d "$ROOT_DIR/frontend/node_modules" ]]; then
  (cd "$ROOT_DIR/frontend" && npm ci --no-audit --no-fund)
fi
(cd "$ROOT_DIR/frontend" && npm run typecheck)
(cd "$ROOT_DIR/frontend" && npm test -- --run)
(cd "$ROOT_DIR/frontend" && npm run lint)

section "compose config (optional)"
if [[ "${LYFLOW_COMPOSE_CHECK:-0}" != "1" ]]; then
  echo "skip: set LYFLOW_COMPOSE_CHECK=1 and required env vars to validate compose files"
else
  for file in deploy/compose/lean.yml deploy/compose/full-private.yml docker-compose.yml; do
    if [[ -f "$ROOT_DIR/$file" ]]; then
      (cd "$ROOT_DIR" && docker compose -f "$file" config >/dev/null)
      echo "ok: $file"
    else
      echo "skip: $file (not present)"
    fi
  done
fi

section "policy checks"
bash "$ROOT_DIR/scripts/dev/check-secrets.sh"
bash "$ROOT_DIR/scripts/dev/check-private.sh"
bash "$ROOT_DIR/scripts/dev/check-licenses.sh"

section "all fast checks passed"
