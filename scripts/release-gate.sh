#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-full}"

export CI="${CI:-true}"
export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"
export GIT_TERMINAL_PROMPT=0
export GCM_INTERACTIVE=never
export GIT_EDITOR=:
export EDITOR=:
export VISUAL=""
export GIT_SEQUENCE_EDITOR=:
export GIT_MERGE_AUTOEDIT=no
export GIT_PAGER=cat
export PAGER=cat
export npm_config_yes=true
export PIP_NO_INPUT=1
export GOFLAGS="${GOFLAGS:--mod=readonly}"

sections=()

run_section() {
  local name="$1"
  shift
  printf '\n==> [%s] %s\n' "$name" "$*"
  sections+=("$name")
  "$@"
}

check_file() {
  local path="$1"
  if [[ ! -e "$ROOT_DIR/$path" ]]; then
    printf 'release_gate_missing=%s\n' "$path" >&2
    return 1
  fi
  printf 'release_gate_ok=%s\n' "$path"
}

compose_validation() {
  cd "$ROOT_DIR"
  docker compose config --services >/tmp/lyflow-release-compose-services.txt
  if grep -qx 'ly-agent' /tmp/lyflow-release-compose-services.txt; then
    printf 'release_gate_error=ly-agent must remain profile-gated in default compose\n' >&2
    return 1
  fi
}

frontend_gate() {
  cd "$ROOT_DIR/frontend"
  npm run test -- --run src/domain/topology.test.js src/domain/timeline.test.js src/domain/incidents.test.js src/domain/attack-queue/normalize.test.js src/layout/nav-config.test.js src/router/auth.guard.test.js
  npm run build
}

fixture_gate() {
  cd "$ROOT_DIR"
  python3 fixtures/architecture/load_fixtures.py --out /tmp/lyflow-release-fixtures >/tmp/lyflow-release-fixtures.txt
  grep -R 'lyfixture-chain-001' /tmp/lyflow-release-fixtures >/tmp/lyflow-release-chain.txt
}

evidence_gate() {
  check_file README.md
  check_file ARCHITECTURE.md
  check_file docs/API.md
  check_file docs/WHITEPAPER.md
  check_file fixtures/architecture/README.md
  check_file rules/xdr/lyflow_baseline_rules.yaml
  check_file scripts/validate-stream-bus.sh
  check_file agent/scripts/install.sh
  check_file agent/scripts/uninstall.sh
}

quick_gate() {
  run_section compose compose_validation
  run_section fixtures fixture_gate
  run_section evidence evidence_gate
  run_section frontend frontend_gate
}

full_gate() {
  quick_gate
  run_section platform "$ROOT_DIR/scripts/verify-platform.sh"
}

case "$MODE" in
  quick) quick_gate ;;
  full) full_gate ;;
  *) printf 'usage: %s [quick|full]\n' "$0" >&2; exit 2 ;;
esac

printf '\nrelease_gate=pass sections=%s\n' "${sections[*]}"
