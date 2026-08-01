#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export CI="${CI:-true}"
export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"
export GIT_TERMINAL_PROMPT="0"
export GCM_INTERACTIVE="never"
export GIT_EDITOR=:
export EDITOR=:
export VISUAL=""
export GIT_SEQUENCE_EDITOR=:
export GIT_MERGE_AUTOEDIT=no
export GIT_PAGER=cat
export PAGER=cat
export npm_config_yes=true
export PIP_NO_INPUT=1

# The execution environment may have a persistent `go env -w GOFLAGS=-mod=mod`.
# That conflicts with this repository's go.work. Keep verification self-contained
# without mutating global Go configuration.
export GOFLAGS="-mod=readonly"

run() {
  printf '\n==> %s\n' "$*"
  "$@"
}

run_frontend() {
  cd "$ROOT_DIR/frontend"
  run npm run lint
  run npm run typecheck
  run npm run test
  run npm run build
}

run_go_module() {
  local module_path="$1"
  local packages
  cd "$ROOT_DIR/$module_path"
  if [[ ! -f go.mod ]]; then
    printf '\n==> go test skipped for %s: no go.mod\n' "$module_path"
    return 0
  fi
  packages=$(env GOWORK=off GOFLAGS="$GOFLAGS" go list ./...)
  if [[ -z $packages ]]; then
    printf '\n==> go test skipped for %s: no Go packages\n' "$module_path"
    return 0
  fi
  run env GOWORK=off GOFLAGS="$GOFLAGS" go test ./...
}

run_rasp_python() {
  cd "$ROOT_DIR/agent/rasp/python"
  if python -m pytest --version >/dev/null 2>&1; then
    run python -m pytest
  else
    printf '\n==> python -m pytest skipped: pytest is not installed in this environment\n'
  fi
}

main() {
  run_frontend
  run_go_module agent
  run_go_module pkg
  run_go_module security-engine
  run_go_module server
  run_go_module dpi-engine
  run_go_module probe
  run_rasp_python
}

main "$@"
