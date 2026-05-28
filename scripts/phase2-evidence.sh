#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_DIR="${EVIDENCE_DIR:-$ROOT_DIR/.sisyphus/evidence}"
TMP_DIR=""

usage() {
  cat <<'EOF'
Usage: phase2-evidence.sh <evidence-name> -- <command> [args...]

Runs a command, captures stdout/stderr and exit code, and writes evidence to:
  .sisyphus/evidence/phase-2-<evidence-name>.txt

Environment:
  EXPECT_EXIT=<code>  Expected exit code, default 0.
EOF
}

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

if [[ $# -lt 3 || "$2" != "--" ]]; then
  usage >&2
  exit 2
fi

name="$1"
shift 2
expect="${EXPECT_EXIT:-0}"
mkdir -p "$EVIDENCE_DIR"
TMP_DIR="$(mktemp -d)"
out="$EVIDENCE_DIR/phase-2-$name.txt"

set +e
"$@" > "$TMP_DIR/stdout" 2> "$TMP_DIR/stderr"
status=$?
set -e

{
  printf '# phase-2 evidence: %s\n\n' "$name"
  printf '## command\n'
  printf '%q ' "$@"
  printf '\n\n## exit_code\n%s\n\n' "$status"
  printf '## expected_exit_code\n%s\n\n' "$expect"
  printf '## stdout\n'
  cat "$TMP_DIR/stdout"
  printf '\n## stderr\n'
  cat "$TMP_DIR/stderr"
} > "$out"

if [[ "$status" != "$expect" ]]; then
  printf 'phase2 evidence command failed: got exit %s expected %s; see %s\n' "$status" "$expect" "$out" >&2
  exit 1
fi

printf '%s\n' "$out"
