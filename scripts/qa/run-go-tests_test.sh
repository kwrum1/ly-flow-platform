#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

manifest="$tmp/expected.txt"
printf 'auth|example/package|TestExpected\n' >"$manifest"
printf '%s\n' '{"Action":"pass","Package":"example/package","Test":"TestExpected"}' >"$tmp/pass.json"
printf '%s\n' '{"Action":"pass","Package":"example/package","Test":"TestOther"}' >"$tmp/missing.json"
printf '%s\n' 'ok example/package' >"$tmp/malformed.json"

"$root/scripts/qa/verify-go-test-json.sh" auth "$manifest" "$tmp/pass.json"
if "$root/scripts/qa/verify-go-test-json.sh" auth "$manifest" "$tmp/missing.json" >/dev/null 2>&1; then
  printf 'missing expected test was accepted\n' >&2
  exit 1
fi
if "$root/scripts/qa/verify-go-test-json.sh" auth "$manifest" "$tmp/malformed.json" >/dev/null 2>&1; then
  printf 'malformed go test output was accepted\n' >&2
  exit 1
fi

printf 'JSON-aware Go test harness self-test passed\n'
