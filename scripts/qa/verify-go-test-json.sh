#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  printf 'usage: %s <category> <manifest> <go-test-json>\n' "$0" >&2
  exit 2
fi

category=$1
manifest=$2
events=$3

jq -e -s '.' "$events" >/dev/null

if jq -e 'select(.Action == "fail")' "$events" >/dev/null; then
  printf 'go test JSON contains a failing event\n' >&2
  exit 1
fi

found=0
while IFS='|' read -r expected_category package test_name; do
  [[ -z "$expected_category" || "$expected_category" == \#* ]] && continue
  [[ "$expected_category" != "$category" ]] && continue
  found=1
  if ! jq -e -s --arg package "$package" --arg test "$test_name" \
    'any(.[]; .Action == "pass" and (.Package == $package or (.Package | endswith("/" + $package))) and .Test == $test)' "$events" >/dev/null; then
    printf 'missing passing test event: %s %s\n' "$package" "$test_name" >&2
    exit 1
  fi
done <"$manifest"

if [[ $found -ne 1 ]]; then
  printf 'no expected tests declared for category: %s\n' "$category" >&2
  exit 1
fi
