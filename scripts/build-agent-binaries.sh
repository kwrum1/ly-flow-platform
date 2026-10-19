#!/usr/bin/env bash
# Build the cross-platform ly-agent binaries served by /api/v1/agent/download.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/agent"

build() {
  local goos="$1" goarch="$2" output="$3"
  echo "building agent $goos/$goarch -> agent/$output"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    GOTOOLCHAIN="${GOTOOLCHAIN:-auto}" GOSUMDB="${GOSUMDB:-sum.golang.org}" \
    go build -trimpath -o "$output" ./cmd
}

build linux amd64 ly-agent
build linux arm64 ly-agent-linux-arm64
build windows amd64 ly-agent-windows-amd64

ls -lh ly-agent ly-agent-linux-arm64 ly-agent-windows-amd64
