#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest=${DETECTION_REPLAY_MANIFEST:-$root/fixtures/detection-replay/v1/manifest.json}
output_dir=${DETECTION_REPLAY_OUTPUT_DIR:-$root/.artifacts/detection-replay}

(cd "$root/server" && GOWORK=off GOPROXY=off go test ./xdr/replay -count=1)
(cd "$root/server" && GOWORK=off GOPROXY=off go run ./cmd/detection-replay -manifest "$manifest" -output-dir "$output_dir" "$@")

printf 'detection replay QA PASS\n'
