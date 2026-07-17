#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
output=$(bash "$root/scripts/qa/run-control-health-schema-conformance.sh")
[[ $output == 'control-health schema conformance: agent security-engine python java PASS' ]]
