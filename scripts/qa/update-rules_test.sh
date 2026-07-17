#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

bash -n "$root/scripts/update-rules.sh"
printf 'update-rules shell syntax regression passed\n'
