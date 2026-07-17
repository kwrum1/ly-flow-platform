#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
profile="$root/agent/cmd/testdata/capture-quality/inert-synthetic-profile.json"
output=$(mktemp)
trap 'rm -f "$output"' EXIT INT TERM

jq -e '
  .schema_version == "lyflow.capture-benchmark.v1" and
  .inert == true and
  (.packets | type == "number" and . > 0) and
  (.max_packets_per_cpu | type == "number" and . > 0) and
  .source_ip == "192.0.2.10" and
  .destination_ip == "198.51.100.20" and
  (.description | contains("offline") and contains("not measured"))
' "$profile" >/dev/null

(
  cd "$root/agent"
  timeout 120s env GOWORK=off go test -count=1 -run '^TestLinuxSyntheticPCAPProfileReportsBoundedLossAndCPU$' -v ./cmd
) | tee "$output"

grep -Eq 'parser_packet_loss_percent=[0-9]+\.[0-9]{4}' "$output"
grep -Eq 'kernel_packet_loss=not_measured' "$output"
grep -Eq 'cpu_percent=[0-9]+\.[0-9]{2} local_cpus=[1-9][0-9]* visibility_claim=offline_parser_only' "$output"
printf 'capture-quality synthetic profile verified\n'
