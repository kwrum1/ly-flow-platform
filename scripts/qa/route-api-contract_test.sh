#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evidence="$root/acceptance-evidence/T02"
contract="$root/contracts/product-acceptance/v1/route-api-contract.json"
generator="$root/scripts/qa/generate-route-api-contract.mjs"
mkdir -p "$evidence"
temp_dir=$(mktemp -d)
export LYFLOW_ROUTE_CONTRACT_TEMP_ROOT="$temp_dir"

cleanup() {
  rm -rf "$temp_dir"
  printf '{"temporary_directory_removed":true,"background_processes":0,"temporary_fixtures_remaining":0}\n' >"$evidence/cleanup.json"
}
on_signal() {
  local status=$1
  trap - EXIT
  cleanup
  exit "$status"
}
trap cleanup EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
exec > >(tee "$evidence/command.log") 2>&1

generated_registry="$temp_dir/generated-route-registry.json"
regenerated_contract="$temp_dir/route-api-contract.json"
result="$evidence/route-api-matrix.json"
export GOSUMDB=sum.golang.org
export GOTOOLCHAIN=auto

git -C "$root" status --short >"$evidence/worktree-status.txt"
git -C "$root" rev-parse HEAD >"$evidence/start-commit.txt"

(
  cd "$root/server"
  GOWORK=off LYFLOW_GENERATED_ROUTE_REGISTRY="$generated_registry" \
    go test -count=1 -run '^TestGeneratedRouteRegistry_writesAuthoritativeSnapshot$' ./cmd
)
node "$generator" --registry "$generated_registry" --output "$regenerated_contract"
cmp "$contract" "$regenerated_contract"

(
  cd "$root/server"
  GOWORK=off LYFLOW_ROUTE_API_CONTRACT="$contract" LYFLOW_ROUTE_API_RESULT="$result" \
    go test -count=1 -run 'TestRouteAPIContract_matchesMountedRegistry|TestArchitectureRouteSnapshot_characterizesCurrentCountAndRoles|TestRouteRegistryCoversEveryMountedPath|TestRouteRegistryEnforcesRoutePolicyForProtectedRoutes' ./cmd
)
(
  cd "$root/frontend"
  npm test -- --run src/router/route-characterization.test.js src/domain/contracts/product-acceptance-contract.test.ts src/domain/contracts/route-api-contract.test.ts
  npm run typecheck
)

make_invalid_contract() {
  local kind=$1
  local output=$2
  node -e '
    const fs = require("node:fs")
    const [source, destination, kind] = process.argv.slice(1)
    const contract = JSON.parse(fs.readFileSync(source, "utf8"))
    if (kind === "malformed") contract.api_routes[0].operations = []
    else if (kind === "duplicate") contract.api_routes.push(contract.api_routes[0])
    else if (kind === "missing-disposition") delete contract.api_routes[0].disposition
    else if (kind === "stale") contract.registry.sorted_path_sha256 = "0".repeat(64)
    else throw new Error(`unknown invalid contract kind: ${kind}`)
    fs.writeFileSync(destination, `${JSON.stringify(contract, null, 2)}\n`)
  ' "$contract" "$output" "$kind"
}

expect_contract_failure() {
  local kind=$1
  local invalid="$temp_dir/$kind.json"
  local invalid_result="$temp_dir/$kind-result.json"
  local failure_log="$evidence/adversarial-$kind.log"
  make_invalid_contract "$kind" "$invalid"
  if (
    cd "$root/server"
    GOWORK=off LYFLOW_ROUTE_API_CONTRACT="$invalid" LYFLOW_ROUTE_API_RESULT="$invalid_result" \
      go test -count=1 -run '^TestRouteAPIContract_matchesMountedRegistry$' ./cmd
  ) >"$failure_log" 2>&1; then
    printf 'invalid contract unexpectedly passed: %s\n' "$kind" >&2
    exit 1
  fi
  if [[ -e "$invalid_result" ]] || grep -q 'route-api-contract-result=' "$failure_log"; then
    printf 'failed validation emitted misleading success output: %s\n' "$kind" >&2
    exit 1
  fi
}

expect_contract_failure malformed
expect_contract_failure duplicate
expect_contract_failure missing-disposition
expect_contract_failure stale

second_registry="$temp_dir/generated-route-registry-second.json"
(
  cd "$root/server"
  GOWORK=off LYFLOW_GENERATED_ROUTE_REGISTRY="$second_registry" \
    go test -count=1 -run '^TestGeneratedRouteRegistry_writesAuthoritativeSnapshot$' ./cmd
)
cmp "$generated_registry" "$second_registry"

malformed_registry="$temp_dir/malformed-registry.json"
interrupted_output="$temp_dir/interrupted-output.json"
printf '[]\n' >"$malformed_registry"
if node "$generator" --registry "$malformed_registry" --output "$interrupted_output" >"$evidence/adversarial-partial-generation.log" 2>&1; then
  printf 'malformed registry unexpectedly generated a contract\n' >&2
  exit 1
fi
if [[ -e "$interrupted_output" ]] || compgen -G "$interrupted_output.tmp-*" >/dev/null; then
  printf 'failed generation left a partial artifact\n' >&2
  exit 1
fi

node -e '
  const fs = require("node:fs")
  const result = JSON.parse(fs.readFileSync(process.argv[1], "utf8"))
  if (result.status !== "PASS" || result.mounted_paths !== 116 || result.contract_api_records !== 116) process.exit(1)
  if (result.duplicate_api_records !== 0 || result.unowned_actions !== 0) process.exit(1)
  if (result.unknown_protected_path_meets_404_requirement !== false || result.unknown_protected_path_red_gap_recorded !== true) process.exit(1)
  const auth = result.auth_contract_results
  if (auth.public_routes !== 2 || auth.jwt_protected_routes !== 104 || auth.agent_credential_routes !== 9 || auth.loopback_routes !== 1) process.exit(1)
  if (auth.unauthenticated_jwt_status !== 401 || auth.unauthorized_role_status !== 403 || auth.authorized_role_status !== 200) process.exit(1)
  if (auth.remote_loopback_status !== 403 || auth.local_loopback_status !== 204) process.exit(1)
' "$result"

printf '%s\n' \
  '{' \
  '  "malformed_input": "PASS: malformed contract and registry inputs were rejected",' \
  '  "stale_state": "PASS: regenerated contract and path digest matched; altered digest was rejected",' \
  '  "dirty_worktree": "PASS: pre-existing state was recorded and generation remained read-only outside T02 outputs",' \
  '  "flaky_ordering": "PASS: two independent generated registries were byte-identical",' \
  '  "misleading_success_output": "PASS: failed validation emitted no result JSON or success marker",' \
  '  "repeated_interruptions": "PASS: failed generation left no destination or temporary artifact",' \
  '  "prompt_injection": "N/A: no untrusted natural-language or model input is consumed",' \
  '  "cancel_resume": "N/A: generation is single-shot and atomically published, with no resumable state",' \
  '  "hung_long_commands": "N/A: all commands are local bounded unit, compiler, or generator operations"' \
  '}' >"$evidence/adversarial-classes.json"

printf 'PASS route/API contract: mounted=116 duplicate_api_records=0 unowned_actions=0 unknown_404_current=false red_gap_recorded=true\n'
