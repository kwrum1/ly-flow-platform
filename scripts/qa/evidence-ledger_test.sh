#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
checker="$root/scripts/check-evidence.sh"
schema="$root/scripts/qa/evidence-ledger-schema.json"
evidence_output=${EVIDENCE_LEDGER_FIXTURE_OUT:-}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
evidence_root="$tmp/evidence"
mkdir -p "$evidence_root"

fail() {
  printf '[evidence-ledger-test] ERROR: %s\n' "$*" >&2
  exit 1
}

digest_file() {
  local digest
  digest=$(sha256sum "$1")
  printf '%s' "${digest%% *}"
}

artifact_json() {
  local evidence_id=$1 kind=$2 path=$3 digest
  digest=$(digest_file "$evidence_root/$path")
  jq -cn --arg evidence_id "$evidence_id" --arg kind "$kind" --arg path "$path" --arg sha256 "$digest" \
    '{evidence_id:$evidence_id,kind:$kind,path:$path,sha256:$sha256}'
}

expect_rejected() {
  local name=$1 ledger=$2 expected=$3 status
  set +e
  bash "$checker" "$ledger" >"$tmp/$name.stdout" 2>"$tmp/$name.stderr"
  status=$?
  set -e
  [[ $status -ne 0 ]] || fail "$name ledger was accepted"
  grep -Fq "$expected" "$tmp/$name.stderr" || fail "$name rejection did not identify $expected"
  printf 'rejected=%s identified=%s\n' "$name" "$expected"
}

set +e
bash "$checker" >"$tmp/no-args.stdout" 2>"$tmp/no-args.stderr"
status=$?
set -e
[[ $status -eq 2 ]] || fail "no-argument status changed: $status"
grep -Fq 'usage:' "$tmp/no-args.stderr" || fail 'no-argument usage message missing'

printf 'T01 PASS prose-only legacy evidence\n' >"$tmp/nonempty.txt"
bash "$checker" "$tmp/nonempty.txt" >"$tmp/nonempty.stdout"
grep -Fxq "legacy_evidence_present=$tmp/nonempty.txt" "$tmp/nonempty.stdout" || fail 'legacy evidence boundary changed'
if grep -Eq '(^|[[:space:]])ok=' "$tmp/nonempty.stdout"; then
  fail 'legacy evidence was reported as a ledger pass'
fi

: >"$tmp/empty.txt"
set +e
bash "$checker" "$tmp/empty.txt" "$tmp/missing.txt" >"$tmp/missing.stdout" 2>"$tmp/missing.stderr"
status=$?
set -e
[[ $status -eq 1 ]] || fail "missing/empty status changed: $status"
grep -Fxq "missing_or_empty=$tmp/empty.txt" "$tmp/missing.stderr" || fail 'empty evidence was not identified'
grep -Fxq "missing_or_empty=$tmp/missing.txt" "$tmp/missing.stderr" || fail 'missing evidence was not identified'

mkdir -p "$evidence_root/starting-state"
printf '?? fixture-untracked\n' >"$evidence_root/starting-state/porcelain.txt"
porcelain=$(artifact_json 'T01:starting:porcelain' worktree_porcelain 'starting-state/porcelain.txt')
commit=652a7b620dfd1f8f93ae022c16f8d644b3908824
jq -n -S --arg commit "$commit" --arg porcelain_sha256 "$(jq -r '.sha256' <<<"$porcelain")" \
  '{schema:"lyflow-starting-state-receipt/v1",commit:$commit,dirty:true,porcelain_sha256:$porcelain_sha256}' \
  >"$evidence_root/starting-state/receipt.json"
starting_receipt=$(artifact_json 'T01:starting:receipt' starting_state_receipt 'starting-state/receipt.json')
jq -n -S --arg schema_id "$(jq -r '.schema_id' "$schema")" --argjson schema_version "$(jq '.schema_version' "$schema")" \
  --arg commit "$commit" --argjson porcelain "$porcelain" --argjson receipt "$starting_receipt" \
  '{schema_id:$schema_id,schema_version:$schema_version,purpose:"schema_conformance_fixture",starting_state:{commit:$commit,dirty:true,porcelain:$porcelain,receipt:$receipt},entries:[]}' \
  >"$evidence_root/valid-ledger.json"

while IFS= read -r task; do
  task_id=$(jq -r '.id' <<<"$task")
  task_evidence_id=$(jq -r '.evidence_id' <<<"$task")
  task_dir="$evidence_root/$task_id"
  mkdir -p "$task_dir/artifacts" "$task_dir/adversarial"

  setup_identity="schema fixture setup $task_id"
  jq -n -S --arg task_id "$task_id" --arg identity "$setup_identity" '{schema:"lyflow-setup-receipt/v1",task_id:$task_id,identity:$identity}' >"$task_dir/setup.json"
  setup_receipt=$(artifact_json "$task_id:setup" setup_receipt "$task_id/setup.json")

  red_command="schema-red-check $task_id"
  printf 'expected pre-fix failure for %s\n' "$task_id" >"$task_dir/red-output.log"
  red_output=$(artifact_json "$task_id:red:output" command_output "$task_id/red-output.log")
  jq -n -S --arg command "$red_command" --argjson output "$red_output" '{schema:"lyflow-command-receipt/v1",command:$command,exit_code:1,output:$output}' >"$task_dir/red-receipt.json"
  red_receipt=$(artifact_json "$task_id:red:receipt" command_receipt "$task_id/red-receipt.json")

  result_command="schema-green-check $task_id"
  printf 'schema acceptance passed for %s\n' "$task_id" >"$task_dir/result-output.log"
  result_output=$(artifact_json "$task_id:result:output" command_output "$task_id/result-output.log")
  jq -n -S --arg command "$result_command" --argjson output "$result_output" '{schema:"lyflow-command-receipt/v1",command:$command,exit_code:0,output:$output}' >"$task_dir/result-receipt.json"
  result_receipt=$(artifact_json "$task_id:result:receipt" command_receipt "$task_id/result-receipt.json")

  jq -n -S --arg task_id "$task_id" '{schema:"lyflow-cleanup-receipt/v1",task_id:$task_id,status:"PASS",removed:[]}' >"$task_dir/cleanup.json"
  cleanup_receipt=$(artifact_json "$task_id:cleanup" cleanup_receipt "$task_id/cleanup.json")

  artifacts='[]'
  while IFS= read -r class; do
    if [[ $class == live_service ]]; then
      probe="probe fixture-service-$task_id health"
      printf 'service fixture observable for %s\n' "$task_id" >"$task_dir/artifacts/live_service-output.log"
      live_output=$(artifact_json "$task_id:artifact:live_service:output" command_output "$task_id/artifacts/live_service-output.log")
      jq -n -S --arg command "$probe" --argjson output "$live_output" '{schema:"lyflow-command-receipt/v1",command:$command,exit_code:0,output:$output}' >"$task_dir/artifacts/live_service-receipt.json"
      live_receipt=$(artifact_json "$task_id:artifact:live_service:receipt" command_receipt "$task_id/artifacts/live_service-receipt.json")
      jq -n -S --arg task_id "$task_id" --arg probe "$probe" '{schema:"lyflow-live-service-evidence/v1",task_id:$task_id,service:{name:"fixture-service",instance:$task_id},probe:$probe,observable:"structured health response observed"}' >"$task_dir/artifacts/live_service.json"
      artifact=$(artifact_json "$task_id:artifact:live_service" live_service "$task_id/artifacts/live_service.json")
      artifact=$(jq -c --argjson receipt "$live_receipt" '. + {service:{name:"fixture-service",instance:"'"$task_id"'"},probe:"'"$probe"'",observable:"structured health response observed",receipt:$receipt}' <<<"$artifact")
    else
      jq -n -S --arg task_id "$task_id" --arg kind "$class" '{schema:"lyflow-evidence-artifact/v1",task_id:$task_id,kind:$kind,observable:("typed " + $kind + " evidence observed")}' >"$task_dir/artifacts/$class.json"
      artifact=$(artifact_json "$task_id:artifact:$class" "$class" "$task_id/artifacts/$class.json")
    fi
    artifacts=$(jq -c --argjson artifact "$artifact" '. + [$artifact]' <<<"$artifacts")
  done < <(jq -r '.required_artifact_classes[]' <<<"$task")

  adversarial='[]'
  while IFS= read -r class; do
    if jq -e --arg class "$class" '.mandatory_adversarial_classes | index($class) != null' <<<"$task" >/dev/null; then
      jq -n -S --arg task_id "$task_id" --arg class "$class" '{schema:"lyflow-adversarial-probe/v1",task_id:$task_id,class:$class,result:("rejection probe passed for " + $class)}' >"$task_dir/adversarial/$class.json"
      adversarial_artifact=$(artifact_json "$task_id:adversarial:$class" adversarial_probe "$task_id/adversarial/$class.json")
      item=$(jq -cn --arg class "$class" --argjson artifact "$adversarial_artifact" '{class:$class,disposition:"PROBED",artifact:$artifact}')
    else
      item=$(jq -cn --arg class "$class" --arg task_id "$task_id" '{class:$class,disposition:"N/A",reason:("Class " + $class + " is not triggered by schema fixture task " + $task_id + ".")}')
    fi
    adversarial=$(jq -c --argjson item "$item" '. + [$item]' <<<"$adversarial")
  done < <(jq -r '.adversarial_classes[]' "$schema")

  entry=$(jq -cn --arg id "$task_id" --arg evidence_id "$task_evidence_id" --arg setup_identity "$setup_identity" \
    --arg red_command "$red_command" --arg result_command "$result_command" --argjson setup_receipt "$setup_receipt" \
    --argjson red_receipt "$red_receipt" --argjson result_receipt "$result_receipt" --argjson artifacts "$artifacts" \
    --argjson cleanup_receipt "$cleanup_receipt" --argjson adversarial "$adversarial" \
    '{id:$id,evidence_id:$evidence_id,setup:{identity:$setup_identity,receipt:$setup_receipt},red:{command:$red_command,status:"FAIL",receipt:$red_receipt},result:{command:$result_command,status:"PASS",receipt:$result_receipt},artifacts:$artifacts,cleanup:{status:"PASS",receipt:$cleanup_receipt},adversarial_classes:$adversarial}')
  jq --argjson entry "$entry" '.entries += [$entry]' "$evidence_root/valid-ledger.json" >"$evidence_root/valid-ledger.next.json"
  mv "$evidence_root/valid-ledger.next.json" "$evidence_root/valid-ledger.json"
done < <(jq -c '.tasks[]' "$schema")

valid_ledger="$evidence_root/valid-ledger.json"
bash "$checker" "$valid_ledger" >"$tmp/valid.stdout"
jq -e '[.starting_state.porcelain.path,.starting_state.receipt.path] + [.entries[] | .setup.receipt.path,.red.receipt.path,.result.receipt.path,.artifacts[].path,.cleanup.receipt.path, (.adversarial_classes[] | select(.disposition == "PROBED") | .artifact.path)] as $paths | ($paths | length) > 100 and ($paths | length) == ($paths | unique | length)' "$valid_ledger" >/dev/null \
  || fail 'semantic evidence paths are not distinct'

if [[ -n $evidence_output ]]; then
  mkdir -p "$evidence_output"
  cp "$schema" "$evidence_output/ledger-schema.json"
  cp -R "$evidence_root/." "$evidence_output/"
  if [[ -s $evidence_output/starting-state-initial.txt ]]; then
    line_number=0
    : >"$evidence_output/starting-state/porcelain.txt"
    while IFS= read -r line; do
      line_number=$((line_number + 1))
      if [[ $line_number -eq 1 ]]; then
        initial_commit=$line
      else
        printf '%s\n' "$line" >>"$evidence_output/starting-state/porcelain.txt"
      fi
    done <"$evidence_output/starting-state-initial.txt"
    porcelain_digest=$(digest_file "$evidence_output/starting-state/porcelain.txt")
    jq -n -S --arg commit "$initial_commit" --arg porcelain_sha256 "$porcelain_digest" \
      '{schema:"lyflow-starting-state-receipt/v1",commit:$commit,dirty:true,porcelain_sha256:$porcelain_sha256}' \
      >"$evidence_output/starting-state/receipt.json"
    receipt_digest=$(digest_file "$evidence_output/starting-state/receipt.json")
    jq --arg commit "$initial_commit" --arg porcelain_sha256 "$porcelain_digest" --arg receipt_sha256 "$receipt_digest" \
      '.starting_state = {commit:$commit,dirty:true,porcelain:{evidence_id:"T01:starting:porcelain",kind:"worktree_porcelain",path:"starting-state/porcelain.txt",sha256:$porcelain_sha256},receipt:{evidence_id:"T01:starting:receipt",kind:"starting_state_receipt",path:"starting-state/receipt.json",sha256:$receipt_sha256}}' \
      "$evidence_output/valid-ledger.json" >"$evidence_output/valid-ledger.next.json"
    mv "$evidence_output/valid-ledger.next.json" "$evidence_output/valid-ledger.json"
    bash "$checker" "$evidence_output/valid-ledger.json" >/dev/null
  fi
fi

jq '.starting_state.dirty = false' "$valid_ledger" >"$evidence_root/dirty-state-contradiction.json"
expect_rejected dirty-state-contradiction "$evidence_root/dirty-state-contradiction.json" 'starting_state_mismatch'

jq '.starting_state.worktree_dirty = false' "$valid_ledger" >"$evidence_root/legacy-dirty-state-contradiction.json"
expect_rejected legacy-dirty-state-contradiction "$evidence_root/legacy-dirty-state-contradiction.json" 'invalid_starting_state'

printf 'arbitrary non-porcelain bytes\n' >"$evidence_root/starting-state/arbitrary.txt"
arbitrary_porcelain=$(artifact_json 'T01:starting:arbitrary-porcelain' worktree_porcelain 'starting-state/arbitrary.txt')
jq -n -S --arg commit "$commit" --arg porcelain_sha256 "$(jq -r '.sha256' <<<"$arbitrary_porcelain")" \
  '{schema:"lyflow-starting-state-receipt/v1",commit:$commit,dirty:true,porcelain_sha256:$porcelain_sha256}' >"$evidence_root/starting-state/arbitrary-receipt.json"
arbitrary_starting_receipt=$(artifact_json 'T01:starting:arbitrary-receipt' starting_state_receipt 'starting-state/arbitrary-receipt.json')
jq --argjson porcelain "$arbitrary_porcelain" --argjson receipt "$arbitrary_starting_receipt" '.starting_state.porcelain = $porcelain | .starting_state.receipt = $receipt' "$valid_ledger" >"$evidence_root/arbitrary-starting-state.json"
expect_rejected arbitrary-starting-state "$evidence_root/arbitrary-starting-state.json" 'invalid_worktree_porcelain'

jq '.entries[0].red.command = "true" | .entries[0].result.command = "false"' "$valid_ledger" >"$evidence_root/command-receipt-contradiction.json"
expect_rejected command-receipt-contradiction "$evidence_root/command-receipt-contradiction.json" 'command_receipt_mismatch id=T01'

jq '.exit_code = 0' "$evidence_root/T01/red-receipt.json" >"$evidence_root/T01/red-zero-receipt.json"
red_zero_receipt=$(artifact_json 'T01:red:zero-receipt' command_receipt 'T01/red-zero-receipt.json')
jq --argjson receipt "$red_zero_receipt" '.entries[0].red.receipt = $receipt' "$valid_ledger" >"$evidence_root/red-zero-exit.json"
expect_rejected red-zero-exit "$evidence_root/red-zero-exit.json" 'red_exit_code_zero id=T01'

jq '.exit_code = 1' "$evidence_root/T01/result-receipt.json" >"$evidence_root/T01/result-nonzero-receipt.json"
result_nonzero_receipt=$(artifact_json 'T01:result:nonzero-receipt' command_receipt 'T01/result-nonzero-receipt.json')
jq --argjson receipt "$result_nonzero_receipt" '.entries[0].result.receipt = $receipt' "$valid_ledger" >"$evidence_root/result-nonzero-exit.json"
expect_rejected result-nonzero-exit "$evidence_root/result-nonzero-exit.json" 'result_exit_code_nonzero id=T01'

jq 'del(.output)' "$evidence_root/T01/result-receipt.json" >"$evidence_root/T01/result-no-output-receipt.json"
result_no_output_receipt=$(artifact_json 'T01:result:no-output-receipt' command_receipt 'T01/result-no-output-receipt.json')
jq --argjson receipt "$result_no_output_receipt" '.entries[0].result.receipt = $receipt' "$valid_ledger" >"$evidence_root/result-no-output.json"
expect_rejected result-no-output "$evidence_root/result-no-output.json" 'missing_command_output id=T01 phase=result'

printf 'arbitrary bytes\n' >"$evidence_root/T12/artifacts/arbitrary-live-service.bin"
arbitrary_digest=$(digest_file "$evidence_root/T12/artifacts/arbitrary-live-service.bin")
jq --arg digest "$arbitrary_digest" '(.entries[11].artifacts[] | select(.kind == "live_service")) |= (.path = "T12/artifacts/arbitrary-live-service.bin" | .sha256 = $digest)' "$valid_ledger" >"$evidence_root/arbitrary-live-service.json"
expect_rejected arbitrary-live-service "$evidence_root/arbitrary-live-service.json" 'invalid_live_service id=T12'

jq '(.entries[0].adversarial_classes[] | select(.class == "malformed_input")) = {class:"malformed_input",disposition:"N/A",reason:"Generic N/A is not sufficient."}' "$valid_ledger" >"$evidence_root/mandatory-probe-na.json"
expect_rejected mandatory-probe-na "$evidence_root/mandatory-probe-na.json" 'mandatory_adversarial_not_probed id=T01 class=malformed_input'

jq '.entries[1].evidence_id = .entries[0].evidence_id' "$valid_ledger" >"$evidence_root/duplicate-evidence-id.json"
expect_rejected duplicate-evidence-id "$evidence_root/duplicate-evidence-id.json" 'duplicate_evidence_id id=T01:task'

jq 'del(.entries[-1])' "$valid_ledger" >"$evidence_root/missing-task.json"
expect_rejected missing-task "$evidence_root/missing-task.json" 'missing_task id=T25'

jq 'del(.entries[0].red)' "$valid_ledger" >"$evidence_root/missing-red.json"
expect_rejected missing-red "$evidence_root/missing-red.json" 'missing_red id=T01'

jq 'del(.entries[11].artifacts[] | select(.kind == "live_service"))' "$valid_ledger" >"$evidence_root/missing-live-service.json"
expect_rejected missing-live-service "$evidence_root/missing-live-service.json" 'missing_artifact_class id=T12 class=live_service'

jq '.entries += [.entries[0]]' "$valid_ledger" >"$evidence_root/duplicate-id.json"
expect_rejected duplicate-id "$evidence_root/duplicate-id.json" 'duplicate_id id=T01'

jq 'del(.entries[0].result.receipt)' "$valid_ledger" >"$evidence_root/missing-command-output.json"
expect_rejected missing-command-output "$evidence_root/missing-command-output.json" 'invalid_artifact context=T01:result:receipt'

jq 'del(.entries[0].result.status)' "$valid_ledger" >"$evidence_root/missing-status.json"
expect_rejected missing-status "$evidence_root/missing-status.json" 'invalid_status id=T01'

jq 'del(.entries[0].artifacts[0].sha256)' "$valid_ledger" >"$evidence_root/missing-digest.json"
expect_rejected missing-digest "$evidence_root/missing-digest.json" 'invalid_artifact context=T01:artifact:ledger'

jq 'del(.entries[0].setup.identity)' "$valid_ledger" >"$evidence_root/missing-setup-identity.json"
expect_rejected missing-setup-identity "$evidence_root/missing-setup-identity.json" 'missing_setup_identity id=T01'

jq 'del(.entries[0].cleanup.receipt)' "$valid_ledger" >"$evidence_root/missing-cleanup-receipt.json"
expect_rejected missing-cleanup-receipt "$evidence_root/missing-cleanup-receipt.json" 'missing_cleanup id=T01'

jq 'del(.entries[0].adversarial_classes[-1])' "$valid_ledger" >"$evidence_root/missing-adversarial-class.json"
expect_rejected missing-adversarial-class "$evidence_root/missing-adversarial-class.json" 'missing_adversarial_class id=T01'

jq '.entries[0].result = {status:"PASS",claim:"Everything passed."}' "$valid_ledger" >"$evidence_root/prose-only-pass.json"
expect_rejected prose-only-pass "$evidence_root/prose-only-pass.json" 'prose_only_pass id=T01'

jq '.entries[0].artifacts[0].path = "../outside.log"' "$valid_ledger" >"$evidence_root/path-traversal.json"
expect_rejected path-traversal "$evidence_root/path-traversal.json" 'artifact_path_outside_ledger=../outside.log'

printf '{"schema_id":"lyflow-acceptance-evidence-ledger/v2","entries":[' >"$evidence_root/partial-ledger.json"
expect_rejected partial-ledger "$evidence_root/partial-ledger.json" 'invalid_json'

printf 'tampered bytes\n' >"$evidence_root/T01/artifacts/ledger.json"
expect_rejected stale-artifact "$valid_ledger" 'artifact_digest_mismatch=T01/artifacts/ledger.json'

printf 'evidence ledger validation passed\n'
