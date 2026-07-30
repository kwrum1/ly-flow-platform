#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  printf 'usage: %s <evidence-file> [<evidence-file> ...]\n' "$0" >&2
  exit 2
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
schema="$root/scripts/qa/evidence-ledger-schema.json"
declare -A seen_evidence_ids=()
declare -A seen_artifact_paths=()
verified_artifacts=0
verified_artifact_evidence_id=''
verified_artifact_kind=''
verified_artifact_path=''

ledger_error() {
  printf 'ledger_error=%s %s\n' "$1" "$2" >&2
  exit 1
}

artifact_field() {
  jq -r --arg field "$2" '.[$field] // empty' <<<"$1"
}

validate_artifact_shape() {
  jq -e 'type == "object" and
    (.evidence_id | type == "string" and test("^T[0-9]{2}:[A-Za-z0-9._:-]+$")) and
    (.kind | type == "string" and length > 0) and
    (.path | type == "string" and test("^[A-Za-z0-9._/-]+$")) and
    (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))' <<<"$1" >/dev/null
}

verify_artifact() {
  local ledger=$1 ledger_dir=$2 record=$3 context=$4
  local evidence_id kind path expected_digest actual_digest
  validate_artifact_shape "$record" || ledger_error "$ledger" "invalid_artifact context=$context"
  evidence_id=$(artifact_field "$record" evidence_id)
  kind=$(artifact_field "$record" kind)
  path=$(artifact_field "$record" path)
  expected_digest=$(artifact_field "$record" sha256)
  [[ -z ${seen_evidence_ids[$evidence_id]+x} ]] || ledger_error "$ledger" "duplicate_evidence_id id=$evidence_id"
  [[ -z ${seen_artifact_paths[$path]+x} ]] || ledger_error "$ledger" "duplicate_artifact_path path=$path"
  seen_evidence_ids[$evidence_id]=1
  seen_artifact_paths[$path]=1
  case "$path" in
    /*|..|../*|*/../*) ledger_error "$ledger" "artifact_path_outside_ledger=$path" ;;
  esac
  [[ ! -L "$ledger_dir/$path" ]] || ledger_error "$ledger" "artifact_symlink=$path"
  [[ -f "$ledger_dir/$path" ]] || ledger_error "$ledger" "artifact_missing=$path"
  actual_digest=$(sha256sum "$ledger_dir/$path")
  actual_digest=${actual_digest%% *}
  [[ $actual_digest == "$expected_digest" ]] || ledger_error "$ledger" "artifact_digest_mismatch=$path"
  verified_artifacts=$((verified_artifacts + 1))
  verified_artifact_evidence_id=$evidence_id
  verified_artifact_kind=$kind
  verified_artifact_path=$path
}

validate_command_receipt() {
  local ledger=$1 ledger_dir=$2 task_id=$3 phase=$4 command=$5 expected=$6 record=$7
  local path receipt output_record exit_code receipt_command
  verify_artifact "$ledger" "$ledger_dir" "$record" "$task_id:$phase:receipt"
  [[ $verified_artifact_kind == command_receipt ]] || ledger_error "$ledger" "invalid_command_receipt id=$task_id phase=$phase"
  path=$verified_artifact_path
  receipt=$(jq -c . "$ledger_dir/$path" 2>/dev/null) || ledger_error "$ledger" "invalid_command_receipt id=$task_id phase=$phase"
  jq -e '.schema == "lyflow-command-receipt/v1" and (.command | type == "string") and (.exit_code | type == "number" and floor == .)' <<<"$receipt" >/dev/null \
    || ledger_error "$ledger" "invalid_command_receipt id=$task_id phase=$phase"
  jq -e '.output | type == "object"' <<<"$receipt" >/dev/null || ledger_error "$ledger" "missing_command_output id=$task_id phase=$phase"
  receipt_command=$(jq -r '.command' <<<"$receipt")
  exit_code=$(jq -r '.exit_code' <<<"$receipt")
  [[ $receipt_command == "$command" ]] || ledger_error "$ledger" "command_receipt_mismatch id=$task_id phase=$phase"
  if [[ $expected == nonzero ]]; then
    [[ $exit_code -ne 0 ]] || ledger_error "$ledger" "red_exit_code_zero id=$task_id"
  else
    [[ $exit_code -eq 0 ]] || ledger_error "$ledger" "result_exit_code_nonzero id=$task_id"
  fi
  output_record=$(jq -c '.output' <<<"$receipt")
  verify_artifact "$ledger" "$ledger_dir" "$output_record" "$task_id:$phase:output"
  [[ $verified_artifact_kind == command_output ]] || ledger_error "$ledger" "missing_command_output id=$task_id phase=$phase"
}

validate_starting_state() {
  local ledger=$1 ledger_dir=$2 state receipt_record porcelain_record receipt_path receipt porcelain_path
  state=$(jq -c '.starting_state' "$ledger")
  jq -e '(has("worktree_dirty") | not) and (.commit | type == "string" and test("^[0-9a-f]{40}$")) and (.dirty | type == "boolean") and (.porcelain | type == "object") and (.receipt | type == "object")' <<<"$state" >/dev/null \
    || ledger_error "$ledger" 'invalid_starting_state'
  porcelain_record=$(jq -c '.porcelain' <<<"$state")
  verify_artifact "$ledger" "$ledger_dir" "$porcelain_record" 'starting-state:porcelain'
  [[ $verified_artifact_kind == worktree_porcelain ]] || ledger_error "$ledger" 'invalid_starting_state'
  porcelain_path=$verified_artifact_path
  receipt_record=$(jq -c '.receipt' <<<"$state")
  verify_artifact "$ledger" "$ledger_dir" "$receipt_record" 'starting-state:receipt'
  [[ $verified_artifact_kind == starting_state_receipt ]] || ledger_error "$ledger" 'invalid_starting_state'
  receipt_path=$verified_artifact_path
  receipt=$(jq -c . "$ledger_dir/$receipt_path" 2>/dev/null) || ledger_error "$ledger" 'invalid_starting_state_receipt'
  jq -e --arg commit "$(jq -r '.commit' <<<"$state")" --argjson dirty "$(jq '.dirty' <<<"$state")" --arg digest "$(artifact_field "$porcelain_record" sha256)" \
    '.schema == "lyflow-starting-state-receipt/v1" and .commit == $commit and .dirty == $dirty and .porcelain_sha256 == $digest' <<<"$receipt" >/dev/null \
    || ledger_error "$ledger" 'starting_state_mismatch'
  if [[ -s "$ledger_dir/$porcelain_path" ]]; then
    jq -Rse 'split("\n") | if .[-1] == "" then .[:-1] else . end | length > 0 and all(.[]; test("^(\\?\\?|!!|[ MADRCU][ MADRCU]) .+$"))' "$ledger_dir/$porcelain_path" >/dev/null \
      || ledger_error "$ledger" 'invalid_worktree_porcelain'
    jq -e '.dirty == true' <<<"$state" >/dev/null || ledger_error "$ledger" 'starting_state_mismatch'
  else
    jq -e '.dirty == false' <<<"$state" >/dev/null || ledger_error "$ledger" 'starting_state_mismatch'
  fi
}

validate_typed_artifact() {
  local ledger=$1 ledger_dir=$2 task_id=$3 class=$4 record=$5 path receipt_record
  verify_artifact "$ledger" "$ledger_dir" "$record" "$task_id:artifact:$class"
  [[ $verified_artifact_kind == "$class" ]] || ledger_error "$ledger" "invalid_artifact_class id=$task_id class=$class"
  path=$verified_artifact_path
  if [[ $class == live_service ]]; then
    jq -e --arg task "$task_id" '.schema == "lyflow-live-service-evidence/v1" and .task_id == $task and
      (.service.name | type == "string" and length > 0) and (.service.instance | type == "string" and length > 0) and
      (.probe | type == "string" and length > 0) and (.observable | type == "string" and length > 0)' "$ledger_dir/$path" >/dev/null 2>&1 \
      || ledger_error "$ledger" "invalid_live_service id=$task_id"
    jq -e --argjson file "$(jq -c . "$ledger_dir/$path")" '.service == $file.service and .probe == $file.probe and .observable == $file.observable and (.receipt | type == "object")' <<<"$record" >/dev/null \
      || ledger_error "$ledger" "invalid_live_service id=$task_id"
    receipt_record=$(jq -c '.receipt' <<<"$record")
    validate_command_receipt "$ledger" "$ledger_dir" "$task_id" live_service "$(jq -r '.probe' <<<"$record")" zero "$receipt_record"
  else
    jq -e --arg task "$task_id" --arg kind "$class" '.schema == "lyflow-evidence-artifact/v1" and .task_id == $task and .kind == $kind and (.observable | type == "string" and length > 0)' "$ledger_dir/$path" >/dev/null 2>&1 \
      || ledger_error "$ledger" "invalid_artifact_class id=$task_id class=$class"
  fi
}

validate_ledger() {
  local ledger=$1 ledger_dir id entry expected_evidence_id required_class class disposition record path
  local -a expected_ids actual_classes
  seen_evidence_ids=()
  seen_artifact_paths=()
  verified_artifacts=0
  jq -e . "$ledger" >/dev/null 2>&1 || ledger_error "$ledger" 'invalid_json'
  jq -e --arg schema_id "$(jq -r '.schema_id' "$schema")" --argjson version "$(jq '.schema_version' "$schema")" \
    '.schema_id == $schema_id and .schema_version == $version and (.purpose == "schema_conformance_fixture" or .purpose == "acceptance") and (.entries | type == "array")' "$ledger" >/dev/null \
    || ledger_error "$ledger" 'schema_mismatch'
  ledger_dir=$(cd "$(dirname "$ledger")" && pwd)
  validate_starting_state "$ledger" "$ledger_dir"
  id=$(jq -r '([.entries[]?.id] | group_by(.)[] | select(length > 1) | .[0]) // empty' "$ledger")
  [[ -z $id ]] || ledger_error "$ledger" "duplicate_id id=$id"
  id=$(jq -r '([.entries[]?.evidence_id] | group_by(.)[] | select(length > 1) | .[0]) // empty' "$ledger")
  [[ -z $id ]] || ledger_error "$ledger" "duplicate_evidence_id id=$id"
  mapfile -t expected_ids < <(jq -r '.tasks[].id' "$schema")
  for id in "${expected_ids[@]}"; do
    jq -e --arg id "$id" '[.entries[] | select(.id == $id)] | length == 1' "$ledger" >/dev/null || ledger_error "$ledger" "missing_task id=$id"
    entry=$(jq -c --arg id "$id" '.entries[] | select(.id == $id)' "$ledger")
    expected_evidence_id=$(jq -r --arg id "$id" '.tasks[] | select(.id == $id) | .evidence_id' "$schema")
    [[ $(jq -r '.evidence_id' <<<"$entry") == "$expected_evidence_id" ]] || ledger_error "$ledger" "invalid_task_evidence_id id=$id"
    [[ -z ${seen_evidence_ids[$expected_evidence_id]+x} ]] || ledger_error "$ledger" "duplicate_evidence_id id=$expected_evidence_id"
    seen_evidence_ids[$expected_evidence_id]=1
    jq -e '.setup.identity | type == "string" and length > 0' <<<"$entry" >/dev/null || ledger_error "$ledger" "missing_setup_identity id=$id"
    record=$(jq -c '.setup.receipt' <<<"$entry")
    verify_artifact "$ledger" "$ledger_dir" "$record" "$id:setup"
    path=$verified_artifact_path
    [[ $verified_artifact_kind == setup_receipt ]] || ledger_error "$ledger" "missing_setup_receipt id=$id"
    jq -e --arg task "$id" --arg identity "$(jq -r '.setup.identity' <<<"$entry")" '.schema == "lyflow-setup-receipt/v1" and .task_id == $task and .identity == $identity' "$ledger_dir/$path" >/dev/null 2>&1 \
      || ledger_error "$ledger" "setup_receipt_mismatch id=$id"
    jq -e '.red.status == "FAIL" and (.red.command | type == "string" and length > 0)' <<<"$entry" >/dev/null || ledger_error "$ledger" "missing_red id=$id"
    validate_command_receipt "$ledger" "$ledger_dir" "$id" red "$(jq -r '.red.command' <<<"$entry")" nonzero "$(jq -c '.red.receipt' <<<"$entry")"
    if jq -e '.result.status == "PASS" and (.result.claim | type == "string") and (.result.receipt | type != "object")' <<<"$entry" >/dev/null; then
      ledger_error "$ledger" "prose_only_pass id=$id"
    fi
    jq -e '.result.status == "PASS" and (.result.command | type == "string" and length > 0)' <<<"$entry" >/dev/null || ledger_error "$ledger" "invalid_status id=$id"
    validate_command_receipt "$ledger" "$ledger_dir" "$id" result "$(jq -r '.result.command' <<<"$entry")" zero "$(jq -c '.result.receipt' <<<"$entry")"
    jq -e '.cleanup.status == "PASS" and (.cleanup.receipt | type == "object")' <<<"$entry" >/dev/null || ledger_error "$ledger" "missing_cleanup id=$id"
    verify_artifact "$ledger" "$ledger_dir" "$(jq -c '.cleanup.receipt' <<<"$entry")" "$id:cleanup"
    path=$verified_artifact_path
    [[ $verified_artifact_kind == cleanup_receipt ]] || ledger_error "$ledger" "missing_cleanup_receipt id=$id"
    jq -e --arg task "$id" '.schema == "lyflow-cleanup-receipt/v1" and .task_id == $task and .status == "PASS" and (.removed | type == "array")' "$ledger_dir/$path" >/dev/null 2>&1 \
      || ledger_error "$ledger" "cleanup_receipt_mismatch id=$id"
    jq -e '.artifacts | type == "array" and length > 0' <<<"$entry" >/dev/null || ledger_error "$ledger" "missing_digest id=$id"
    while IFS= read -r required_class; do
      record=$(jq -c --arg class "$required_class" '.artifacts[] | select(.kind == $class)' <<<"$entry")
      [[ -n $record ]] || ledger_error "$ledger" "missing_artifact_class id=$id class=$required_class"
      validate_typed_artifact "$ledger" "$ledger_dir" "$id" "$required_class" "$record"
    done < <(jq -r --arg id "$id" '.tasks[] | select(.id == $id) | .required_artifact_classes[]' "$schema")
    mapfile -t actual_classes < <(jq -r '.adversarial_classes[]?.class' <<<"$entry")
    [[ ${#actual_classes[@]} -eq 9 ]] || ledger_error "$ledger" "missing_adversarial_class id=$id"
    jq -e --slurpfile schema "$schema" '[.adversarial_classes[].class] | sort == ($schema[0].adversarial_classes | sort) and (unique | length == 9)' <<<"$entry" >/dev/null \
      || ledger_error "$ledger" "invalid_adversarial_classes id=$id"
    while IFS= read -r class; do
      disposition=$(jq -r --arg class "$class" '.adversarial_classes[] | select(.class == $class) | .disposition' <<<"$entry")
      [[ $disposition == PROBED ]] || ledger_error "$ledger" "mandatory_adversarial_not_probed id=$id class=$class"
    done < <(jq -r --arg id "$id" '.tasks[] | select(.id == $id) | .mandatory_adversarial_classes[]' "$schema")
    while IFS= read -r class; do
      disposition=$(jq -r --arg class "$class" '.adversarial_classes[] | select(.class == $class) | .disposition' <<<"$entry")
      if [[ $disposition == PROBED ]]; then
        record=$(jq -c --arg class "$class" '.adversarial_classes[] | select(.class == $class) | .artifact' <<<"$entry")
        verify_artifact "$ledger" "$ledger_dir" "$record" "$id:adversarial:$class"
        path=$(artifact_field "$record" path)
        jq -e --arg task "$id" --arg class "$class" '.schema == "lyflow-adversarial-probe/v1" and .task_id == $task and .class == $class and (.result | type == "string" and length > 0)' "$ledger_dir/$path" >/dev/null 2>&1 \
          || ledger_error "$ledger" "incomplete_adversarial_record id=$id class=$class"
      elif [[ $disposition == N/A ]]; then
        jq -e --arg class "$class" '.adversarial_classes[] | select(.class == $class) | .reason | type == "string" and length > 10' <<<"$entry" >/dev/null \
          || ledger_error "$ledger" "incomplete_adversarial_record id=$id class=$class"
      else
        ledger_error "$ledger" "invalid_adversarial_disposition id=$id class=$class"
      fi
    done < <(jq -r '.adversarial_classes[]' "$schema")
  done
  jq -e --slurpfile schema "$schema" '[.entries[].id] - [$schema[0].tasks[].id] | length == 0' "$ledger" >/dev/null || ledger_error "$ledger" 'unexpected_task_id'
  printf 'ok=%s entries=%s artifacts=%s\n' "$ledger" "${#expected_ids[@]}" "$verified_artifacts"
}

failed=0
for evidence_path in "$@"; do
  if [[ ! -s "$evidence_path" ]]; then
    printf 'missing_or_empty=%s\n' "$evidence_path" >&2
    failed=1
  elif [[ $evidence_path == *.json ]]; then
    (validate_ledger "$evidence_path") || failed=1
  else
    printf 'legacy_evidence_present=%s\n' "$evidence_path"
  fi
done
exit "$failed"
