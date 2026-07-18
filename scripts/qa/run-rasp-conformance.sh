#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
matrix="$root/scripts/qa/rasp-support-matrix.tsv"
evidence="$root/.omo/evidence/task-13-lyflow-commercial-defense-hardening.json"
evidence_dir=
iterations=1
while [[ $# -gt 0 ]]; do
  case $1 in
    --evidence)
      [[ $# -ge 2 ]] || { printf 'missing value for --evidence\n' >&2; exit 2; }
      evidence=$2
      shift 2
      ;;
    --evidence-dir)
      [[ $# -ge 2 ]] || { printf 'missing value for --evidence-dir\n' >&2; exit 2; }
      evidence_dir=$2
      shift 2
      ;;
    --iterations)
      [[ $# -ge 2 && $2 =~ ^[1-9][0-9]*$ ]] || { printf 'invalid value for --iterations\n' >&2; exit 2; }
      iterations=$2
      shift 2
      ;;
    *)
      printf 'usage: %s [--evidence PATH] [--evidence-dir PATH] [--iterations COUNT]\n' "$0" >&2
      exit 2
      ;;
  esac
done
[[ -n $evidence_dir ]] || evidence_dir="${evidence%.json}.d"

tmp=$(mktemp -d)
container_id=
cleanup() {
  if [[ -n $container_id ]]; then
    docker rm -f "$container_id" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM
entries="$tmp/entries.jsonl"
overall=PASS
artifact_status=PASS
artifact_detail=authoritative-python-only

mkdir -p "$evidence_dir/logs" "$evidence_dir/receipts" "$evidence_dir/sources"
cp "$matrix" "$evidence_dir/sources/rasp-support-matrix.tsv"
cp "$root/agent/rasp/python/tests/test_conformance.py" "$evidence_dir/sources/test_conformance.py"
cp "$root/agent/rasp/python/tests/test_bridge_delivery.py" "$evidence_dir/sources/test_bridge_delivery.py"
cp "$root/agent/rasp/python/tests/fixtures/canonical-events.json" "$evidence_dir/sources/canonical-events.json"
cp "$root/server/Dockerfile.final" "$evidence_dir/sources/server.Dockerfile.final"
for source in "$root"/scripts/qa/rasp-conformance-images/*.Dockerfile; do
  cp "$source" "$evidence_dir/sources/$(basename "$source")"
done
: >"$evidence_dir/receipts/source-fixtures.sha256"
for source in "$evidence_dir"/sources/*; do
  digest=$(sha256sum "$source")
  digest=${digest%% *}
  printf '%s  sources/%s\n' "$digest" "$(basename "$source")" >>"$evidence_dir/receipts/source-fixtures.sha256"
done

mark_overall() {
  case $1 in
    FAIL)
      overall=FAIL
      ;;
    BLOCKED)
      if [[ $overall == PASS ]]; then
        overall=BLOCKED
      fi
      ;;
  esac
}

emit_row() {
  local source_path=$1 runtime=$2 os_name=$3 monitor_mode=$4 gates=$5 status=$6 detail=$7
  local row
  printf -v row '{"source_path":"%s","runtime":"%s","os":"%s","monitor_mode":"%s","gates":"%s","status":"%s","detail":"%s"}' \
    "$source_path" "$runtime" "$os_name" "$monitor_mode" "$gates" "$status" "$detail"
  printf '%s\n' "$row"
  printf '%s\n' "$row" >>"$entries"
}

assert_pilot_artifacts() {
  local dockerfile archive listed image_list
  for dockerfile in "$root/server/Dockerfile" "$root/server/Dockerfile.final"; do
    if grep -Eq '^[[:space:]]*COPY[[:space:]]+probe/rasp' "$dockerfile"; then
      artifact_detail=excluded-probe-copy
      return 1
    fi
    if ! grep -Eq '^[[:space:]]*COPY[[:space:]]+agent/rasp/python/' "$dockerfile"; then
      artifact_detail=authoritative-python-copy-missing
      return 1
    fi
    if grep -Eq '^[[:space:]]*COPY[[:space:]]+agent/rasp/(java|nodejs|php|dotnet)' "$dockerfile"; then
      artifact_detail=noncandidate-runtime-copy
      return 1
    fi
  done
  shopt -s nullglob
  for archive in "$root"/release/lyflow-offline-install-*.tar.gz; do
    listed="$tmp/$(basename "$archive").list"
    if ! tar -tzf "$archive" >"$listed"; then
      artifact_detail=unreadable-pilot-archive
      return 1
    fi
    if grep -Eq '(^|/)probe/rasp(/|$)' "$listed"; then
      artifact_detail=excluded-tree-in-pilot-archive
      return 1
    fi
  done
  if [[ -n ${RASP_PILOT_IMAGE:-} ]]; then
    if ! docker image inspect "$RASP_PILOT_IMAGE" >/dev/null 2>&1; then
      artifact_detail=missing-local-pilot-image
      return 1
    fi
    if ! container_id=$(docker create "$RASP_PILOT_IMAGE"); then
      artifact_detail=unreadable-pilot-image
      return 1
    fi
    docker image inspect "$RASP_PILOT_IMAGE" >"$evidence_dir/receipts/pilot-image.inspect.json"
    docker history --no-trunc "$RASP_PILOT_IMAGE" >"$evidence_dir/receipts/pilot-image.history.txt"
    image_list="$evidence_dir/receipts/pilot-image.filesystem.txt"
    if ! docker export "$container_id" | tar -tf - >"$image_list"; then
      artifact_detail=unreadable-pilot-image
      return 1
    fi
    docker rm "$container_id" >/dev/null
    container_id=
    if grep -Eq '(^|/)probe/rasp(/|$)' "$image_list"; then
      artifact_detail=excluded-tree-in-pilot-image
      return 1
    fi
    if grep -Eq '(^|/)app/agent/rasp/(java|nodejs|php|dotnet)(/|$)' "$image_list"; then
      artifact_detail=noncandidate-runtime-in-pilot-image
      return 1
    fi
    if ! grep -Eq '(^|/)app/agent/rasp/python(/|$)' "$image_list"; then
      artifact_detail=authoritative-python-missing-from-pilot-image
      return 1
    fi
  fi
}

if ! assert_pilot_artifacts; then
  artifact_status=FAIL
  mark_overall FAIL
fi

host_os_matches() {
  local expected=$1
  [[ -r /etc/os-release ]] || return 1
  . /etc/os-release
  [[ ${ID:-} == ubuntu && ${VERSION_ID:-} == "$expected" ]]
}

run_with_host() {
  local executable=$1 minor=$2 os_version=$3 log=$4
  command -v "$executable" >/dev/null 2>&1 || return 2
  host_os_matches "$os_version" || return 2
  "$executable" -c "import sys; raise SystemExit(0 if sys.version_info[:2] == ($minor) else 1)" || return 2
  (
    cd "$root/agent/rasp/python"
    PYTHONPYCACHEPREFIX="$tmp/pycache-$minor" "$executable" -m compileall -q ly_rasp tests
    PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX="$tmp/pycache-$minor" "$executable" -m unittest -q tests.test_conformance tests.test_bridge_delivery
  ) >"$log" 2>&1
}

run_with_image() {
  local image=$1 minor=$2 os_version=$3 log=$4
  command -v docker >/dev/null 2>&1 || return 2
  docker image inspect "$image" >/dev/null 2>&1 || return 2
  docker run --rm --pull=never --network=none \
    -e EXPECTED_MINOR="$minor" -e EXPECTED_OS="$os_version" \
    -v "$root:/workspace:ro" -w /workspace/agent/rasp/python "$image" \
    sh -ceu '
      . /etc/os-release
      test "$ID" = ubuntu
      test "$VERSION_ID" = "$EXPECTED_OS"
      runtime=python
      command -v "$runtime" >/dev/null 2>&1 || runtime=python3
      "$runtime" -c "import os, sys; expected=tuple(map(int, os.environ[\"EXPECTED_MINOR\"].split(\".\"))); raise SystemExit(0 if sys.version_info[:2] == expected else 1)"
      PYTHONPYCACHEPREFIX=/tmp/lyflow-pyc "$runtime" -m compileall -q ly_rasp tests
      PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=/tmp/lyflow-pyc "$runtime" -m unittest -q tests.test_conformance tests.test_bridge_delivery
    ' >"$log" 2>&1
}

record_image_receipt() {
  local image=$1 minor=$2
  docker image inspect "$image" >"$evidence_dir/receipts/python-${minor}-image.inspect.json"
  docker history --no-trunc "$image" >"$evidence_dir/receipts/python-${minor}-image.history.txt"
  docker run --rm --pull=never --network=none "$image" sh -ceu '
    . /etc/os-release
    runtime=python
    command -v "$runtime" >/dev/null 2>&1 || runtime=python3
    printf "ID=%s\nVERSION_ID=%s\nPRETTY_NAME=%s\n" "$ID" "$VERSION_ID" "$PRETTY_NAME"
    printf "PYTHON=%s\n" "$("$runtime" --version 2>&1)"
    "$runtime" -c "import platform, sys; print(\"PYTHON_FULL=\" + sys.version.replace(chr(10), \" \")); print(\"IMPLEMENTATION=\" + platform.python_implementation())"
  ' >"$evidence_dir/receipts/python-${minor}-runtime.txt"
}

run_python_row() {
  local runtime=$1 os_name=$2 source_path=$3 monitor_mode=$4 declared_gates=$5
  local executable image minor os_version log result status detail gates iteration run_result
  case $runtime in
    'CPython 3.10') executable=python3.10; image=${RASP_PYTHON_310_IMAGE:-lyflow/rasp-conformance:cpython3.10-ubuntu22.04}; minor=3.10; os_version=22.04 ;;
    'CPython 3.11') executable=python3.11; image=${RASP_PYTHON_311_IMAGE:-lyflow/rasp-conformance:cpython3.11-ubuntu22.04}; minor=3.11; os_version=22.04 ;;
    'CPython 3.12') executable=python3.12; image=${RASP_PYTHON_312_IMAGE:-lyflow/rasp-conformance:cpython3.12-ubuntu24.04}; minor=3.12; os_version=24.04 ;;
    *)
      emit_row "$source_path" "$runtime" "$os_name" "$monitor_mode" "matrix:FAIL,artifact-exclusions:$artifact_status" FAIL unsupported-matrix-runtime
      mark_overall FAIL
      return
      ;;
  esac
  result=0
  detail="count${iterations}-pass"
  if docker image inspect "$image" >/dev/null 2>&1; then
    record_image_receipt "$image" "$minor"
    for ((iteration = 1; iteration <= iterations; iteration++)); do
      printf -v log '%s/logs/python-%s-run-%02d.log' "$evidence_dir" "$minor" "$iteration"
      run_result=0
      run_with_image "$image" "$minor" "$os_version" "$log" || run_result=$?
      if [[ $run_result -ne 0 ]]; then
        result=1
        detail="image-conformance-failed:run-${iteration}"
        break
      fi
    done
  else
    printf -v log '%s/logs/python-%s-host.log' "$evidence_dir" "$minor"
    run_result=0
    run_with_host "$executable" "$minor" "$os_version" "$log" || run_result=$?
    if [[ $run_result -eq 0 ]]; then
      if [[ $iterations -ne 1 ]]; then
        result=2
        detail="missing-local-image-for-count${iterations}:${image}"
      else
        detail=local-executable
      fi
    elif [[ $run_result -eq 1 ]]; then
      result=1
      detail=host-conformance-failed
    else
      result=2
      detail="missing-local-runtime-or-image:${image}"
    fi
  fi
  case $result in
    0) status=PASS; gates="${declared_gates//,/\:PASS,}:PASS" ;;
    1) status=FAIL; gates="conformance:FAIL,artifact-exclusions:$artifact_status" ;;
    2) status=BLOCKED; gates="conformance:BLOCKED,artifact-exclusions:$artifact_status" ;;
  esac
  if [[ $artifact_status == FAIL ]]; then
    status=FAIL
    gates="conformance:${status},artifact-exclusions:FAIL"
    detail=$artifact_detail
  fi
  emit_row "$source_path" "$runtime" "$os_name" "$monitor_mode" "$gates" "$status" "$detail"
  mark_overall "$status"
}

while IFS=$'\t' read -r kind source_path excluded_tree runtime os_name monitor_mode gates declared_status gate; do
  [[ $kind == kind ]] && continue
  case $kind in
    python)
      if [[ $source_path != agent/rasp/python || $monitor_mode != monitor || $gate != required ]]; then
        emit_row "$source_path" "$runtime" "$os_name" "$monitor_mode" "matrix:FAIL" FAIL invalid-python-authority
        mark_overall FAIL
      else
        run_python_row "$runtime" "$os_name" "$source_path" "$monitor_mode" "$gates"
      fi
      ;;
    java)
      status=EXPERIMENTAL
      gate_status=PASS
      detail=Todo15-experimental-runtime-verified
      java_log="$evidence_dir/logs/java-experimental.log"
      if [[ $source_path != agent/rasp/java || $excluded_tree != probe/rasp/java || $gate != Todo15-experimental ]] \
          || ! bash "$root/scripts/qa/run-java-rasp-conformance.sh" --iterations "$iterations" >"$java_log" 2>&1; then
        status=EXPERIMENTAL
        gate_status=FAIL
        detail=Todo15-experimental-runtime-failed
      fi
      emit_row "$source_path" "$runtime" "$os_name" "$monitor_mode" "todo15-runtime:$gate_status,pilot-exclusion:$artifact_status" "$status" "$detail"
      ;;
    node|php|dotnet)
      status=UNSUPPORTED
      [[ $source_path == none && $declared_status == unsupported/deferred ]] || status=FAIL
      emit_row "$source_path" "$runtime" "$os_name" "$monitor_mode" "pilot-exclusion:$artifact_status" "$status" "$excluded_tree-excluded"
      [[ $status == FAIL ]] && mark_overall FAIL
      ;;
    *)
      emit_row "$source_path" "$runtime" "$os_name" "$monitor_mode" "matrix:FAIL" FAIL unknown-matrix-kind
      mark_overall FAIL
      ;;
  esac
done <"$matrix"

mkdir -p "$(dirname "$evidence")"
: >"$evidence_dir/receipts/conformance-logs.sha256"
for log in "$evidence_dir"/logs/*.log; do
  [[ -e $log ]] || continue
  digest=$(sha256sum "$log")
  digest=${digest%% *}
  printf '%s  logs/%s\n' "$digest" "$(basename "$log")" >>"$evidence_dir/receipts/conformance-logs.sha256"
done
aggregate_digest=$(sha256sum "$evidence_dir/receipts/conformance-logs.sha256")
aggregate_digest=${aggregate_digest%% *}
printf '%s  receipts/conformance-logs.sha256\n' "$aggregate_digest" >"$evidence_dir/receipts/conformance-logs.aggregate.sha256"
printf 'iterations=%s\npython_310_image=%s\npython_311_image=%s\npython_312_image=%s\npilot_image=%s\nnetwork=none\n' \
  "$iterations" \
  "${RASP_PYTHON_310_IMAGE:-lyflow/rasp-conformance:cpython3.10-ubuntu22.04}" \
  "${RASP_PYTHON_311_IMAGE:-lyflow/rasp-conformance:cpython3.11-ubuntu22.04}" \
  "${RASP_PYTHON_312_IMAGE:-lyflow/rasp-conformance:cpython3.12-ubuntu24.04}" \
  "${RASP_PILOT_IMAGE:-not-set}" >"$evidence_dir/receipts/verification-command.txt"

python3 - "$evidence" "$entries" "$evidence_dir" "$overall" "$artifact_status" "$artifact_detail" "$iterations" "${TASK13_AUTHORIZED_PROXY:-}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

evidence_path = Path(sys.argv[1])
entries_path = Path(sys.argv[2])
evidence_dir = Path(sys.argv[3]).resolve()
overall = sys.argv[4]
artifact_status = sys.argv[5]
artifact_detail = sys.argv[6]
iterations = int(sys.argv[7])
authorized_proxy = sys.argv[8]

matrix = [json.loads(line) for line in entries_path.read_text(encoding="utf-8").splitlines()]


def receipt_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values


runtime_images = []
for minor, requirement in (
    ("3.10", "CPython 3.10 on Ubuntu 22.04"),
    ("3.11", "CPython 3.11 on Ubuntu 22.04"),
    ("3.12", "CPython 3.12 on Ubuntu 24.04"),
):
    inspect_path = evidence_dir / "receipts" / f"python-{minor}-image.inspect.json"
    runtime_path = evidence_dir / "receipts" / f"python-{minor}-runtime.txt"
    row = next(item for item in matrix if item["runtime"] == f"CPython {minor}")
    if inspect_path.is_file() and runtime_path.is_file():
        inspected = json.loads(inspect_path.read_text(encoding="utf-8"))[0]
        values = receipt_values(runtime_path)
        repo_digests = inspected.get("RepoDigests") or []
        runtime_images.append({
            "requirement": requirement,
            "image": inspected["RepoTags"][0],
            "repo_digest": repo_digests[0] if repo_digests else None,
            "image_id": inspected["Id"],
            "os_release": {
                "id": values["ID"],
                "version_id": values["VERSION_ID"],
                "pretty_name": values["PRETTY_NAME"],
            },
            "python": values["PYTHON"],
            "python_full": values["PYTHON_FULL"],
            "implementation": values["IMPLEMENTATION"],
            "iterations": iterations,
            "status": row["status"],
            "receipts": [
                str(inspect_path.relative_to(evidence_dir)),
                str(runtime_path.relative_to(evidence_dir)),
                f"receipts/python-{minor}-image.history.txt",
            ],
        })
    else:
        runtime_images.append({
            "requirement": requirement,
            "iterations": iterations,
            "status": row["status"],
            "detail": row["detail"],
        })

pilot = None
pilot_inspect_path = evidence_dir / "receipts" / "pilot-image.inspect.json"
if pilot_inspect_path.is_file():
    inspected = json.loads(pilot_inspect_path.read_text(encoding="utf-8"))[0]
    repo_digests = inspected.get("RepoDigests") or []
    pilot = {
        "image": inspected["RepoTags"][0],
        "repo_digest": repo_digests[0] if repo_digests else None,
        "image_id": inspected["Id"],
        "filesystem_receipt": "receipts/pilot-image.filesystem.txt",
        "history_receipt": "receipts/pilot-image.history.txt",
    }

log_hashes = evidence_dir / "receipts" / "conformance-logs.sha256"
aggregate = hashlib.sha256(log_hashes.read_bytes()).hexdigest()
passed = overall == "PASS"
gate_status = "PASS" if passed else overall
evidence = {
    "task": 13,
    "claim": "authoritative RASP support matrix and conformance",
    "status": overall,
    "done_claim": "DONE" if passed else "BLOCKED",
    "candidate": "agent/rasp/python",
    "iterations": iterations,
    "evidence_directory": str(evidence_dir),
    "network_access": {
        "authorized": bool(authorized_proxy),
        "used_for_pull_and_build": bool(authorized_proxy),
        "proxy": authorized_proxy or None,
        "conformance_network": "none",
    },
    "artifact_exclusions": {
        "status": artifact_status,
        "detail": artifact_detail,
        "pilot_image": pilot,
        "included": ["/app/agent/rasp/python"],
        "excluded": ["probe/rasp", "agent/rasp/java", "Node.js", "PHP", ".NET"],
    },
    "runtime_images": runtime_images,
    "quality_gates": {
        "python_conformance_count": gate_status,
        "inert_command_file_sql": gate_status,
        "canonical_events": gate_status,
        "policy_version_binding": gate_status,
        "missing_policy_fail_behavior_health": gate_status,
        "exporter_outage_fail_behavior_health": gate_status,
        "pilot_package_exclusion": artifact_status,
  "java_todo14_gate": "RECORDED: EXPERIMENTAL and gated",
    },
    "determinism": {
        "iterations_per_runtime": iterations,
        "log_hash_manifest": "receipts/conformance-logs.sha256",
        "log_hash_manifest_sha256": aggregate,
        "status": gate_status,
    },
    "sources": {
        "fixture_hash_manifest": "receipts/source-fixtures.sha256",
        "directory": "sources",
    },
    "retention": {
        "verification_images_retained": True,
        "evidence_retained": True,
        "transient_containers_only_cleaned": True,
    },
    "matrix": matrix,
}
evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

[[ $overall == PASS ]]
