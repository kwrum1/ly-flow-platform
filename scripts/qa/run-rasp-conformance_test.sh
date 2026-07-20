#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
evidence="$tmp/evidence.json"
output="$tmp/output.jsonl"
artifacts="$tmp/evidence-artifacts"

if env \
  RASP_PYTHON_310_IMAGE=lyflow/rasp-conformance:self-test-missing-310 \
  RASP_PYTHON_311_IMAGE=lyflow/rasp-conformance:self-test-missing-311 \
  RASP_PYTHON_312_IMAGE=lyflow/rasp-conformance:self-test-missing-312 \
  "$root/scripts/qa/run-rasp-conformance.sh" \
    --evidence "$evidence" \
    --evidence-dir "$artifacts" \
    --iterations 2 >"$output"; then
  printf 'conformance unexpectedly passed without every exact matrix runtime\n' >&2
  exit 1
fi

python3 - "$evidence" "$output" "$artifacts" <<'PY'
import json
import sys
from pathlib import Path

evidence = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
rows = [json.loads(line) for line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()]
assert evidence["status"] in {"BLOCKED", "FAIL"}
assert evidence["iterations"] == 2
assert Path(evidence["evidence_directory"]) == Path(sys.argv[3])
assert evidence["matrix"] == rows
assert [row["runtime"] for row in rows[:3]] == ["CPython 3.10", "CPython 3.11", "CPython 3.12"]
assert all(row["source_path"] == "agent/rasp/python" for row in rows[:3])
assert all(row["monitor_mode"] == "monitor" for row in rows[:4])
assert rows[3]["source_path"] == "agent/rasp/java"
assert rows[3]["status"] == "EXPERIMENTAL"
assert rows[3]["gates"].startswith("todo15-runtime:")
assert all(row["status"] == "UNSUPPORTED" for row in rows[4:])
assert (Path(sys.argv[3]) / "sources" / "rasp-support-matrix.tsv").is_file()
assert (Path(sys.argv[3]) / "sources" / "canonical-events.json").is_file()
assert (Path(sys.argv[3]) / "receipts" / "source-fixtures.sha256").is_file()
PY

printf 'RASP conformance harness self-test passed\n'
