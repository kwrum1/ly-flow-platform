#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workflow="$root/.gitea/workflows/ci.yml"

python3 - "$workflow" <<'PY'
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml


def validate(document: str, source: str) -> list[str]:
    errors: list[str] = []
    loaded = yaml.load(document, Loader=yaml.BaseLoader)
    if not isinstance(loaded, dict):
        return [f"{source}: workflow root must be a mapping"]

    if "permissions" in loaded:
        errors.append(f"{source}: top-level permissions are unsupported by Gitea Actions")

    jobs = loaded.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return errors + [f"{source}: jobs must be a non-empty mapping"]

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            errors.append(f"{source}: job {job_name} must be a mapping")
            continue

        runs_on = job.get("runs-on")
        valid_runner = isinstance(runs_on, str) or (
            isinstance(runs_on, list)
            and bool(runs_on)
            and all(isinstance(label, str) for label in runs_on)
        )
        if not valid_runner:
            errors.append(
                f"{source}: job {job_name} runs-on must be a string or string array"
            )
        for unsupported in ("environment", "permissions"):
            if unsupported in job:
                errors.append(
                    f"{source}: job {job_name} uses unsupported {unsupported}"
                )

        job_env = job.get("env", {})
        if isinstance(job_env, dict) and "LYFLOW_GITEA_TOKEN" in job_env:
            errors.append(
                f"{source}: job {job_name} exposes the release token to non-upload steps"
            )

        steps = job.get("steps")
        if not isinstance(steps, list):
            errors.append(f"{source}: job {job_name} steps must be an array")
            continue
        for step_number, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                errors.append(
                    f"{source}: job {job_name} step {step_number} must be a mapping"
                )
                continue
            run = step.get("run")
            if isinstance(run, str):
                result = subprocess.run(
                    ["bash", "-n"],
                    input=run,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if result.returncode != 0:
                    errors.append(
                        f"{source}: job {job_name} step {step_number} is invalid shell: "
                        f"{result.stderr.strip()}"
                    )

    return errors


invalid_cases = {
    "mapping runner": "jobs:\n  build:\n    runs-on:\n      labels: [docker]\n    steps: []\n",
    "GitHub environment": "jobs:\n  build:\n    runs-on: docker\n    environment: release\n    steps: []\n",
    "GitHub permissions": "permissions:\n  id-token: write\njobs:\n  build:\n    runs-on: docker\n    steps: []\n",
}
for case_name, fixture in invalid_cases.items():
    if not validate(fixture, case_name):
        raise SystemExit(f"invalid fixture was accepted: {case_name}")

workflow_path = Path(sys.argv[1])
text = workflow_path.read_text(encoding="utf-8")
workflow_errors = validate(text, str(workflow_path))
loaded_workflow = yaml.load(text, Loader=yaml.BaseLoader)
jobs = loaded_workflow.get("jobs", {}) if isinstance(loaded_workflow, dict) else {}
for job_name in ("release-amd64",):
    job = jobs.get(job_name, {}) if isinstance(jobs, dict) else {}
    steps = job.get("steps", []) if isinstance(job, dict) else []
    first_step = steps[0] if isinstance(steps, list) and steps else {}
    if not isinstance(first_step, dict) or "git clone --depth 1" not in first_step.get("run", ""):
        workflow_errors.append(
            f"{workflow_path}: job {job_name} must start with a local Gitea clone"
        )
for required in (
    "mktemp -d",
    "if: always()",
    "github.event_name != 'pull_request'",
    "gitea_url=\"${GITEA_INSTANCE_URL:-http://127.0.0.1:10000}\"",
    "git clone --depth 1",
    "bash scripts/qa/install-offline_test.sh",
    "bash scripts/qa/container-smoke_test.sh",
    "bash scripts/qa/prepare-rasp-conformance-images_test.sh",
    "bash scripts/qa/build-offline-release_test.sh",
    "bash scripts/qa/gitea-workflow_test.sh",
    "bash scripts/qa/prepare-rasp-conformance-images.sh",
    "bash scripts/container-smoke.sh",
    "docker pull postgres:16-alpine",
    "docker pull redis:7-alpine",
    "docker pull clickhouse/clickhouse-server:24.8-alpine",
    "release-root.pem",
):
    if required not in text:
        workflow_errors.append(f"{workflow_path}: missing concurrency safeguard {required!r}")
if "/tmp/lyflow-actions-workspace" in text:
    workflow_errors.append(f"{workflow_path}: checkout uses a shared temporary directory")
if "https://github.com/actions/checkout" in text or "uses: actions/checkout" in text:
    workflow_errors.append(f"{workflow_path}: workflow must not depend on GitHub checkout")
if 'mktemp -d "${TMPDIR:-/tmp}' in text:
    workflow_errors.append(f"{workflow_path}: temporary paths must be workspace-scoped")
if "/root/ly-flow-platform" in text:
    workflow_errors.append(f"{workflow_path}: workflow depends on a host-specific workspace")
token_binding = "LYFLOW_GITEA_TOKEN: ${{ secrets.LYFLOW_GITEA_TOKEN }}"
if text.count(token_binding) != 1:
    workflow_errors.append(
        f"{workflow_path}: upload step must bind LYFLOW_GITEA_TOKEN exactly once"
    )
rasp_mappings = re.findall(
    r'RASP_PYTHON_(\d+)_IMAGE="\$\{rasp_images\[(\d+)\]\}"', text
)
if rasp_mappings != [("310", "0"), ("311", "1"), ("312", "2")]:
    workflow_errors.append(
        f"{workflow_path}: RASP helper output must map exactly three ordered refs"
    )
if "[[ ${#rasp_images[@]} -eq 3 ]]" not in text:
    workflow_errors.append(
        f"{workflow_path}: RASP helper output count is not validated"
    )
helper_call = "bash scripts/qa/prepare-rasp-conformance-images.sh"
release_call = "bash scripts/build-offline-release.sh"
if text.count(helper_call) != 1 or text.find(helper_call) > text.find(release_call):
    workflow_errors.append(
        f"{workflow_path}: RASP images must be prepared once before package construction"
    )

if workflow_errors:
    raise SystemExit("\n".join(workflow_errors))
PY

printf 'Gitea workflow validation passed\n'
