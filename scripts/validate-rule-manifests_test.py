#!/usr/bin/env python3
"""Smoke-test source manifest category validation."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate-rule-manifests.py"
YARA_MANIFEST = ROOT / "rules" / "subscriptions" / "yara-signature-base" / "manifest.json"


def run_validator(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(VALIDATOR), str(path)],
        check=False,
        capture_output=True,
        text=True,
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        manifest = json.loads(YARA_MANIFEST.read_text(encoding="utf-8"))
        valid_path = Path(directory) / "yara-hids.json"
        valid_path.write_text(json.dumps(manifest), encoding="utf-8")
        valid = run_validator(valid_path)
        if valid.returncode != 0 or "ok:" not in valid.stdout:
            raise AssertionError(f"hids manifest rejected: {valid.stderr}")

        manifest["category"] = "runtime"
        invalid_path = Path(directory) / "yara-runtime.json"
        invalid_path.write_text(json.dumps(manifest), encoding="utf-8")
        invalid = run_validator(invalid_path)
        if invalid.returncode == 0 or "invalid category 'runtime'" not in invalid.stderr:
            raise AssertionError("runtime source category was accepted")

    print("ok: YARA hids accepted; runtime source category rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
