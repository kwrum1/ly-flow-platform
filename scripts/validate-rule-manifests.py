#!/usr/bin/env python3
"""Validate LyFlow rule source manifests without external dependencies."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


REQUIRED_FIELDS = {
    "schema_version",
    "source_id",
    "name",
    "category",
    "source_type",
    "update_mode",
    "vendor",
    "license",
    "source_url",
    "raw_path",
    "converted_path",
    "compiled_path",
    "enabled_by_default",
    "conversion",
}
VALID_CATEGORIES = {"hids", "dpi", "correlation", "scoring"}
VALID_SOURCE_TYPES = {"internal", "rebuilt_internal", "external_subscription", "external_import"}
SAFE_UPDATE_MODES = {"manual", "one_time_import", "manual_fetch_then_convert"}


def non_empty(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def validate(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [f"{path}: failed to parse JSON: {exc}"]

    missing = sorted(REQUIRED_FIELDS - set(data))
    if missing:
        errors.append(f"{path}: missing field(s): {', '.join(missing)}")

    for field in ["source_id", "name", "vendor", "license", "source_url", "raw_path", "converted_path", "compiled_path"]:
        if field in data and not non_empty(data[field]):
            errors.append(f"{path}: {field} must be a non-empty string")

    if data.get("category") not in VALID_CATEGORIES:
        errors.append(f"{path}: invalid category {data.get('category')!r}")
    if data.get("source_type") not in VALID_SOURCE_TYPES:
        errors.append(f"{path}: invalid source_type {data.get('source_type')!r}")
    if data.get("update_mode") not in SAFE_UPDATE_MODES:
        errors.append(f"{path}: update_mode must be manual, one_time_import, or manual_fetch_then_convert")
    if not isinstance(data.get("enabled_by_default"), bool):
        errors.append(f"{path}: enabled_by_default must be boolean")

    conversion = data.get("conversion")
    if not isinstance(conversion, dict):
        errors.append(f"{path}: conversion must be object")
    else:
        if not non_empty(conversion.get("converter")):
            errors.append(f"{path}: conversion.converter must be non-empty")
        if conversion.get("target_ir") != "lyflow-rule-ir-v1":
            errors.append(f"{path}: conversion.target_ir must be lyflow-rule-ir-v1")

    if data.get("source_type") == "external_subscription" and data.get("enabled_by_default") is True:
        errors.append(f"{path}: external subscriptions must not be enabled by default")

    return errors


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: validate-rule-manifests.py <manifest.json> [<manifest.json> ...]", file=sys.stderr)
        return 2

    errors: list[str] = []
    for name in argv[1:]:
        errors.extend(validate(Path(name)))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    for name in argv[1:]:
        print(f"ok: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
