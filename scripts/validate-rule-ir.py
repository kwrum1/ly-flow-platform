#!/usr/bin/env python3
"""Lightweight LyFlow Rule IR validator.

This validator intentionally avoids third-party dependencies. It is not a full
JSON Schema engine; it enforces the required safety and metadata contract used
by the HIDS + DPI rule engineering plan.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


REQUIRED_TOP_LEVEL = {
    "kind",
    "schema_version",
    "id",
    "name",
    "category",
    "enabled",
    "source",
    "support",
    "classification",
    "scoring",
    "match",
}

REQUIRED_SOURCE = {"origin", "vendor", "license", "url", "version"}
VALID_KINDS = {
    "single_event_rule",
    "behavior_rule",
    "scoring_rule",
    "subscription_manifest",
    "support_report",
}
VALID_CATEGORIES = {"hids", "dpi", "correlation", "scoring", "manifest", "report"}
VALID_SUPPORT = {"full_supported", "partial_supported", "unsupported"}
VALID_STAGES = {
    "recon",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "lateral_movement",
    "c2_exfiltration",
    "uncategorized",
}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_LOGIC = {"all", "any", "sequence"}


def fail(path: Path, message: str) -> str:
    return f"{path}: {message}"


def is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def validate_rule(path: Path, rule: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    missing = sorted(REQUIRED_TOP_LEVEL - set(rule))
    if missing:
        errors.append(fail(path, f"missing top-level field(s): {', '.join(missing)}"))

    if rule.get("kind") not in VALID_KINDS:
        errors.append(fail(path, f"invalid kind: {rule.get('kind')!r}"))
    if rule.get("category") not in VALID_CATEGORIES:
        errors.append(fail(path, f"invalid category: {rule.get('category')!r}"))
    if not isinstance(rule.get("enabled"), bool):
        errors.append(fail(path, "enabled must be boolean"))

    source = rule.get("source")
    if not isinstance(source, dict):
        errors.append(fail(path, "source must be object"))
    else:
        missing_source = sorted(REQUIRED_SOURCE - set(source))
        if missing_source:
            errors.append(fail(path, f"missing source field(s): {', '.join(missing_source)}"))
        for key in REQUIRED_SOURCE:
            if key in source and not is_non_empty_string(source[key]):
                errors.append(fail(path, f"source.{key} must be non-empty string"))

    support = rule.get("support")
    if not isinstance(support, dict):
        errors.append(fail(path, "support must be object"))
    elif support.get("level") not in VALID_SUPPORT:
        errors.append(fail(path, f"invalid support.level: {support.get('level')!r}"))

    classification = rule.get("classification")
    if not isinstance(classification, dict):
        errors.append(fail(path, "classification must be object"))
    elif classification.get("stage") not in VALID_STAGES:
        errors.append(fail(path, f"invalid classification.stage: {classification.get('stage')!r}"))

    scoring = rule.get("scoring")
    if not isinstance(scoring, dict):
        errors.append(fail(path, "scoring must be object"))
    else:
        score = scoring.get("base_score")
        if not isinstance(score, int) or score < 0 or score > 100:
            errors.append(fail(path, "scoring.base_score must be integer 0..100"))
        if scoring.get("severity") not in VALID_SEVERITIES:
            errors.append(fail(path, f"invalid scoring.severity: {scoring.get('severity')!r}"))

    match = rule.get("match")
    if not isinstance(match, dict):
        errors.append(fail(path, "match must be object"))
    elif match.get("logic") not in VALID_LOGIC:
        errors.append(fail(path, f"invalid match.logic: {match.get('logic')!r}"))

    response = rule.get("response")
    if response is not None:
        if not isinstance(response, dict):
            errors.append(fail(path, "response must be object"))
        elif response.get("candidate_only") is not True:
            errors.append(fail(path, "response.candidate_only must be true; enforcement is out of scope"))

    if support and isinstance(support, dict) and support.get("level") == "unsupported" and rule.get("enabled") is True:
        errors.append(fail(path, "unsupported rules must not be enabled"))

    return errors


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: validate-rule-ir.py <rule.json> [<rule.json> ...]", file=sys.stderr)
        return 2

    all_errors: list[str] = []
    for name in argv[1:]:
        path = Path(name)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - CLI should show parse error directly.
            all_errors.append(fail(path, f"failed to parse JSON: {exc}"))
            continue
        if not isinstance(data, dict):
            all_errors.append(fail(path, "root must be object"))
            continue
        all_errors.extend(validate_rule(path, data))

    if all_errors:
        for error in all_errors:
            print(error, file=sys.stderr)
        return 1

    for name in argv[1:]:
        print(f"ok: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
