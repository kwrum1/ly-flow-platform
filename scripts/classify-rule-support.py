#!/usr/bin/env python3
"""Classify LyFlow Rule IR files by telemetry field support."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ORDER = {
    "full_supported": 0,
    "partial_supported": 1,
    "unsupported": 2,
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def classify_rule(policy: dict[str, Any], path: Path) -> dict[str, Any]:
    rule = load_json(path)
    category = rule.get("category", "")
    fields = policy.get("field_support", {}).get(category, {})
    support_level = "full_supported"
    unsupported_fields: list[str] = []
    partial_fields: list[str] = []

    for condition in rule.get("match", {}).get("conditions", []):
        field = condition.get("field")
        level = fields.get(field, "unsupported")
        if ORDER[level] > ORDER[support_level]:
            support_level = level
        if level == "unsupported":
            unsupported_fields.append(field)
        elif level == "partial_supported":
            partial_fields.append(field)

    declared = rule.get("support", {}).get("level")
    if declared == "unsupported":
        support_level = "unsupported"
    elif declared == "partial_supported" and support_level == "full_supported":
        support_level = "partial_supported"

    enabled_allowed = support_level != "unsupported"
    return {
        "path": str(path),
        "id": rule.get("id"),
        "category": category,
        "declared_support": declared,
        "computed_support": support_level,
        "enabled": bool(rule.get("enabled")),
        "enabled_allowed": enabled_allowed,
        "unsupported_fields": sorted(set(unsupported_fields)),
        "partial_fields": sorted(set(partial_fields)),
        "quarantine": support_level == "unsupported",
        "reason": "unsupported telemetry fields" if unsupported_fields or support_level == "unsupported" else "",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--quarantine-report", type=Path)
    parser.add_argument("rules", nargs="+", type=Path)
    args = parser.parse_args()

    policy = load_json(args.policy)
    results = [classify_rule(policy, path) for path in args.rules]
    errors = [r for r in results if r["computed_support"] == "unsupported" and r["enabled"]]

    report = {
        "schema_version": "v1",
        "total": len(results),
        "counts": {
            "full_supported": sum(1 for r in results if r["computed_support"] == "full_supported"),
            "partial_supported": sum(1 for r in results if r["computed_support"] == "partial_supported"),
            "unsupported": sum(1 for r in results if r["computed_support"] == "unsupported"),
        },
        "rules": results,
    }

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))

    if args.quarantine_report:
        quarantine = {
            "schema_version": "v1",
            "rules": [r for r in results if r["quarantine"]],
        }
        args.quarantine_report.parent.mkdir(parents=True, exist_ok=True)
        args.quarantine_report.write_text(json.dumps(quarantine, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if errors:
        for error in errors:
            print(f"unsupported rule is enabled: {error['id']} ({error['path']})")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
