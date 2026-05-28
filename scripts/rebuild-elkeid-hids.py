#!/usr/bin/env python3
"""One-time rebuild of local Elkeid HIDS YAML rules into LyFlow Rule IR.

This parser targets the repository's curated `rules/hids/elkeid_hids_rules.yaml`
shape. It intentionally does not download upstream rules and does not activate
the rebuilt rules by default.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SEVERITY_SCORE = {
    "critical": 95,
    "high": 82,
    "medium": 58,
    "low": 32,
}

SEVERITY_BUCKET = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

CATEGORY_STAGE = {
    "backdoor": "persistence",
    "bruteforce": "initial_access",
    "binary_hijack": "persistence",
    "network_anomaly": "c2_exfiltration",
    "privilege_escalation": "privilege_escalation",
    "lateral_movement": "lateral_movement",
}

UNSUPPORTED_HOOK_TYPES = {"kernel"}


def scalar(value: str) -> Any:
    value = value.strip()
    if value == "true":
        return True
    if value == "false":
        return False
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def parse_rules(path: Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_rules = False
    in_mitre = False
    in_patterns = False

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if stripped == "rules:":
            in_rules = True
            continue
        if not in_rules or not stripped or stripped.startswith("#"):
            continue

        match = re.match(r"^\s{2}- id:\s*(.+)$", line)
        if match:
            if current:
                rules.append(current)
            current = {"id": scalar(match.group(1)), "patterns": [], "mitre": {}}
            in_mitre = False
            in_patterns = False
            continue
        if current is None:
            continue

        if re.match(r"^\s{4}patterns:\s*$", line):
            in_patterns = True
            in_mitre = False
            continue
        if re.match(r"^\s{4}mitre:\s*$", line):
            in_mitre = True
            in_patterns = False
            continue
        if in_patterns:
            pattern_value = re.match(r"^\s{8}value:\s*(.+)$", line)
            if pattern_value:
                current["patterns"].append(scalar(pattern_value.group(1)))
            if re.match(r"^\s{4}\w", line):
                in_patterns = False
        if in_mitre:
            mitre_value = re.match(r"^\s{6}(tactic|technique):\s*(.+)$", line)
            if mitre_value:
                current["mitre"][mitre_value.group(1)] = scalar(mitre_value.group(2))
            if re.match(r"^\s{4}\w", line):
                in_mitre = False

        field = re.match(r"^\s{4}([a-zA-Z_]+):\s*(.+)$", line)
        if field and field.group(1) not in {"patterns", "mitre"}:
            current[field.group(1)] = scalar(field.group(2))

    if current:
        rules.append(current)
    return rules


def slug(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-")
    return cleaned or "rule"


def support_for(rule: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    hook = str(rule.get("hook_type", "")).lower()
    if hook in UNSUPPORTED_HOOK_TYPES:
        return "unsupported", ["evt.type"], [f"Elkeid hook_type={hook} requires telemetry not exposed by current LyFlow HIDS"]
    if not rule.get("patterns"):
        return "unsupported", ["match.conditions"], ["No patterns were found in source rule"]
    return "full_supported", [], ["Converted from local Elkeid curated YAML patterns"]


def field_for(rule: dict[str, Any], support: str) -> str:
    if support == "unsupported":
        return "evt.type"
    category = str(rule.get("category", ""))
    if category in {"bruteforce"}:
        return "metadata.line"
    if category in {"binary_hijack", "backdoor", "privilege_escalation"}:
        return "metadata.command_line"
    if category == "network_anomaly":
        return "metadata.command_line"
    return "metadata.command_line"


def build_ir(rule: dict[str, Any], source_path: Path) -> dict[str, Any]:
    severity = str(rule.get("severity", "medium")).lower()
    support, unsupported_fields, notes = support_for(rule)
    field = field_for(rule, support)
    # One-time rebuilt Elkeid rules become internal assets, but they are not
    # activated by the import step. Later compile/rollout tasks decide enablement
    # after support, deduplication, scoring, and review are complete.
    enabled = False
    rule_id = str(rule.get("id", "unknown"))
    category = str(rule.get("category", ""))
    mitre = rule.get("mitre", {}) if isinstance(rule.get("mitre"), dict) else {}
    stage = CATEGORY_STAGE.get(category, "uncategorized" if support == "unsupported" else "execution")
    patterns = [str(value) for value in rule.get("patterns", [])]
    conditions = [
        {"field": field, "operator": "regex", "value": value}
        for value in patterns
    ]
    if not conditions:
        conditions = [{"field": field, "operator": "exists", "value": True}]

    return {
        "kind": "single_event_rule",
        "schema_version": "v1",
        "id": f"elkeid-rebuilt-{rule_id.lower()}",
        "name": str(rule.get("name", rule_id)),
        "description": str(rule.get("description", "")),
        "category": "hids",
        "enabled": enabled,
        "source": {
            "origin": "rebuilt_internal",
            "vendor": "ByteDance Elkeid",
            "license": "Apache-2.0",
            "url": "https://github.com/bytedance/Elkeid",
            "version": "local-2024-01-15",
            "upstream_id": rule_id,
            "revision": "1",
            "conversion_version": "v1",
            "raw_path": str(source_path),
            "converted_path": "rules/internal/hids/elkeid-rebuilt/"
        },
        "support": {
            "level": support,
            "unsupported_fields": unsupported_fields,
            "notes": notes,
        },
        "classification": {
            "stage": stage,
            "mitre_tactics": [mitre.get("tactic")] if mitre.get("tactic") else [],
            "mitre_techniques": [mitre.get("technique")] if mitre.get("technique") else [],
            "confidence": 0.82 if support != "unsupported" else 0.25,
            "rationale": f"Mapped from Elkeid category {category or 'unknown'}."
        },
        "scoring": {
            "base_score": 0 if support == "unsupported" else SEVERITY_SCORE.get(severity, 58),
            "severity": SEVERITY_BUCKET.get(severity, "medium"),
            "source_reliability": 78,
        },
        "match": {
            "logic": "any",
            "entities": ["host.id", "user.name", "process.pid"],
            "conditions": conditions,
        },
        "provenance": [
            {
                "source": str(source_path),
                "rule_id": rule_id,
                "category": category,
                "hook_type": str(rule.get("hook_type", "")),
            }
        ],
        "response": {
            "candidate_only": True,
            "allowed_candidate_types": ["collect_forensic_bundle", "increase_monitoring", "analyst_review"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--quarantine-report", required=True, type=Path)
    args = parser.parse_args()

    source_rules = parse_rules(args.source)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    active = []
    quarantine = []

    for source_rule in source_rules:
        ir = build_ir(source_rule, args.source)
        target = args.output_dir / f"{slug(ir['id'])}.json"
        target.write_text(json.dumps(ir, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        entry = {
            "id": ir["id"],
            "path": str(target),
            "support_level": ir["support"]["level"],
            "enabled": ir["enabled"],
            "stage": ir["classification"]["stage"],
            "unsupported_fields": ir["support"].get("unsupported_fields", []),
        }
        if ir["support"]["level"] == "unsupported":
            quarantine.append(entry)
        else:
            active.append(entry)

    report = {
        "schema_version": "v1",
        "source": str(args.source),
        "total": len(source_rules),
        "converted": len(active),
        "unsupported": len(quarantine),
        "rules": active + quarantine,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.quarantine_report.parent.mkdir(parents=True, exist_ok=True)
    args.quarantine_report.write_text(json.dumps({"schema_version": "v1", "rules": quarantine}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"ok: rebuilt {len(source_rules)} Elkeid rules ({len(active)} converted, {len(quarantine)} unsupported)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
