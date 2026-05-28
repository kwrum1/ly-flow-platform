#!/usr/bin/env python3
"""Convert the LyFlow-supported subset of Falco YAML rules into Rule IR."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


PRIORITY = {
    "EMERGENCY": (98, "critical"),
    "ALERT": (95, "critical"),
    "CRITICAL": (90, "critical"),
    "ERROR": (82, "high"),
    "WARNING": (58, "medium"),
    "NOTICE": (40, "low"),
    "INFO": (25, "low"),
    "DEBUG": (10, "low"),
}

FIELD_MAP = {
    "proc.name": "process.name",
    "proc.cmdline": "process.command_line",
    "user.name": "user.name",
}
UNSUPPORTED_FIELDS = {"evt.type", "fd.name", "fd.type", "fd.num"}


def slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-")


def parse_fixture(path: Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        if raw.startswith("- rule:"):
            if current:
                rules.append(current)
            current = {"rule": raw.split(":", 1)[1].strip()}
            continue
        if current is None:
            continue
        line = raw.strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        if value.startswith("[") and value.endswith("]"):
            current[key] = [item.strip() for item in value[1:-1].split(",") if item.strip()]
        else:
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            current[key] = value
    if current:
        rules.append(current)
    return rules


def extract_conditions(condition: str) -> tuple[list[dict[str, Any]], list[str]]:
    conditions: list[dict[str, Any]] = []
    unsupported: list[str] = []
    for field in sorted(UNSUPPORTED_FIELDS):
        if re.search(rf"\b{re.escape(field)}\b", condition):
            unsupported.append(field)
    for falco_field, lyflow_field in FIELD_MAP.items():
        if re.search(rf"\b{re.escape(falco_field)}\b", condition):
            conditions.append({"field": lyflow_field, "operator": "regex", "value": condition})
    if not conditions:
        conditions.append({"field": unsupported[0] if unsupported else "falco.condition", "operator": "regex", "value": condition})
    return conditions, sorted(set(unsupported))


def stage_from_tags(tags: list[str], support: str) -> str:
    if support == "unsupported":
        return "uncategorized"
    text = " ".join(tags).lower()
    if "persistence" in text:
        return "persistence"
    if "privilege" in text:
        return "privilege_escalation"
    if "lateral" in text:
        return "lateral_movement"
    if "network" in text or "exfil" in text or "c2" in text:
        return "c2_exfiltration"
    return "execution"


def build_rule(item: dict[str, Any], source: Path) -> dict[str, Any]:
    name = str(item.get("rule", "unknown"))
    condition = str(item.get("condition", ""))
    priority = str(item.get("priority", "INFO")).upper()
    tags = item.get("tags", []) if isinstance(item.get("tags"), list) else []
    conditions, unsupported = extract_conditions(condition)
    support = "unsupported" if unsupported else "full_supported"
    score, severity = PRIORITY.get(priority, (25, "low"))
    return {
        "kind": "single_event_rule",
        "schema_version": "v1",
        "id": f"falco-subset-{slug(name)}",
        "name": name,
        "description": str(item.get("desc", name)),
        "category": "hids",
        "enabled": False,
        "source": {"origin": "external_subscription", "vendor": "Falco Project", "license": "Apache-2.0", "url": "https://github.com/falcosecurity/rules", "version": "fixture", "upstream_id": name, "revision": "1", "conversion_version": "v1", "raw_path": str(source), "converted_path": "rules/subscriptions/falco/converted/"},
        "support": {"level": support, "unsupported_fields": unsupported, "notes": ["Converted from Falco supported subset fixture"] if support != "unsupported" else ["Falco syscall/file-descriptor fields are not exposed by current LyFlow HIDS"]},
        "classification": {"stage": stage_from_tags(tags, support), "mitre_tactics": [], "mitre_techniques": [], "confidence": 0.74 if support != "unsupported" else 0.2, "rationale": "Mapped from Falco tags and supported fields."},
        "scoring": {"base_score": 0 if support == "unsupported" else score, "severity": severity, "upstream_score": {"falco_priority": priority}, "source_reliability": 76},
        "match": {"logic": "all", "entities": ["host.id", "user.name", "process.pid"], "conditions": conditions},
        "provenance": [{"source": str(source), "rule": name, "condition": condition, "output": item.get("output", ""), "tags": tags}],
        "response": {"candidate_only": True, "allowed_candidate_types": ["increase_monitoring", "collect_forensic_bundle", "analyst_review"]},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--quarantine-report", required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    converted = []
    quarantine = []
    for item in parse_fixture(args.source):
        rule = build_rule(item, args.source)
        target = args.output_dir / f"{slug(rule['id'])}.json"
        target.write_text(json.dumps(rule, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        entry = {"id": rule["id"], "path": str(target), "support_level": rule["support"]["level"], "enabled": rule["enabled"], "stage": rule["classification"]["stage"], "unsupported_fields": rule["support"].get("unsupported_fields", [])}
        (quarantine if rule["support"]["level"] == "unsupported" else converted).append(entry)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"schema_version": "v1", "source": str(args.source), "total": len(converted) + len(quarantine), "converted": len(converted), "unsupported": len(quarantine), "rules": converted + quarantine}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.quarantine_report.parent.mkdir(parents=True, exist_ok=True)
    args.quarantine_report.write_text(json.dumps({"schema_version": "v1", "rules": quarantine}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"ok: converted {len(converted)} Falco subset rules, quarantined {len(quarantine)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
