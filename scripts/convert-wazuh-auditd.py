#!/usr/bin/env python3
"""Convert local Wazuh auditd XML fixtures into LyFlow HIDS Rule IR."""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def severity_from_level(level: int) -> tuple[int, str]:
    if level >= 12:
        return 95, "critical"
    if level >= 9:
        return 82, "high"
    if level >= 6:
        return 58, "medium"
    return 32, "low"


def stage_from_rule(description: str, groups: list[str], mitre: list[str]) -> str:
    text = " ".join([description, *groups, *mitre]).lower()
    if "sudo" in text or "privilege" in text or "t1548" in text:
        return "privilege_escalation"
    if "brute" in text or "authentication_failed" in text:
        return "initial_access"
    if "user" in text or "account" in text or "t1136" in text:
        return "persistence"
    if "root" in text or "t1078" in text:
        return "initial_access"
    return "execution"


def split_groups(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-")


def build_rule(element: ET.Element, source: Path) -> dict[str, Any]:
    rule_id = element.attrib.get("id", "unknown")
    level = int(element.attrib.get("level", "0") or 0)
    match_text = (element.findtext("match") or element.findtext("regex") or "").strip()
    field = (element.findtext("field") or "").strip()
    description = (element.findtext("description") or f"Wazuh auditd rule {rule_id}").strip()
    groups = split_groups(element.findtext("group") or element.findtext("groups") or "")
    mitre = [node.text.strip() for node in element.findall("./mitre/id") if node.text and node.text.strip()]
    score, severity = severity_from_level(level)
    unsupported_fields = []
    support = "full_supported"
    condition_field = "metadata.line"
    condition_operator = "contains"
    condition_value: Any = match_text or description

    if field:
        condition_field = field
        condition_operator = "exists"
        condition_value = True
        if field == "audit.auid":
            unsupported_fields.append(field)
            support = "unsupported"
    if not match_text and not field:
        support = "unsupported"
        unsupported_fields.append("match.conditions")

    return {
        "kind": "single_event_rule",
        "schema_version": "v1",
        "id": f"wazuh-auditd-{rule_id}",
        "name": description,
        "description": description,
        "category": "hids",
        "enabled": False,
        "source": {
            "origin": "external_subscription",
            "vendor": "Wazuh",
            "license": "GPL-2.0",
            "url": "https://github.com/wazuh/wazuh/tree/master/ruleset/rules",
            "version": "fixture",
            "upstream_id": rule_id,
            "revision": "1",
            "conversion_version": "v1",
            "raw_path": str(source),
            "converted_path": "rules/subscriptions/wazuh-auditd/converted/"
        },
        "support": {
            "level": support,
            "unsupported_fields": unsupported_fields,
            "notes": ["Converted from Wazuh auditd XML fixture"] if support != "unsupported" else ["Requires unsupported auditd field(s)"],
        },
        "classification": {
            "stage": "uncategorized" if support == "unsupported" else stage_from_rule(description, groups, mitre),
            "mitre_tactics": [],
            "mitre_techniques": mitre,
            "confidence": 0.78 if support != "unsupported" else 0.2,
            "rationale": "Mapped from Wazuh groups and MITRE metadata."
        },
        "scoring": {
            "base_score": 0 if support == "unsupported" else score,
            "severity": severity,
            "upstream_score": {"wazuh_level": level},
            "source_reliability": 86,
        },
        "match": {
            "logic": "all",
            "entities": ["host.id", "user.name", "network.src_ip"],
            "conditions": [
                {"field": condition_field, "operator": condition_operator, "value": condition_value}
            ],
        },
        "provenance": [
            {"source": str(source), "rule_id": rule_id, "groups": groups}
        ],
        "response": {
            "candidate_only": True,
            "allowed_candidate_types": ["increase_monitoring", "collect_forensic_bundle", "analyst_review"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--quarantine-report", required=True, type=Path)
    args = parser.parse_args()

    root = ET.fromstring(args.source.read_text(encoding="utf-8"))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    converted = []
    quarantine = []
    for element in root.findall("rule"):
        rule = build_rule(element, args.source)
        target = args.output_dir / f"{slug(rule['id'])}.json"
        target.write_text(json.dumps(rule, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        entry = {
            "id": rule["id"],
            "path": str(target),
            "support_level": rule["support"]["level"],
            "enabled": rule["enabled"],
            "stage": rule["classification"]["stage"],
            "unsupported_fields": rule["support"].get("unsupported_fields", []),
        }
        if rule["support"]["level"] == "unsupported":
            quarantine.append(entry)
        else:
            converted.append(entry)

    report = {
        "schema_version": "v1",
        "source": str(args.source),
        "total": len(converted) + len(quarantine),
        "converted": len(converted),
        "unsupported": len(quarantine),
        "rules": converted + quarantine,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.quarantine_report.parent.mkdir(parents=True, exist_ok=True)
    args.quarantine_report.write_text(json.dumps({"schema_version": "v1", "rules": quarantine}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"ok: converted {len(converted)} Wazuh auditd rules, quarantined {len(quarantine)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
