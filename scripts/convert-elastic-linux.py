#!/usr/bin/env python3
"""Convert Elastic Linux detection fixtures into LyFlow HIDS Rule IR."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SEVERITY_SCORE = {"critical": 95, "high": 82, "medium": 58, "low": 32}


def slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-")


def threat_metadata(rule: dict[str, Any]) -> tuple[list[str], list[str], str]:
    tactics: list[str] = []
    techniques: list[str] = []
    stage = "execution"
    for threat in rule.get("threat", []):
        tactic = threat.get("tactic", {}) if isinstance(threat, dict) else {}
        tactic_id = tactic.get("id")
        tactic_name = str(tactic.get("name", "")).lower()
        if tactic_id:
            tactics.append(tactic_id)
        for technique in threat.get("technique", []) if isinstance(threat, dict) else []:
            if technique.get("id"):
                techniques.append(technique["id"])
        if "persistence" in tactic_name:
            stage = "persistence"
        elif "execution" in tactic_name:
            stage = "execution"
        elif "privilege" in tactic_name:
            stage = "privilege_escalation"
        elif "lateral" in tactic_name:
            stage = "lateral_movement"
        elif "command" in tactic_name or "exfiltration" in tactic_name:
            stage = "c2_exfiltration"
    return tactics, techniques, stage


def query_conditions(query: str) -> tuple[list[dict[str, Any]], list[str]]:
    unsupported: list[str] = []
    conditions: list[dict[str, Any]] = []
    if "process.command_line" in query:
        conditions.append({"field": "process.command_line", "operator": "regex", "value": query})
    if "process.name" in query:
        conditions.append({"field": "process.name", "operator": "regex", "value": query})
    if "file.path" in query:
        conditions.append({"field": "file.path", "operator": "regex", "value": query})
    if not conditions:
        unsupported.append("elastic.query")
        conditions.append({"field": "elastic.query", "operator": "regex", "value": query})
    return conditions, unsupported


def build_rule(rule: dict[str, Any], source: Path) -> dict[str, Any]:
    rule_id = str(rule.get("rule_id", "unknown"))
    language = str(rule.get("language", "")).lower()
    query_type = str(rule.get("type", "")).lower()
    severity = str(rule.get("severity", "medium")).lower()
    tactics, techniques, stage = threat_metadata(rule)
    query = str(rule.get("query", ""))
    conditions, unsupported_fields = query_conditions(query)
    support = "full_supported"
    notes = ["Converted from Elastic Linux fixture"]
    if language == "eql" and "sequence" in query.lower():
        support = "unsupported"
        unsupported_fields.append("elastic.eql.sequence")
        notes = ["EQL sequence requires behavior correlation conversion and is not a single-event rule"]
    elif query_type not in {"query", "kuery"}:
        support = "partial_supported"
        notes = ["Elastic query type was partially represented as simple field conditions"]

    return {
        "kind": "single_event_rule",
        "schema_version": "v1",
        "id": f"elastic-linux-{slug(rule_id)}",
        "name": str(rule.get("name", rule_id)),
        "description": str(rule.get("name", rule_id)),
        "category": "hids",
        "enabled": False,
        "source": {
            "origin": "external_subscription",
            "vendor": "Elastic",
            "license": "Elastic License 2.0",
            "url": "https://github.com/elastic/detection-rules",
            "version": "fixture",
            "upstream_id": rule_id,
            "revision": "1",
            "conversion_version": "v1",
            "raw_path": str(source),
            "converted_path": "rules/subscriptions/elastic-linux/converted/"
        },
        "support": {"level": support, "unsupported_fields": sorted(set(unsupported_fields)), "notes": notes},
        "classification": {"stage": "uncategorized" if support == "unsupported" else stage, "mitre_tactics": tactics, "mitre_techniques": techniques, "confidence": 0.78 if support != "unsupported" else 0.2, "rationale": "Mapped from Elastic threat metadata and tags."},
        "scoring": {"base_score": 0 if support == "unsupported" else int(rule.get("risk_score", SEVERITY_SCORE.get(severity, 58))), "severity": severity if severity in SEVERITY_SCORE else "medium", "upstream_score": {"elastic_risk_score": rule.get("risk_score")}, "source_reliability": 84},
        "match": {"logic": "any", "entities": ["host.id", "user.name", "process.pid"], "conditions": conditions},
        "provenance": [{"source": str(source), "rule_id": rule_id, "language": language, "query": query, "tags": rule.get("tags", []), "references": rule.get("references", [])}],
        "response": {"candidate_only": True, "allowed_candidate_types": ["increase_monitoring", "collect_forensic_bundle", "analyst_review"]},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--quarantine-report", required=True, type=Path)
    args = parser.parse_args()
    rules = json.loads(args.source.read_text(encoding="utf-8"))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    converted = []
    quarantine = []
    for item in rules:
        rule = build_rule(item, args.source)
        target = args.output_dir / f"{slug(rule['id'])}.json"
        target.write_text(json.dumps(rule, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        entry = {"id": rule["id"], "path": str(target), "support_level": rule["support"]["level"], "enabled": rule["enabled"], "stage": rule["classification"]["stage"], "unsupported_fields": rule["support"].get("unsupported_fields", [])}
        if rule["support"]["level"] == "unsupported":
            quarantine.append(entry)
        else:
            converted.append(entry)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"schema_version": "v1", "source": str(args.source), "total": len(rules), "converted": len(converted), "unsupported": len(quarantine), "rules": converted + quarantine}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.quarantine_report.parent.mkdir(parents=True, exist_ok=True)
    args.quarantine_report.write_text(json.dumps({"schema_version": "v1", "rules": quarantine}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"ok: converted {len(converted)} Elastic Linux rules, quarantined {len(quarantine)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
