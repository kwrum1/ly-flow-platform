#!/usr/bin/env python3
"""Migrate existing LyFlow internal HIDS/DPI rules into Rule IR.

RASP rules are intentionally skipped because RASP is deferred by the current
HIDS + DPI plan.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


STAGE_GROUP_PREFIX = "attack_chain:"


def slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-") or "rule"


def scalar(value: str) -> Any:
    value = value.strip()
    if value == "true":
        return True
    if value == "false":
        return False
    if value.isdigit():
        return int(value)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def parse_xdr_yaml(path: Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_list: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        start = re.match(r"^\s{2}- id:\s*(.+)$", raw)
        if start:
            if current:
                rules.append(current)
            current = {"id": scalar(start.group(1)), "mitre": [], "groups": []}
            current_list = None
            continue
        if current is None:
            continue
        list_name = re.match(r"^\s{4}(mitre|groups):\s*$", raw)
        if list_name:
            current_list = list_name.group(1)
            continue
        list_item = re.match(r"^\s{6}-\s*(.+)$", raw)
        if list_item and current_list:
            current.setdefault(current_list, []).append(scalar(list_item.group(1)))
            continue
        field = re.match(r"^\s{4}([a-zA-Z_]+):\s*(.+)$", raw)
        if field:
            current[field.group(1)] = scalar(field.group(2))
            current_list = None
    if current:
        rules.append(current)
    return rules


def level_to_score(level: int) -> tuple[int, str]:
    if level >= 13:
        return 95, "critical"
    if level >= 9:
        return 78, "high"
    if level >= 6:
        return 55, "medium"
    return 30, "low"


def stage_from_groups(groups: list[str], default: str = "execution") -> str:
    mapping = {"initial_access": "initial_access", "execution": "execution", "persistence": "persistence", "privilege_escalation": "privilege_escalation", "lateral_movement": "lateral_movement", "discovery": "recon", "c2": "c2_exfiltration", "command_and_control": "c2_exfiltration"}
    for group in groups:
        if isinstance(group, str) and group.startswith(STAGE_GROUP_PREFIX):
            value = group.split(":", 1)[1]
            return mapping.get(value, default)
    text = " ".join(str(g) for g in groups).lower()
    for key, value in mapping.items():
        if key in text:
            return value
    return default


def build_xdr_ir(rule: dict[str, Any], source_path: Path) -> dict[str, Any] | None:
    source = str(rule.get("source", "hids")).lower()
    if source == "rasp":
        return None
    category = "dpi" if source == "dpi" else "hids"
    level = int(rule.get("level", 5) or 5)
    score, severity = level_to_score(level)
    groups = rule.get("groups", []) if isinstance(rule.get("groups"), list) else []
    match_field = "metadata.line" if category == "hids" and source not in {"runtime"} else "metadata.command_line" if source == "runtime" else "domain"
    if category == "dpi":
        match_field = "http.uri" if "admin" in str(rule.get("name", "")).lower() else "domain"
    return {
        "kind": "single_event_rule",
        "schema_version": "v1",
        "id": f"lyflow-internal-{slug(str(rule.get('id')))}",
        "name": str(rule.get("name", rule.get("id"))),
        "description": str(rule.get("description", "")),
        "category": category,
        "enabled": False,
        "source": {"origin": "internal", "vendor": "LyFlow", "license": "Proprietary", "url": "lyflow://rules/internal", "version": "2026.05", "upstream_id": str(rule.get("id")), "revision": "1", "conversion_version": "v1", "raw_path": str(source_path), "converted_path": f"rules/internal/{category}/lyflow/generated/"},
        "support": {"level": "partial_supported" if category == "dpi" else "full_supported", "unsupported_fields": [], "notes": ["Migrated from existing LyFlow internal XDR rule"]},
        "classification": {"stage": stage_from_groups(groups), "mitre_tactics": [m for m in rule.get("mitre", []) if str(m).startswith("TA")], "mitre_techniques": [m for m in rule.get("mitre", []) if str(m).startswith("T") and not str(m).startswith("TA")], "confidence": 0.75, "rationale": "Mapped from existing LyFlow groups and MITRE tags."},
        "scoring": {"base_score": score, "severity": severity, "upstream_score": {"lyflow_level": level}, "source_reliability": 92},
        "match": {"logic": "all", "entities": ["host.id", "network.src_ip", "user.name"], "conditions": [{"field": match_field, "operator": "regex" if rule.get("regex") else "contains", "value": str(rule.get("match", ""))}]},
        "provenance": [{"source": str(source_path), "rule_id": rule.get("id"), "groups": groups}],
        "response": {"candidate_only": True, "allowed_candidate_types": ["increase_monitoring", "collect_forensic_bundle", "analyst_review"]},
    }


def parse_suricata_lines(path: Path) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    buffer = ""
    start = 0
    for idx, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not buffer:
            start = idx
        buffer += line.rstrip("\\").strip() + " "
        if not line.endswith("\\"):
            logical.append((start, buffer.strip()))
            buffer = ""
    return logical


def build_dpi_ir(line: str, source_path: Path, line_no: int) -> dict[str, Any] | None:
    match = re.search(r"msg:\s*\"([^\"]+)\".*?sid:\s*([0-9]+).*?rev:\s*([0-9]+)", line)
    if not match:
        return None
    msg, sid, rev = match.groups()
    protocol = line.split()[1] if len(line.split()) > 1 else "tcp"
    return {
        "kind": "single_event_rule", "schema_version": "v1", "id": f"lyflow-internal-dpi-{sid}", "name": msg, "description": msg, "category": "dpi", "enabled": False,
        "source": {"origin": "internal", "vendor": "LyFlow", "license": "Proprietary", "url": "lyflow://rules/internal/dpi", "version": "2026.05", "upstream_id": sid, "revision": rev, "conversion_version": "v1", "raw_path": str(source_path), "converted_path": "rules/internal/dpi/lyflow/generated/"},
        "support": {"level": "partial_supported", "unsupported_fields": [], "notes": ["Migrated from LyFlow custom Suricata-like DPI rule"]},
        "classification": {"stage": "c2_exfiltration" if any(x in msg.lower() for x in ["c2", "trojan", "beacon"]) else "initial_access" if any(x in msg.lower() for x in ["scanner", "webshell", "unauthorized"]) else "execution", "mitre_tactics": [], "mitre_techniques": [], "confidence": 0.7, "rationale": "Mapped from LyFlow custom DPI rule message."},
        "scoring": {"base_score": 70, "severity": "high", "upstream_score": {"sid": int(sid)}, "source_reliability": 92},
        "match": {"logic": "all", "entities": ["network.src_ip", "network.dst_ip", "domain"], "conditions": [{"field": "network.protocol", "operator": "equals", "value": protocol}], "suricata": {"sid": int(sid), "rev": int(rev), "msg": msg, "raw": line}},
        "provenance": [{"source": str(source_path), "sid": int(sid), "rev": int(rev), "line": line_no}],
        "response": {"candidate_only": True, "allowed_candidate_types": ["increase_monitoring", "analyst_review"]},
    }


def write_ir(rule: dict[str, Any], root: Path) -> Path:
    category = rule["category"]
    target = root / category / "lyflow" / "generated" / f"{slug(rule['id'])}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(rule, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    converted = []
    skipped = []
    for path in args.paths:
        if path.suffix in {".yaml", ".yml"}:
            for item in parse_xdr_yaml(path):
                ir = build_xdr_ir(item, path)
                if ir is None:
                    skipped.append({"source": str(path), "rule_id": item.get("id"), "reason": "rasp_deferred"})
                    continue
                target = write_ir(ir, args.output_root)
                converted.append({"id": ir["id"], "path": str(target), "category": ir["category"], "stage": ir["classification"]["stage"], "enabled": ir["enabled"]})
        elif path.suffix == ".rules":
            for line_no, line in parse_suricata_lines(path):
                ir = build_dpi_ir(line, path, line_no)
                if ir:
                    target = write_ir(ir, args.output_root)
                    converted.append({"id": ir["id"], "path": str(target), "category": ir["category"], "stage": ir["classification"]["stage"], "enabled": ir["enabled"]})
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"schema_version": "v1", "converted": len(converted), "skipped": len(skipped), "rules": converted, "skipped_rules": skipped}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"ok: migrated {len(converted)} LyFlow internal rules, skipped {len(skipped)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
