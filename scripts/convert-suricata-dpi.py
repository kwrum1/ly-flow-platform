#!/usr/bin/env python3
"""Convert Suricata/ET Open style rules into LyFlow DPI Rule IR."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


BUFFER_FIELD = {
    "dns.query": "dns.query",
    "http.host": "http.host",
    "http.uri": "http.uri",
    "tls.sni": "tls.sni",
}
SUPPORTED_OPTIONS = set(BUFFER_FIELD) | {"msg", "sid", "rev", "classtype", "priority", "metadata", "reference", "content", "pcre", "flow"}
PARTIAL_OPTIONS = {"threshold"}


def slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-")


def parse_options(raw: str) -> list[str]:
    options: list[str] = []
    current = []
    in_quote = False
    escape = False
    for ch in raw:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == "\\":
            current.append(ch)
            escape = True
            continue
        if ch == '"':
            in_quote = not in_quote
            current.append(ch)
            continue
        if ch == ";" and not in_quote:
            item = "".join(current).strip()
            if item:
                options.append(item)
            current = []
            continue
        current.append(ch)
    item = "".join(current).strip()
    if item:
        options.append(item)
    return options


def option_key(option: str) -> str:
    return option.split(":", 1)[0].strip()


def option_value(option: str) -> str:
    if ":" not in option:
        return ""
    value = option.split(":", 1)[1].strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def parse_rule(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    match = re.match(r"^(\w+)\s+(\w+)\s+(.+?)\s+(->|<>)\s+(.+?)\s+\((.*)\)$", line)
    if not match:
        return None
    action, protocol, src, direction, dst, options_raw = match.groups()
    options = parse_options(options_raw)
    parsed: dict[str, Any] = {"action": action, "protocol": protocol, "src": src, "direction": direction, "dst": dst, "options": options}
    for option in options:
        key = option_key(option)
        value = option_value(option)
        if key in {"msg", "classtype", "metadata", "reference", "content", "pcre", "flow"}:
            parsed.setdefault(key, []).append(value)
        elif key in {"sid", "rev", "priority"}:
            try:
                parsed[key] = int(value)
            except ValueError:
                parsed[key] = value
        else:
            parsed.setdefault("flags", []).append(key)
    return parsed


def stage_from_rule(rule: dict[str, Any]) -> str:
    text = " ".join(str(x) for x in [rule.get("protocol", ""), *(rule.get("msg") or []), *(rule.get("classtype") or [])]).lower()
    if "trojan" in text or "tunnel" in text or "c2" in text or "dns" in text:
        return "c2_exfiltration"
    if "fraud" in text or "phishing" in text:
        return "initial_access"
    if "malware" in text or "download" in text:
        return "execution"
    return "recon"


def build_conditions(rule: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    active_field = BUFFER_FIELD.get(f"{rule.get('protocol')}.query")
    conditions: list[dict[str, Any]] = [{"field": "network.protocol", "operator": "equals", "value": rule.get("protocol")}]
    partial: list[str] = []
    unsupported: list[str] = []
    for flag in rule.get("flags", []):
        if flag in BUFFER_FIELD:
            active_field = BUFFER_FIELD[flag]
        elif flag in PARTIAL_OPTIONS:
            partial.append(flag)
        elif flag not in SUPPORTED_OPTIONS:
            unsupported.append(flag)
    for content in rule.get("content", []):
        field = active_field or "domain"
        conditions.append({"field": field, "operator": "contains", "value": content})
    for pcre in rule.get("pcre", []):
        field = active_field or "domain"
        pattern = pcre.strip("/") if pcre.startswith("/") else pcre
        conditions.append({"field": field, "operator": "regex", "value": pattern})
    return conditions, sorted(set(partial)), sorted(set(unsupported))


def build_ir(rule: dict[str, Any], source: Path, line_no: int) -> dict[str, Any]:
    sid = rule.get("sid", f"line-{line_no}")
    rev = rule.get("rev", 1)
    msg = (rule.get("msg") or [f"Suricata rule {sid}"])[0]
    conditions, partial, unsupported = build_conditions(rule)
    support = "unsupported" if unsupported else "partial_supported" if partial or any(c["field"] in {"dns.query", "http.host", "http.uri", "tls.sni"} for c in conditions) else "full_supported"
    priority = int(rule.get("priority", 2) or 2)
    base_score = 0 if support == "unsupported" else max(20, 95 - priority * 12)
    severity = "critical" if base_score >= 85 else "high" if base_score >= 70 else "medium" if base_score >= 45 else "low"
    return {
        "kind": "single_event_rule",
        "schema_version": "v1",
        "id": f"suricata-etopen-{sid}",
        "name": msg,
        "description": msg,
        "category": "dpi",
        "enabled": False,
        "source": {"origin": "external_subscription", "vendor": "Proofpoint Emerging Threats Open", "license": "ET Open Ruleset License", "url": "rules/suricata/et-open.rules", "version": "v1.0.0", "upstream_id": str(sid), "revision": str(rev), "conversion_version": "v1", "raw_path": str(source), "converted_path": "rules/subscriptions/suricata/converted/"},
        "support": {"level": support, "unsupported_fields": unsupported, "notes": ["Converted from Suricata/ET Open rule", *([f"Partially supported option: {x}" for x in partial])]},
        "classification": {"stage": "uncategorized" if support == "unsupported" else stage_from_rule(rule), "mitre_tactics": [], "mitre_techniques": [], "confidence": 0.72 if support != "unsupported" else 0.2, "rationale": "Mapped from Suricata protocol/msg/classtype."},
        "scoring": {"base_score": base_score, "severity": severity, "upstream_score": {"suricata_priority": priority}, "source_reliability": 80},
        "match": {"logic": "all", "entities": ["network.src_ip", "network.dst_ip", "dns.query", "http.host", "tls.sni"], "conditions": conditions, "suricata": {"action": rule.get("action"), "protocol": rule.get("protocol"), "src": rule.get("src"), "direction": rule.get("direction"), "dst": rule.get("dst"), "msg": msg, "sid": sid, "rev": rev, "classtype": rule.get("classtype", []), "priority": rule.get("priority"), "metadata": rule.get("metadata", []), "reference": rule.get("reference", []), "content": rule.get("content", []), "pcre": rule.get("pcre", []), "flow": rule.get("flow", []), "raw_options": rule.get("options", [])}},
        "provenance": [{"source": str(source), "sid": sid, "rev": rev, "line": line_no}],
        "response": {"candidate_only": True, "allowed_candidate_types": ["suggest_ip_block", "increase_monitoring", "analyst_review"]},
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
    for idx, line in enumerate(args.source.read_text(encoding="utf-8").splitlines(), start=1):
        parsed = parse_rule(line)
        if not parsed:
            continue
        ir = build_ir(parsed, args.source, idx)
        target = args.output_dir / f"{slug(ir['id'])}.json"
        target.write_text(json.dumps(ir, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        entry = {"id": ir["id"], "path": str(target), "support_level": ir["support"]["level"], "enabled": ir["enabled"], "stage": ir["classification"]["stage"], "unsupported_fields": ir["support"].get("unsupported_fields", [])}
        (quarantine if ir["support"]["level"] == "unsupported" else converted).append(entry)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"schema_version": "v1", "source": str(args.source), "total": len(converted) + len(quarantine), "converted": len(converted), "unsupported": len(quarantine), "rules": converted + quarantine}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.quarantine_report.parent.mkdir(parents=True, exist_ok=True)
    args.quarantine_report.write_text(json.dumps({"schema_version": "v1", "rules": quarantine}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"ok: converted {len(converted)} Suricata DPI rules, quarantined {len(quarantine)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
