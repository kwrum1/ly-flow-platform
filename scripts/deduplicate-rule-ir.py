#!/usr/bin/env python3
"""Deduplicate LyFlow Rule IR files while preserving provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


SOURCE_RANK = {
    "LyFlow": 0,
    "ByteDance Elkeid": 1,
    "Wazuh": 2,
    "Elastic": 3,
    "Falco Project": 4,
    "Proofpoint Emerging Threats Open": 5,
}


def load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    data["__path"] = str(path)
    return data


def normalized_conditions(rule: dict[str, Any]) -> str:
    conditions = rule.get("match", {}).get("conditions", [])
    normalized = []
    for item in conditions:
        normalized.append({"field": str(item.get("field", "")).lower(), "operator": str(item.get("operator", "")).lower(), "value": str(item.get("value", "")).lower().strip()})
    return json.dumps(sorted(normalized, key=lambda x: (x["field"], x["operator"], x["value"])), ensure_ascii=False, sort_keys=True)


def fingerprint(rule: dict[str, Any]) -> str:
    payload = "|".join([rule.get("category", ""), rule.get("classification", {}).get("stage", ""), normalized_conditions(rule)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def rank(rule: dict[str, Any]) -> tuple[int, int, str]:
    vendor = rule.get("source", {}).get("vendor", "")
    score = int(rule.get("scoring", {}).get("base_score", 0) or 0)
    return (SOURCE_RANK.get(vendor, 99), -score, rule.get("id", ""))


def merge_group(group: list[dict[str, Any]], fp: str) -> tuple[dict[str, Any], dict[str, Any]]:
    ordered = sorted(group, key=rank)
    winner = json.loads(json.dumps(ordered[0]))
    winner.pop("__path", None)
    provenance = []
    source_ids = []
    for rule in ordered:
        source_ids.append(rule.get("id"))
        provenance.extend(rule.get("provenance", []))
        provenance.append({"source": rule.get("__path"), "rule_id": rule.get("id"), "vendor": rule.get("source", {}).get("vendor")})
    winner["provenance"] = provenance
    winner.setdefault("dedup", {})
    winner["dedup"].update({"fingerprint": fp, "merged_rule_ids": source_ids, "winner_reason": "source precedence then score"})
    return winner, {"fingerprint": fp, "winner": winner.get("id"), "merged_rule_ids": source_ids, "count": len(group)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("rules", nargs="+", type=Path)
    args = parser.parse_args()
    groups: dict[str, list[dict[str, Any]]] = {}
    for path in args.rules:
        rule = load(path)
        if rule.get("support", {}).get("level") == "unsupported":
            # Unsupported rules remain visible in quarantine reports and are not compiled here.
            continue
        groups.setdefault(fingerprint(rule), []).append(rule)
    if args.output_dir.exists():
        shutil.rmtree(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    merged_report = []
    conflicts = []
    written = []
    for fp, group in sorted(groups.items()):
        if len(group) > 1:
            stages = {r.get("classification", {}).get("stage") for r in group}
            categories = {r.get("category") for r in group}
            if len(stages) > 1 or len(categories) > 1:
                conflicts.append({"fingerprint": fp, "rule_ids": [r.get("id") for r in group], "reason": "stage/category mismatch"})
                continue
        rule, report = merge_group(group, fp)
        target = args.output_dir / f"{rule['category']}-{rule['id']}.json"
        target.write_text(json.dumps(rule, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        written.append({"id": rule.get("id"), "path": str(target), "fingerprint": fp})
        if len(group) > 1:
            merged_report.append(report)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"schema_version": "v1", "input_rules": len(args.rules), "output_rules": len(written), "merged_groups": merged_report, "conflicts": conflicts, "written": written}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"ok: wrote {len(written)} deduplicated rules, merged {len(merged_report)} groups, conflicts {len(conflicts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
