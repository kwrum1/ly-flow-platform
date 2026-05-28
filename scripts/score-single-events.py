#!/usr/bin/env python3
"""Compute normalized single-event scores for LyFlow Rule IR."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any


SEVERITY_BASE = {"low": 25, "medium": 50, "high": 75, "critical": 90}
SUPPORT_FACTOR = {"full_supported": 1.0, "partial_supported": 0.85, "unsupported": 0.0}
STAGE_WEIGHT = {"recon": 0, "initial_access": 4, "execution": 6, "persistence": 8, "privilege_escalation": 10, "lateral_movement": 10, "c2_exfiltration": 12, "uncategorized": -10}


def bucket(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def score_rule(rule: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    support = rule.get("support", {}).get("level", "unsupported")
    if support == "unsupported":
        return 0, {"reason": "unsupported rules do not produce active scores", "active": False}
    scoring = rule.get("scoring", {})
    severity = scoring.get("severity", "medium")
    base = int(scoring.get("base_score", SEVERITY_BASE.get(severity, 50)) or 0)
    source_reliability = int(scoring.get("source_reliability", 75) or 75)
    confidence = float(rule.get("classification", {}).get("confidence", 0.6) or 0.6)
    stage = rule.get("classification", {}).get("stage", "uncategorized")
    support_factor = SUPPORT_FACTOR.get(support, 0.0)
    source_component = round((source_reliability - 75) * 0.2)
    confidence_component = round((confidence - 0.5) * 20)
    stage_component = STAGE_WEIGHT.get(stage, 0)
    score = round((base + source_component + confidence_component + stage_component) * support_factor)
    score = max(0, min(100, score))
    return score, {"reason": "severity + source reliability + support + confidence + stage", "active": True, "components": {"base": base, "source_component": source_component, "confidence_component": confidence_component, "stage_component": stage_component, "support_factor": support_factor}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("rules", nargs="+", type=Path)
    args = parser.parse_args()
    if args.output_dir.exists():
        shutil.rmtree(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for path in args.rules:
        rule = json.loads(path.read_text(encoding="utf-8"))
        score, detail = score_rule(rule)
        rule.setdefault("scoring", {})
        original = rule["scoring"].copy()
        rule["scoring"].update({"normalized_score": score, "severity": bucket(score), "active_score": detail["active"], "score_detail": detail, "original_scoring": original})
        target = args.output_dir / f"{rule.get('category')}-{rule.get('id')}.json"
        target.write_text(json.dumps(rule, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        written.append({"id": rule.get("id"), "path": str(target), "score": score, "severity": rule["scoring"]["severity"], "active_score": detail["active"]})
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"schema_version": "v1", "total": len(written), "rules": written, "top": sorted(written, key=lambda item: item["score"], reverse=True)[:20]}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"ok: scored {len(written)} single-event rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
