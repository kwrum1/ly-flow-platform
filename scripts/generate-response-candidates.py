#!/usr/bin/env python3
"""Generate response candidates from entity risk summaries without enforcement."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def candidate_types(entity: dict) -> list[str]:
    score = int(entity.get("risk_score", 0))
    stages = set(entity.get("stages", []))
    actions = ["analyst_review", "increase_monitoring"]
    if score >= 70 and entity.get("entity", "").startswith("src_ip:"):
        actions.append("suggest_ip_block")
    if score >= 85 and {"execution", "persistence", "privilege_escalation"}.intersection(stages):
        actions.append("collect_forensic_bundle")
        actions.append("suggest_host_isolation")
    return actions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--risk", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    risk = json.loads(args.risk.read_text(encoding="utf-8"))
    candidates = []
    for idx, entity in enumerate(risk.get("entities", []), start=1):
        score = int(entity.get("risk_score", 0))
        if score < 45:
            continue
        candidates.append({
            "candidate_id": f"response-candidate-{idx}",
            "entity": entity.get("entity"),
            "risk_score": score,
            "severity": entity.get("severity"),
            "status": "pending",
            "candidate_only": True,
            "requires_approval": True,
            "action_types": candidate_types(entity),
            "reason": "High-risk entity summary from staged events and behavior chains",
            "evidence_ids": {"events": entity.get("event_ids", []), "behaviors": entity.get("behavior_ids", [])},
            "must_not_execute": ["iptables", "nftables", "kill", "quarantine", "isolate"],
        })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"schema_version": "v1", "candidates": candidates}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"ok: generated {len(candidates)} response candidates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
