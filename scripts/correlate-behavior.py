#!/usr/bin/env python3
"""Correlate staged single-event alerts into behavior chains."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def entity_keys(event: dict[str, Any], configured: list[str]) -> list[str]:
    keys = []
    for name in configured:
        value = event.get(name)
        if value:
            keys.append(f"{name}:{value}")
    return keys


def correlate(config: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    window = int(config.get("window_seconds", 3600))
    min_events = int(config.get("min_events", 2))
    min_score = int(config.get("min_total_score", 120))
    required_any = set(config.get("required_any_stage", []))
    entities = config.get("entities", ["src_ip", "host_id"])
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in sorted(events, key=lambda e: int(e.get("timestamp", 0))):
        for key in entity_keys(event, entities):
            buckets[key].append(event)

    alerts = []
    seen_event_sets = set()
    for key, bucket in buckets.items():
        if not bucket:
            continue
        start = int(bucket[0].get("timestamp", 0))
        chain = [e for e in bucket if int(e.get("timestamp", 0)) - start <= window]
        if len(chain) < min_events:
            continue
        stages = [str(e.get("stage", "")) for e in chain]
        total_score = sum(int(e.get("score", 0)) for e in chain)
        if total_score < min_score or not required_any.intersection(stages):
            continue
        event_ids = tuple(sorted(str(e.get("event_id")) for e in chain))
        if event_ids in seen_event_sets:
            continue
        seen_event_sets.add(event_ids)
        alerts.append({
            "behavior_id": f"behavior-{len(alerts)+1}",
            "rule_id": config.get("id"),
            "entity_key": key,
            "stage_chain": stages,
            "event_ids": list(event_ids),
            "total_score": total_score,
            "severity": "critical" if total_score >= 220 else "high" if total_score >= 160 else "medium",
            "response": {"candidate_only": True},
        })
    return alerts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    alerts = correlate(load(args.config), load(args.events))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"schema_version": "v1", "alerts": alerts}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"ok: produced {len(alerts)} behavior alerts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
