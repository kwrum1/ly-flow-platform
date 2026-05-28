#!/usr/bin/env python3
"""Aggregate event and behavior scores by risky entity."""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def decay(timestamp: int, now: int, half_life_seconds: int) -> float:
    age = max(0, now - timestamp)
    return math.pow(0.5, age / half_life_seconds)


def aggregate(events: list[dict[str, Any]], behaviors: list[dict[str, Any]], now: int, half_life: int) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = defaultdict(lambda: {"score": 0.0, "event_ids": set(), "behavior_ids": set(), "stages": set(), "latest_timestamp": 0})
    event_timestamps = {event.get("event_id"): int(event.get("timestamp", now)) for event in events}
    for event in events:
        timestamp = int(event.get("timestamp", now))
        score = int(event.get("score", 0)) * decay(timestamp, now, half_life)
        for key in ["src_ip", "host_id", "user", "domain"]:
            value = event.get(key)
            if not value:
                continue
            bucket = buckets[f"{key}:{value}"]
            if event.get("event_id") in bucket["event_ids"]:
                continue
            bucket["score"] += score
            bucket["event_ids"].add(event.get("event_id"))
            bucket["stages"].add(event.get("stage"))
            bucket["latest_timestamp"] = max(bucket["latest_timestamp"], timestamp)
    for behavior in behaviors:
        key = behavior.get("entity_key")
        if not key:
            continue
        bucket = buckets[key]
        evidence_times = [event_timestamps[eid] for eid in behavior.get("event_ids", []) if eid in event_timestamps]
        behavior_time = max(evidence_times) if evidence_times else now
        bucket["score"] += int(behavior.get("total_score", 0)) * 0.35 * decay(behavior_time, now, half_life)
        bucket["behavior_ids"].add(behavior.get("behavior_id"))
        for stage in behavior.get("stage_chain", []):
            bucket["stages"].add(stage)
    result = []
    for entity, bucket in buckets.items():
        score = min(100, round(bucket["score"]))
        result.append({"entity": entity, "risk_score": score, "severity": "critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 45 else "low", "event_ids": sorted(bucket["event_ids"]), "behavior_ids": sorted(bucket["behavior_ids"]), "stages": sorted(s for s in bucket["stages"] if s), "latest_timestamp": bucket["latest_timestamp"]})
    return sorted(result, key=lambda item: item["risk_score"], reverse=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--behaviors", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--now", type=int, default=1778717200)
    parser.add_argument("--half-life", type=int, default=3600)
    args = parser.parse_args()
    events = load(args.events)
    behaviors = load(args.behaviors).get("alerts", [])
    entities = aggregate(events, behaviors, args.now, args.half_life)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"schema_version": "v1", "entities": entities}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"ok: aggregated {len(entities)} risky entities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
