#!/usr/bin/env python3
"""Generate or cleanup deterministic LyFlow architecture fixtures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCENARIOS = ROOT / "scenarios.json"


def load_pack() -> dict:
    return json.loads(SCENARIOS.read_text(encoding="utf-8"))


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def generate(out_dir: Path) -> None:
    pack = load_pack()
    events = pack["events"]
    by_stream: dict[str, list[dict]] = {}
    for event in events:
        by_stream.setdefault(event["stream"], []).append(event)

    for stream, rows in sorted(by_stream.items()):
        write_jsonl(out_dir / f"{stream.replace(':', '_')}.jsonl", rows)

    incident = {
        "id": "lyfixture-incident-001",
        "incident_id": "lyfixture-incident-001",
        "chain_id": pack["chain_id"],
        "severity": "critical",
        "status": "open",
        "affected_asset": pack["host_id"],
        "title": "LyFlow deterministic multi-stage attack chain",
        "recommended_action": "Isolate lyfixture-host-01, review RASP SQLi evidence, and verify suspicious process containment.",
        "stages": [
            {"name": "Initial Access", "source_module": "dpi", "summary": "suspicious upload/admin access"},
            {"name": "Execution", "source_module": "runtime", "summary": "bash/curl process spawned"},
            {"name": "Application Exploit", "source_module": "rasp", "summary": "SQL injection probe"},
        ],
        "evidence": events,
    }
    write_jsonl(out_dir / "incidents.jsonl", [incident])
    write_jsonl(out_dir / "timeline_lyfixture-chain-001.jsonl", sorted(events, key=lambda item: item["timestamp"]))


def cleanup(out_dir: Path) -> None:
    if not out_dir.exists():
        return
    for path in out_dir.glob("*.jsonl"):
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        kept = [row for row in rows if not str(row.get("id", row.get("incident_id", ""))).startswith("lyfixture-")]
        write_jsonl(path, kept)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=".sisyphus/evidence/fixtures", help="Output directory for generated JSONL files")
    parser.add_argument("--cleanup", action="store_true", help="Remove only lyfixture-* records from generated JSONL files")
    args = parser.parse_args()
    out_dir = Path(args.out)

    if args.cleanup:
      cleanup(out_dir)
    else:
      generate(out_dir)

    print(f"fixture_output={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
