#!/usr/bin/env python3
"""Classify LyFlow single-event rules into the seven attack stages."""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from typing import Any


STAGES = {
    "recon",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "lateral_movement",
    "c2_exfiltration",
}

MITRE_STAGE = {
    "TA0043": "recon",
    "TA0001": "initial_access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege_escalation",
    "TA0008": "lateral_movement",
    "TA0011": "c2_exfiltration",
    "TA0010": "c2_exfiltration",
    "T1110": "initial_access",
    "T1078": "initial_access",
    "T1190": "initial_access",
    "T1059": "execution",
    "T1204": "execution",
    "T1136": "persistence",
    "T1547": "persistence",
    "T1548": "privilege_escalation",
    "T1068": "privilege_escalation",
    "T1021": "lateral_movement",
    "T1071": "c2_exfiltration",
}

KEYWORDS = [
    ("recon", ["scan", "scanner", "probe", "discovery", "admin access", "endpoint access"]),
    ("initial_access", ["login", "brute", "phishing", "fraud", "upload", "unauthorized", "webshell"]),
    ("execution", ["exec", "command", "shell", "download", "payload", "sql injection", "sqli"]),
    ("persistence", ["cron", "systemd", "authorized_keys", "persistence", "backdoor", "user account", "useradd"]),
    ("privilege_escalation", ["sudo", "privilege", "escalation", "root", "ld.so.preload"]),
    ("lateral_movement", ["lateral", "smb", "rdp", "ssh movement", "winrm"]),
    ("c2_exfiltration", ["c2", "beacon", "trojan", "tunnel", "exfil", "mining", "ja3", "dns tunnel"]),
]


def load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    data["__path"] = str(path)
    return data


def classify(rule: dict[str, Any]) -> tuple[str, float, str]:
    existing = rule.get("classification", {}).get("stage")
    support = rule.get("support", {}).get("level")
    enabled = bool(rule.get("enabled"))
    if support == "unsupported":
        return "uncategorized", 0.2, "unsupported rule remains uncategorized for quarantine"
    if existing in STAGES:
        return existing, max(float(rule.get("classification", {}).get("confidence", 0.7) or 0.7), 0.7), "kept existing valid stage"

    tactics = rule.get("classification", {}).get("mitre_tactics", []) or []
    techniques = rule.get("classification", {}).get("mitre_techniques", []) or []
    for token in [*tactics, *techniques]:
        token = str(token)
        for prefix, stage in MITRE_STAGE.items():
            if token.startswith(prefix):
                return stage, 0.86, f"mapped from MITRE {token}"

    haystack = " ".join([
        str(rule.get("name", "")),
        str(rule.get("description", "")),
        json.dumps(rule.get("provenance", []), ensure_ascii=False),
        json.dumps(rule.get("match", {}), ensure_ascii=False),
    ]).lower()
    for stage, words in KEYWORDS:
        if any(word in haystack for word in words):
            return stage, 0.68, f"mapped from keyword bucket {stage}"
    if not enabled:
        return "execution", 0.45, "disabled rule defaulted to execution pending review"
    return "execution", 0.5, "active rule defaulted to execution because no stronger signal was found"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("rules", nargs="+", type=Path)
    args = parser.parse_args()
    if args.output_dir.exists():
        shutil.rmtree(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    counts = {stage: 0 for stage in sorted(STAGES | {"uncategorized"})}
    low_confidence = []
    written = []
    for path in args.rules:
        rule = load(path)
        stage, confidence, rationale = classify(rule)
        rule.pop("__path", None)
        rule.setdefault("classification", {})
        rule["classification"].update({"stage": stage, "confidence": confidence, "rationale": rationale})
        counts[stage] = counts.get(stage, 0) + 1
        if confidence < 0.6:
            low_confidence.append({"id": rule.get("id"), "stage": stage, "confidence": confidence, "rationale": rationale})
        target = args.output_dir / f"{rule.get('category', 'rule')}-{rule.get('id')}.json"
        target.write_text(json.dumps(rule, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        written.append({"id": rule.get("id"), "path": str(target), "stage": stage, "confidence": confidence})

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"schema_version": "v1", "total": len(written), "counts": counts, "low_confidence": low_confidence, "rules": written}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"ok: classified {len(written)} rules across {len([v for v in counts.values() if v])} stage buckets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
