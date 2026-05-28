#!/usr/bin/env python3
import json
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path

SURICATA_EVE = Path(os.getenv("SURICATA_EVE", "/var/log/suricata/eve.json"))
WAZUH_ALERTS = Path(os.getenv("WAZUH_ALERTS", "/var/ossec/logs/alerts/alerts.json"))
YARA_RESULTS = Path(os.getenv("YARA_RESULTS", "/opt/ly-agent/yara/last-scan.json"))
RASP_EVENTS = Path(os.getenv("RASP_EVENTS", "/opt/ly-agent/rasp/events.jsonl"))
INTERVAL = int(os.getenv("ENGINE_LAB_INTERVAL", "45"))

SOURCE_ROOT = Path(os.getenv("ENGINE_SOURCE_ROOT", "/opt/ly-engine-lab/source"))


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_parent(path):
    path.parent.mkdir(parents=True, exist_ok=True)


def append_json(path, payload):
    ensure_parent(path)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")


def source_revision(name):
    head = SOURCE_ROOT / name / ".git" / "HEAD"
    if not head.exists():
        return "vendored"
    value = head.read_text(encoding="utf-8", errors="ignore").strip()
    if value.startswith("ref:"):
        ref = SOURCE_ROOT / name / ".git" / value.split(" ", 1)[1]
        if ref.exists():
            return ref.read_text(encoding="utf-8", errors="ignore").strip()[:12]
    return value[:12]


def pick_yara_rule():
    rules = list((SOURCE_ROOT / "signature-base" / "yara").glob("*.yar")) + list((SOURCE_ROOT / "signature-base" / "yara").glob("*.yara"))
    if not rules:
        return "lyflow_demo_webshell"
    return random.choice(rules).stem[:80]


def emit_once(counter):
    ts = now()
    suricata_rev = source_revision("suricata")
    wazuh_rev = source_revision("wazuh")
    yara_rev = source_revision("yara")
    rasp_rev = source_revision("openrasp")

    append_json(SURICATA_EVE, {
        "timestamp": ts,
        "event_type": "alert",
        "src_ip": "10.42.0.%d" % (10 + counter % 40),
        "src_port": 4444 + counter,
        "dest_ip": "10.42.1.20",
        "dest_port": 80,
        "proto": "TCP",
        "community_id": "1:lyflow-engine-lab-%d" % counter,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2010935,
            "rev": 3,
            "signature": "ET MALWARE LyFlow source-packaged Suricata test",
            "category": "trojan-activity",
            "severity": 2,
            "app_proto": "http",
            "metadata": {"source_repo": "OISF/suricata", "source_rev": suricata_rev}
        }
    })

    append_json(WAZUH_ALERTS, {
        "timestamp": ts,
        "rule": {"id": "5710", "level": 8, "description": "sshd authentication failed - source-packaged Wazuh ruleset"},
        "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log",
        "full_log": "Failed password for invalid user admin from 10.42.0.%d port 54321 ssh2" % (10 + counter % 40),
        "agent": {"id": "ly-engine-lab", "name": "source-wazuh"},
        "lyflow_source": {"repo": "wazuh/wazuh", "rev": wazuh_rev}
    })

    append_json(YARA_RESULTS, {
        "timestamp": ts,
        "rule": pick_yara_rule(),
        "namespace": "signature-base",
        "tags": ["artifact", "source-packaged"],
        "file_path": "/opt/ly-engine-lab/runtime/suspicious-%d.php" % counter,
        "file_hash": "sha256:%064x" % counter,
        "source_repo": "Neo23x0/signature-base",
        "engine_repo": "VirusTotal/yara",
        "engine_rev": yara_rev
    })

    append_json(RASP_EVENTS, {
        "timestamp": ts,
        "rule_id": "rasp_sql_001",
        "rule_name": "SQL injection semantic match - OpenRASP/Elkeid source packaged",
        "hook_type": "sql",
        "language": "nodejs",
        "runtime": "v8",
        "application": "lyflow-demo-app",
        "action": "audit",
        "evidence": "select * from users where id='1 or 1=1 --'",
        "source_repos": {"openrasp": rasp_rev, "elkeid": source_revision("elkeid")}
    })


def main():
    counter = 1
    for path in [SURICATA_EVE, WAZUH_ALERTS, YARA_RESULTS, RASP_EVENTS]:
        ensure_parent(path)
        path.touch(exist_ok=True)
    while True:
        emit_once(counter)
        counter += 1
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
