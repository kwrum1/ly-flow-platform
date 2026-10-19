#!/usr/bin/env python3
import hashlib
import json
import ssl
import time
import urllib.request

BASE = "https://127.0.0.1"
CTX = ssl._create_unverified_context()
AGENT = "g5-real-agent"
KEY = open("/opt/ly-agent/etc/agent-identity.yaml").read().split('key: "')[1].split('"')[0]
now = time.time()
events = []
for index, target in enumerate(("10.99.0.2", "10.99.0.3", "10.99.0.4")):
    event_uid = f"lateral-acceptance-{int(now)}-{index}"
    raw_hash = hashlib.sha256(event_uid.encode()).hexdigest()
    events.append({
        "schema_version": "lyflow.security_event.v2",
        "event_uid": event_uid,
        "correlation_id": f"lateral-acceptance-{int(now)}",
        "tenant_id": "default",
        "source": "agent.traffic",
        "event_type": "traffic.flow",
        "timestamps": {
            "event_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 60 + index)),
            "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "ingested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        },
        "entities": {
            "asset": {"id": AGENT, "ip": "10.99.0.1", "hostname": "lyflow-test"},
            "network": {"src_ip": "10.99.0.1", "dst_ip": target, "dst_port": 445, "proto": "tcp"},
        },
        "detection": {
            "rule_id": "lateral-acceptance", "rule_source": "acceptance",
            "severity": "low", "confidence": 0.5,
            "tactic_id": "TA0008", "technique_id": "T1021.002",
            "description": "inert SMB acceptance observation",
        },
        "payload": {"dst_ip": target, "dst_port": 445,
                    "note": "inert acceptance observation for lateral tracker"},
        "raw": {"native_schema": "suricata.eve.v7", "native_event_id": event_uid,
                "adapter": "acceptance.lateral", "payload_sha256": raw_hash},
        "quality_flags": ["normalized"],
        "governance": {
            "classification": "internal",
            "retention": {"policy_id": "security-event-30d", "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 30*86400))},
            "encryption": {"required": True, "algorithm": "AES-256-GCM", "key_ref": "kms://lyflow/security-event"},
            "access_policy_id": "security-event-read",
            "deletion_policy_id": "security-event-delete",
            "export_policy_id": "security-event-export",
        },
    })
body = json.dumps({"events": events}).encode()
request = urllib.request.Request(BASE + "/api/v2/ingest/events", data=body, method="POST")
request.add_header("Content-Type", "application/json")
request.add_header("X-Lyflow-Agent-ID", AGENT)
request.add_header("Authorization", "Bearer " + KEY)
try:
    with urllib.request.urlopen(request, context=CTX, timeout=30) as response:
        print(response.status, response.read().decode())
except urllib.error.HTTPError as error:
    print(error.code, error.read().decode())
print("uids", [event["event_uid"] for event in events])
