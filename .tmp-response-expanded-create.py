#!/usr/bin/env python3
import json
import ssl
import urllib.request

BASE = "https://127.0.0.1"
CTX = ssl._create_unverified_context()
def call(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path, data=None if body is None else json.dumps(body).encode(), method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=30) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode())

def login(user, password):
    _, payload = call("POST", "/api/v1/auth/login", {"username": user, "password": password})
    return payload["data"]["token"]

admin = login("admin", "AdminTest2!")
approver = login("approver", "ApproverTest1!")
pid = open("/tmp/lyflow-response-sleep.pid").read().strip()
actions = [
    ("file_delete", "/tmp/lyflow-response/sample.txt", "file acceptance"),
    ("process_kill", pid, "process acceptance"),
    ("account_disable", "lyflow-response-test", "account acceptance"),
]
for action, target, reason in actions:
    status, payload = call("POST", "/api/v1/response/actions", {
        "incident_id": "response-expanded-acceptance", "agent_id": "g5-real-agent",
        "action": action, "target": target, "reason": reason, "ttl_seconds": 300,
    }, token=admin)
    if status != 200:
        print(action, "create", status, payload)
        continue
    record = payload["data"]
    status, payload = call("POST", f"/api/v1/response/actions/{record['id']}/approve", {}, token=approver)
    print(action, record["id"], status, payload.get("data", {}).get("status"))
