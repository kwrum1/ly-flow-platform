#!/usr/bin/env python3
import json
import ssl
import urllib.request

BASE = "https://127.0.0.1"
CTX = ssl._create_unverified_context()

def request(method, path, data=None, token=None, headers=None):
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=30) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        return error.code, error.read(), error.headers

def json_request(method, path, body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    status, raw, _ = request(method, path, data, token, {"Content-Type": "application/json"})
    try:
        return status, json.loads(raw.decode())
    except Exception:
        return status, raw

status, payload = json_request("POST", "/api/v1/auth/login", {"username": "admin", "password": "AdminTest2!"})
token = payload["data"]["token"]
status, payload = json_request("GET", "/api/v1/response/actions", token=token)
print("actions", status, payload.get("data", {}).get("total"))
status, payload = json_request("GET", "/api/v2/events?limit=5", token=token)
items = payload.get("data", {}).get("items", [])
event_uids = [item.get("event_uid") for item in items if item.get("event_uid")]
print("events", status, event_uids[:3])
status, raw, _ = request("POST", "/api/v1/evidence/artifacts", b"inert evidence pcap bytes", token,
                         {"Content-Type": "application/vnd.tcpdump.pcap", "X-Lyflow-Artifact-Name": "acceptance.pcap"})
artifact = json.loads(raw.decode())
print("artifact", status, json.dumps(artifact, ensure_ascii=False)[:300])
artifact_id = artifact.get("data", {}).get("id")
body = {"incident_id": "evidence-acceptance", "agent_id": "g5-real-agent", "event_uids": event_uids[:1], "artifact_ids": [artifact_id], "note": "acceptance"}
status, bundle = json_request("POST", "/api/v1/evidence/bundles", body, token)
print("bundle", status, json.dumps(bundle, ensure_ascii=False)[:500])
bundle_id = bundle.get("data", {}).get("id") if isinstance(bundle, dict) else None
if bundle_id:
    status, downloaded, _ = request("GET", f"/api/v1/evidence/bundles/{bundle_id}/download", token=token)
    print("download", status, len(downloaded))
    status, listed = json_request("GET", "/api/v1/evidence/bundles", token=token)
    print("list", status, listed.get("data", {}).get("total"))
