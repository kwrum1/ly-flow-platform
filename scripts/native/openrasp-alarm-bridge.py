#!/usr/bin/env python3
"""Tail OpenRASP alarm.log and forward alarms to the local LyFlow RASP bridge.

Run on the host that has OpenRASP attached and ly-agent RASP bridge listening.
Environment:
  OPENRASP_ALARM_LOG   default /opt/openrasp/logs/alarm/alarm.log
  LY_RASP_BRIDGE       default http://127.0.0.1:17891/v1/rasp/events
  LY_RASP_TOKEN        bootstrap token, default g5-rasp-token
  LY_RASP_AGENT_ID     default g5-real-agent
  LY_APP_NAME          default openrasp-app
  OPENRASP_START       end|beginning, default end
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


ALARM_LOG = Path(os.environ.get("OPENRASP_ALARM_LOG", "/opt/openrasp/logs/alarm/alarm.log"))
BRIDGE = os.environ.get("LY_RASP_BRIDGE", "http://127.0.0.1:17891/v1/rasp/events")
BOOTSTRAP_TOKEN = os.environ.get("LY_RASP_TOKEN", "g5-rasp-token")
AGENT_ID = os.environ.get("LY_RASP_AGENT_ID", "g5-real-agent")
APP_NAME = os.environ.get("LY_APP_NAME", "openrasp-app")
START = os.environ.get("OPENRASP_START", "end").lower()
CONFIG_URL = BRIDGE.replace("/events", "/config")
current_token = BOOTSTRAP_TOKEN
last_config_refresh = 0.0


def refresh_config() -> None:
    global current_token, AGENT_ID, last_config_refresh
    now = time.time()
    if now - last_config_refresh < 30:
        return
    last_config_refresh = now
    request = urllib.request.Request(CONFIG_URL)
    request.add_header("X-Ly-RASP-Token", BOOTSTRAP_TOKEN)
    request.add_header("X-Lyflow-Agent-ID", AGENT_ID)
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            data = json.loads(response.read().decode())
        current_token = data.get("bridge_token") or current_token
        AGENT_ID = data.get("agent_id") or AGENT_ID
    except Exception:
        pass


def post_event(body: dict) -> bool:
    refresh_config()
    request = urllib.request.Request(BRIDGE, data=json.dumps(body).encode(), method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("X-Ly-RASP-Token", current_token)
    request.add_header("X-Lyflow-Agent-ID", AGENT_ID)
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return 200 <= response.status < 300
    except urllib.error.HTTPError as error:
        if error.code == 401:
            global last_config_refresh
            last_config_refresh = 0.0
        return False
    except Exception:
        return False


def map_alarm(alarm: dict) -> dict:
    attack_type = str(alarm.get("attack_type") or "")
    params = alarm.get("attack_params") or {}
    command = str(params.get("command") or "")
    query = str(params.get("query") or "")
    path = str(params.get("path") or params.get("file") or "")
    url = str(alarm.get("url") or params.get("url") or "")
    evidence = command or query or path or url or str(alarm.get("plugin_message") or "OpenRASP alarm")
    if attack_type in ("command", "command_injection"):
        event_type = "rasp.command"
    elif attack_type in ("sql", "sqli"):
        event_type = "rasp.sql"
    elif attack_type in ("readFile", "writeFile", "deleteFile", "file"):
        event_type = "rasp.file"
    elif attack_type in ("ssrf", "http"):
        event_type = "rasp.http"
    elif "deserial" in attack_type.lower():
        event_type = "rasp.deserialization"
    else:
        event_type = "rasp.command"
    observed = str(alarm.get("event_time") or "")
    try:
        observed = datetime.fromisoformat(observed).astimezone(timezone.utc).isoformat()
    except Exception:
        observed = datetime.now(timezone.utc).isoformat()
    return {
        "event_type": event_type,
        "hook_type": attack_type or "openrasp",
        "language": "java",
        "application": APP_NAME,
        "command": command,
        "cmdline": command,
        "query": query,
        "path": path,
        "url": url,
        "summary": str(alarm.get("plugin_message") or evidence),
        "rule_id": str(alarm.get("plugin_algorithm") or attack_type or "openrasp"),
        "severity": "high" if attack_type in ("command", "sql", "deserialization") else "medium",
        "event_id": str(alarm.get("request_id") or ""),
        "observed_at": observed,
    }


def main() -> int:
    ALARM_LOG.parent.mkdir(parents=True, exist_ok=True)
    ALARM_LOG.touch(exist_ok=True)
    with ALARM_LOG.open("r", encoding="utf-8", errors="replace") as handle:
        if START != "beginning":
            handle.seek(0, os.SEEK_END)
        while True:
            line = handle.readline()
            if not line:
                time.sleep(0.5)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                alarm = json.loads(line)
            except json.JSONDecodeError:
                continue
            if str(alarm.get("event_type") or "") != "attack":
                continue
            body = map_alarm(alarm)
            post_event(body)
            print(json.dumps({"forwarded": body["event_type"], "request_id": body.get("event_id", "")}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(0)
