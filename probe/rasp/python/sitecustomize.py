"""LyFlow Python RASP probe.

Loaded via PYTHONPATH/sitecustomize. It emits monitor-mode telemetry for high-risk
runtime sinks to the local ly-agent RASP bridge. It does not block execution.
"""

from __future__ import annotations

import builtins
import json
import os
import pickle
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable


BRIDGE = os.environ.get("LY_RASP_BRIDGE", "http://127.0.0.1:17891/v1/rasp/events")
TOKEN = os.environ.get("LY_RASP_TOKEN", "")
APP = os.environ.get("LY_APP_NAME", "python-app")
_EMITTING = threading.local()
AGENT_ID = os.environ.get("LY_RASP_AGENT_ID", "") or os.environ.get("RASP_AGENT_ID", "")
CONFIG_URL = BRIDGE.rsplit("/v1/rasp/", 1)[0] + "/v1/rasp/config"
_POLICY = {"mode": "monitor", "block_on_hit": False, "version": 0, "policy_id": "", "loaded_at": 0.0}


class RASPBlocked(PermissionError):
    """Raised when the signed policy promoted this runtime to blocking."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _refresh_policy(force: bool = False) -> None:
    global TOKEN
    if not TOKEN or not AGENT_ID:
        return
    now = time.monotonic()
    if not force and now - float(_POLICY.get("loaded_at") or 0.0) < 30.0:
        return
    request = urllib.request.Request(
        CONFIG_URL,
        method="GET",
        headers={"X-Ly-RASP-Token": TOKEN, "X-Lyflow-Agent-ID": AGENT_ID},
    )
    try:
        raw = _orig_urlopen(request, timeout=0.5).read(65537)
    except Exception:
        return
    if len(raw) > 65536:
        return
    try:
        body = json.loads(raw.decode("utf-8"))
    except Exception:
        return
    signed = {
        "agent_id": body.get("agent_id"),
        "bridge_token": body.get("bridge_token"),
        "expires_at": body.get("expires_at"),
        "limits": body.get("limits"),
        "policy_id": body.get("policy_id"),
        "policy_mode": body.get("policy_mode"),
        "policy_version": body.get("policy_version"),
        "schema_version": body.get("schema_version"),
        "block_on_hit": body.get("block_on_hit"),
    }
    import hashlib
    import hmac

    expected = hmac.new(TOKEN.encode("utf-8"), _canonical(signed), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(body.get("config_signature") or "")):
        return
    if signed["policy_mode"] not in {"monitor", "off", "block"} or not isinstance(signed["block_on_hit"], bool):
        return
    # The bootstrap token only authorizes config; the response carries the
    # rotated token used for event ingestion.
    TOKEN = str(signed["bridge_token"] or TOKEN)
    _POLICY.update({
        "mode": signed["policy_mode"],
        "block_on_hit": bool(signed["block_on_hit"] and signed["policy_mode"] == "block"),
        "version": signed["policy_version"] or 0,
        "policy_id": signed["policy_id"] or "",
        "loaded_at": now,
    })


def _looks_like_command_injection(command: str) -> bool:
    value = command.lower()
    direct = (
        "rm -rf", "mkfs", ":(){", "nc -e", "/dev/tcp/", "chmod 777 /", "dd if=",
        "base64 -d | sh", "curl | sh", "wget | sh", "bash -i", "sh -i",
    )
    if any(marker in value for marker in direct):
        return True
    chained = any(separator in value for separator in (";", "&&", "||", "$(", "`"))
    dangerous = ("rm ", "curl ", "wget ", "nc ", "bash ", "sh -c", "python -c", "cat /etc/")
    return chained and any(marker in value for marker in dangerous)


def _sink_blockable(hook_type: str, payload: dict[str, Any]) -> bool:
    if hook_type == "sql":
        return _looks_like_sql_injection(payload.get("query", ""))
    if hook_type == "exec":
        return _looks_like_command_injection(str(payload.get("command", "")))
    if hook_type == "file":
        path = str(payload.get("path", ""))
        mode = str(payload.get("mode", "r"))
        if any(marker in mode for marker in ("w", "a", "x", "+")):
            return False
        return path.startswith(("/etc/shadow", "/proc/self/environ", "/root/.ssh/", "/root/.bash_history"))
    if hook_type == "ssrf":
        url = str(payload.get("url", "")).lower()
        return url.startswith(("file://", "gopher://")) or any(
            marker in url for marker in ("169.254.169.254", "metadata.google.internal")
        )
    return False


def _decide(hook_type: str, payload: dict[str, Any]) -> tuple[bool, bool]:
    _refresh_policy()
    if _POLICY["mode"] != "block" or not _sink_blockable(hook_type, payload):
        return False, False
    if _POLICY["block_on_hit"]:
        return True, False
    return False, True


def _enforce_with_context(hook_type: str, payload: dict[str, Any]) -> None:
    blocked = emit_with_context(hook_type, payload)
    if blocked:
        raise RASPBlocked(f"LyFlow RASP blocked {hook_type}: {payload.get('sink', hook_type)}")


def emit(hook_type: str, payload: dict[str, Any]) -> bool:
    if getattr(_EMITTING, "active", False):
        return False
    blocked, would_block = _decide(hook_type, payload)
    _EMITTING.active = True
    try:
        normalized = normalize_payload(hook_type, payload)
        body = {
            "event_id": uuid.uuid4().hex,
            "event_type": f"rasp.{hook_type}",
            "language": "python",
            "runtime": "cpython",
            "application": APP,
            "hook_type": hook_type,
            "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "blocked": blocked,
            "would_block": would_block,
            "policy_id": _POLICY.get("policy_id", ""),
            "policy_version": _POLICY.get("version", 0),
            **normalized,
        }
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(BRIDGE, data=data, method="POST", headers={"Content-Type": "application/json"})
        if TOKEN:
            req.add_header("X-Ly-RASP-Token", TOKEN)
        if AGENT_ID:
            req.add_header("X-Lyflow-Agent-ID", AGENT_ID)
        try:
            _orig_urlopen(req, timeout=0.5).read()
        except Exception:
            pass
        return blocked
    finally:
        _EMITTING.active = False



def normalize_payload(hook_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    if "command" in out and "cmdline" not in out:
        out["cmdline"] = out["command"]
    if "cmdline" in out and "command" not in out:
        out["command"] = out["cmdline"]
    if "sql" in out and "query" not in out:
        out["query"] = out["sql"]
    if "file" in out and "path" not in out:
        out["path"] = out["file"]
    if "address" in out and "url" not in out:
        out["url"] = out["address"]
    for key in ("query", "command", "cmdline", "path", "url"):
        value = out.get(key)
        if value and "payload" not in out:
            out["payload"] = str(value)
        if value and "message" not in out:
            out["message"] = str(value)
    out.setdefault("rule_field_contract", ["query", "command", "cmdline", "path", "url", "payload", "message"])
    return out

_orig_popen = subprocess.Popen
_orig_system = os.system
_orig_spawnl = os.spawnl
_orig_spawnlp = getattr(os, "spawnlp", None)
_orig_open = builtins.open
_orig_create_connection = socket.create_connection
_orig_urlopen = urllib.request.urlopen
_orig_import = builtins.__import__
_orig_pickle_load = pickle.load
_orig_pickle_loads = pickle.loads

_PATCHED: set[str] = set()


def _request_context() -> dict[str, str]:
    out: dict[str, str] = {}
    for key, target in {
        "REQUEST_METHOD": "http_method",
        "PATH_INFO": "http_path",
        "REQUEST_URI": "http_path",
        "HTTP_HOST": "http_host",
        "HTTP_X_FORWARDED_FOR": "xff",
        "REMOTE_ADDR": "source_ip",
    }.items():
        value = os.environ.get(key)
        if value and target not in out:
            out[target] = value
    return out


def emit_with_context(hook_type: str, payload: dict[str, Any]) -> bool:
    enriched = {**_request_context(), **payload}
    return emit(hook_type, enriched)


def _looks_like_sql_injection(query: Any) -> bool:
    value = str(query).lower()
    return any(marker in value for marker in ("union select", " or 1=1", "sleep(", "benchmark(", "information_schema", "load_file("))


def _wrap_db_cursor_method(method: Callable[..., Any], sink: str) -> Callable[..., Any]:
    def wrapper(self: Any, query: Any, *args: Any, **kwargs: Any):
        if _looks_like_sql_injection(query):
            emit_with_context("sql", {"query": str(query), "sink": sink})
        return method(self, query, *args, **kwargs)
    return wrapper


def _patch_sqlite3(module: Any) -> None:
    _patch_dbapi_module(module, "sqlite3")


def _patch_dbapi_module(module: Any, name: str) -> None:
    if name in _PATCHED:
        return
    connect = getattr(module, "connect", None)
    if not callable(connect):
        return
    def connect_wrapper(*args: Any, **kwargs: Any):
        conn = connect(*args, **kwargs)
        return _DBConnectionProxy(conn, name)
    try:
        setattr(module, "connect", connect_wrapper)
        _PATCHED.add(name)
    except Exception:
        pass


class _DBConnectionProxy:
    def __init__(self, conn: Any, module_name: str):
        self._conn = conn
        self._module_name = module_name
    def cursor(self, *args: Any, **kwargs: Any):
        return _DBCursorProxy(self._conn.cursor(*args, **kwargs), self._module_name)
    def execute(self, query: Any, *args: Any, **kwargs: Any):
        if _looks_like_sql_injection(query):
            _enforce_with_context("sql", {"query": str(query), "sink": f"{self._module_name}.Connection.execute"})
        return self._conn.execute(query, *args, **kwargs)
    def executemany(self, query: Any, *args: Any, **kwargs: Any):
        if _looks_like_sql_injection(query):
            _enforce_with_context("sql", {"query": str(query), "sink": f"{self._module_name}.Connection.executemany"})
        return self._conn.executemany(query, *args, **kwargs)
    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


class _DBCursorProxy:
    def __init__(self, cursor: Any, module_name: str):
        self._cursor = cursor
        self._module_name = module_name
    def execute(self, query: Any, *args: Any, **kwargs: Any):
        if _looks_like_sql_injection(query):
            _enforce_with_context("sql", {"query": str(query), "sink": f"{self._module_name}.Cursor.execute"})
        return self._cursor.execute(query, *args, **kwargs)
    def executemany(self, query: Any, *args: Any, **kwargs: Any):
        if _looks_like_sql_injection(query):
            _enforce_with_context("sql", {"query": str(query), "sink": f"{self._module_name}.Cursor.executemany"})
        return self._cursor.executemany(query, *args, **kwargs)
    def __iter__(self):
        return iter(self._cursor)
    def __getattr__(self, name: str) -> Any:
        return getattr(self._cursor, name)


def _patch_module(name: str, module: Any) -> None:
    if name == "sqlite3":
        _patch_sqlite3(module)
    elif name in {"pymysql", "MySQLdb", "psycopg2", "pg8000"}:
        _patch_dbapi_module(module, name)


def _import(name: str, globals: Any = None, locals: Any = None, fromlist: tuple[str, ...] = (), level: int = 0):
    module = _orig_import(name, globals, locals, fromlist, level)
    root = name.split(".", 1)[0]
    target = sys.modules.get(root, module)
    _patch_module(root, target)
    return module


def _popen(*args: Any, **kwargs: Any):
    command = args[0] if args else kwargs.get("args", "")
    if isinstance(command, (list, tuple)):
        command = " ".join(map(str, command))
    _enforce_with_context("exec", {"command": str(command), "sink": "subprocess.Popen"})
    return _orig_popen(*args, **kwargs)


def _system(command: str):
    _enforce_with_context("exec", {"command": command, "sink": "os.system"})
    return _orig_system(command)


def _spawnl(mode: int, path: str, *args: Any):
    command = " ".join([path, *map(str, args)])
    _enforce_with_context("exec", {"command": command, "sink": "os.spawnl"})
    return _orig_spawnl(mode, path, *args)


def _spawnlp(mode: int, file: str, *args: Any):
    command = " ".join([file, *map(str, args)])
    _enforce_with_context("exec", {"command": command, "sink": "os.spawnlp"})
    return _orig_spawnlp(mode, file, *args)


def _open(file: Any, mode: str = "r", *args: Any, **kwargs: Any):
    path = str(file)
    # Writes are normal application behavior. Only sensitive reads are RASP
    # signals; otherwise every temp file becomes a false positive.
    if path.startswith(("/etc/shadow", "/proc/self/environ", "/root/.ssh/", "/root/.bash_history")):
        payload = {"path": path, "mode": mode, "sink": "builtins.open"}
        if _sink_blockable("file", payload):
            _enforce_with_context("file", payload)
        else:
            emit_with_context("file", payload)
    return _orig_open(file, mode, *args, **kwargs)


def _create_connection(address: Any, *args: Any, **kwargs: Any):
    # Only metadata endpoints are SSRF-relevant. Reporting every socket,
    # including the probe's own bridge call, creates a self-amplifying flood.
    text = str(address).lower()
    if "169.254.169.254" in text or "metadata.google.internal" in text:
        emit_with_context("network", {"address": str(address), "url": str(address), "sink": "socket.create_connection"})
    return _orig_create_connection(address, *args, **kwargs)


def _urlopen(url: Any, *args: Any, **kwargs: Any):
    target = getattr(url, "full_url", url)
    text = str(target)
    parsed = urllib.parse.urlparse(text)
    if parsed.hostname in {"127.0.0.1", "localhost", "169.254.169.254"} or parsed.scheme in {"file", "gopher"}:
        payload = {"url": text, "sink": "urllib.request.urlopen"}
        if _sink_blockable("ssrf", payload):
            _enforce_with_context("ssrf", payload)
        else:
            emit_with_context("ssrf", payload)
    return _orig_urlopen(url, *args, **kwargs)


def _pickle_load(file: Any, *args: Any, **kwargs: Any):
    emit_with_context("deserialization", {"payload": "pickle.load", "sink": "pickle.load"})
    return _orig_pickle_load(file, *args, **kwargs)


def _pickle_loads(data: Any, *args: Any, **kwargs: Any):
    emit_with_context("deserialization", {"payload": "pickle.loads", "sink": "pickle.loads"})
    return _orig_pickle_loads(data, *args, **kwargs)


subprocess.Popen = _popen
os.system = _system
os.spawnl = _spawnl
if _orig_spawnlp is not None:
    os.spawnlp = _spawnlp
builtins.open = _open
socket.create_connection = _create_connection
urllib.request.urlopen = _urlopen
builtins.__import__ = _import
pickle.load = _pickle_load
pickle.loads = _pickle_loads
try:
    import sqlite3 as _sqlite3
    _patch_sqlite3(_sqlite3)
except Exception:
    pass
