"""Request-level RASP hook (OWASP CRS virtual patching).

Two integration styles are supported:

* ``RASPWSGIMiddleware`` / ``RASPASGIMiddleware`` wrap the application and
  inspect the request before application code runs.
* ``inspect_http_request(...)`` is a framework-neutral helper for Django,
  Flask, FastAPI or custom servers.

The hook is monitor-first. It only raises :class:`~ly_rasp.blocking.RASPBlockedError`
when the signed policy is ``block``, the server promoted it (``block_on_hit``)
and the policy has not expired. In dry-run it reports ``would_block=true`` and
lets the request continue.
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, replace
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from .blocking import RASPBlockedError
from .config import RASPConfig, effective_mode, get_config, load_config, should_block
from .correlation import claim_event, request_scope
from .reporter import Reporter, get_reporter, set_reporter
from .request_rules import (
    DEFAULT_PACK_PATH,
    PACK_PATH_ENV,
    RequestLimits,
    RequestMatch,
    RequestView,
    RulePack,
    RulePackError,
    load_pack,
    match_request,
)

REQUEST_HOOK_ENV = "LY_RASP_REQUEST_HOOK"
PATH_ENV = PACK_PATH_ENV
PACK_REFRESH_SECONDS = 60.0

ATTACK_TYPES = {
    "sqli": "sql_injection",
    "xss": "xss",
    "path_traversal": "sensitive_file_access",
    "lfi": "sensitive_file_access",
    "rfi": "ssrf",
    "rce": "command_injection",
    "webshell": "webshell",
    "scanner": "scanner",
    "deserialization": "deserialize_injection",
}


class RASPRequestBlocked(RASPBlockedError):
    """RASPBlockedError carrying the request rule that triggered the block."""

    def __init__(self, attack_type: str, rule_id: str = "") -> None:
        super().__init__(attack_type, "request")
        self.rule_id = rule_id


@dataclass(frozen=True)
class RequestInspection:
    request_id: str
    enabled: bool
    mode: str
    matches: Tuple[RequestMatch, ...] = ()
    blocked: bool = False
    would_block: bool = False
    reason: str = ""

    @property
    def detected(self) -> bool:
        return bool(self.matches)


def _hook_enabled(config: Optional[RASPConfig], explicit: Optional[bool]) -> bool:
    if explicit is not None:
        return explicit
    if config is not None and hasattr(config, "request_hook_enabled"):
        return bool(config.request_hook_enabled)
    return os.environ.get(REQUEST_HOOK_ENV, "true").strip().lower() in {"1", "true", "yes", "on"}


def _configured_path(config: Optional[RASPConfig], explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    if config is not None and getattr(config, "request_rules_path", ""):
        return str(config.request_rules_path)
    return os.environ.get(PATH_ENV) or DEFAULT_PACK_PATH


def _limits(pack: RulePack, config: Optional[RASPConfig]) -> RequestLimits:
    limits = pack.limits
    max_body = getattr(config, "request_max_body_bytes", 0) if config is not None else 0
    if isinstance(max_body, int) and max_body > 0:
        limits = replace(limits, max_body_bytes=min(limits.max_body_bytes, max_body))
    return limits


class _PackProvider:
    """Loads the pack lazily, refreshes it periodically and retries on failure."""

    def __init__(self, pack: Optional[RulePack] = None, path: Optional[str] = None) -> None:
        self._pack = pack
        self._fixed = pack is not None
        self._path = path
        self._last_attempt = 0.0
        self._last_success = 0.0
        self._last_error = ""

    @property
    def last_error(self) -> str:
        return self._last_error

    def get(self, config: Optional[RASPConfig]) -> Optional[RulePack]:
        if self._fixed:
            return self._pack
        now = time.monotonic()
        if self._pack is not None and now - self._last_success < PACK_REFRESH_SECONDS:
            return self._pack
        if self._last_attempt > 0 and now - self._last_attempt < PACK_REFRESH_SECONDS:
            return self._pack
        self._last_attempt = now
        try:
            self._pack = load_pack(_configured_path(config, self._path))
            self._last_success = now
            self._last_error = ""
        except RulePackError as error:
            self._last_error = str(error)
            # Keep serving the last good pack through a transient read error.
            return self._pack
        return self._pack


def _event_mode(blocked: bool, would_block: bool) -> str:
    if blocked:
        return "protect"
    return "dry_run" if would_block else "monitor"


def _ensure_reporter() -> Optional[Reporter]:
    reporter = get_reporter()
    if reporter is not None:
        return reporter
    config = get_config()
    if config is None:
        return None
    try:
        reporter = Reporter(config)
        reporter.start()
        set_reporter(reporter)
        return reporter
    except Exception:
        return None


def _report_match(
    view: RequestView,
    pack: RulePack,
    match: RequestMatch,
    blocked: bool,
    would_block: bool,
) -> bool:
    reporter = _ensure_reporter()
    if reporter is None:
        return False
    if not claim_event(match.category):
        # A sink hook or another request rule for the same request already
        # produced an event for this attack category.
        return False
    details = {
        "phase": "request",
        "category": match.category,
        "rule_id": match.rule_id,
        "rule_message": match.message,
        "rule_pack": pack.schema_version,
        "rule_pack_digest": pack.digest,
        "rule_source": pack.source,
        "rule_source_version": pack.source_version,
        "http_method": view.method,
        "http_path": view.path[:512],
        "target": match.target,
        "evidence": match.evidence,
        "request_id": view.request_id,
        "attack_type": ATTACK_TYPES.get(match.category, match.category),
        "blocked": blocked,
        "would_block": would_block,
        "action": "block" if blocked else "log",
        "mode": _event_mode(blocked, would_block),
    }
    reporter.report({
        "type": f"request_{match.category}",
        "attack_type": details["attack_type"],
        "severity": match.severity,
        # Canonical bridge events only accept five event types, so the precise
        # request category travels in the rule id instead.
        "rule_id": f"request-{match.category}-{match.rule_id}",
        "details": details,
        "blocked": blocked,
        "would_block": would_block,
        "action": details["action"],
        "mode": details["mode"],
    })
    return True


def inspect_request(
    view: RequestView,
    pack: Optional[RulePack] = None,
    config: Optional[RASPConfig] = None,
) -> RequestInspection:
    """Inspect one request and report findings according to the active policy.

    Raises :class:`RASPRequestBlocked` only when blocking is fully promoted.
    """
    config = config or get_config()
    request_id = view.request_id or uuid.uuid4().hex
    view = replace(view, request_id=request_id)
    if not _hook_enabled(config, None):
        return RequestInspection(request_id=request_id, enabled=False, mode="off", reason="hook_disabled")
    if config is None:
        return RequestInspection(request_id=request_id, enabled=False, mode="off", reason="config_unavailable")
    # Apply an already-published policy change before deciding the mode. The
    # bridge throttles this pull, so a request does not wait on the control
    # plane every time.
    reporter = _ensure_reporter()
    if reporter is not None:
        refresh = getattr(reporter, "refresh_config", None)
        if callable(refresh):
            try:
                refresh()
            except Exception:
                pass
    mode = effective_mode(config)
    if mode == "off":
        return RequestInspection(request_id=request_id, enabled=False, mode=mode, reason="policy_off")
    if not pack:
        try:
            pack = load_pack(_configured_path(config, None))
        except RulePackError as error:
            # Fail open: a missing pack must not break application traffic.
            return RequestInspection(request_id=request_id, enabled=False, mode=mode, reason=str(error))
    matches = match_request(view, pack)
    if not matches:
        return RequestInspection(request_id=request_id, enabled=True, mode=mode, matches=())
    blocked = should_block(config)
    would_block = (not blocked) and mode == "block"
    for match in matches:
        _report_match(view, pack, match, blocked, would_block)
    if blocked:
        raise RASPRequestBlocked(matches[0].category, matches[0].rule_id)
    return RequestInspection(
        request_id=request_id,
        enabled=True,
        mode=mode,
        matches=tuple(matches),
        blocked=blocked,
        would_block=would_block,
    )


def inspect_http_request(
    method: str,
    path: str,
    query: str = "",
    headers: Optional[Mapping[str, str]] = None,
    body: str = "",
    request_id: str = "",
    pack: Optional[RulePack] = None,
    config: Optional[RASPConfig] = None,
) -> RequestInspection:
    """Framework-neutral helper for apps that do not use WSGI/ASGI middleware."""
    view = RequestView(
        method=(method or "GET").upper(),
        path=path or "/",
        query=query or "",
        headers=tuple((str(k), str(v)) for k, v in (headers or {}).items()),
        body=body or "",
        request_id=request_id or uuid.uuid4().hex,
    )
    return inspect_request(view, pack=pack, config=config)


def request_hook_status(path: Optional[str] = None) -> Dict[str, Any]:
    config = get_config()
    enabled = _hook_enabled(config, None)
    resolved = _configured_path(config, path)
    if not enabled:
        return {"enabled": False, "reason": "hook_disabled", "pack_path": resolved}
    try:
        pack = load_pack(resolved)
    except RulePackError as error:
        return {"enabled": False, "reason": str(error), "pack_path": resolved}
    return {
        "enabled": True,
        "pack_path": resolved,
        "schema_version": pack.schema_version,
        "source": pack.source,
        "source_version": pack.source_version,
        "rule_count": len(pack.rules),
        "skipped_rules": pack.skipped,
        "digest": pack.digest,
        "paranoia_level": pack.paranoia_level,
    }


# --- WSGI ---------------------------------------------------------------


class _ReplayInput:
    """Replays bytes consumed for inspection to the WSGI application."""

    def __init__(self, prefix: bytes, stream: Any) -> None:
        self._prefix = prefix
        self._stream = stream

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            data = self._prefix + self._stream.read()
            self._prefix = b""
            return data
        if not self._prefix:
            return self._stream.read(size)
        if size <= len(self._prefix):
            data = self._prefix[:size]
            self._prefix = self._prefix[size:]
            return data
        data = self._prefix + self._stream.read(size - len(self._prefix))
        self._prefix = b""
        return data

    def readline(self, size: int = -1) -> bytes:
        if not self._prefix:
            return self._stream.readline(size)
        index = self._prefix.find(b"\n")
        if index >= 0:
            line = self._prefix[: index + 1]
            self._prefix = self._prefix[index + 1:]
            return line
        prefix, self._prefix = self._prefix, b""
        return prefix + self._stream.readline(-1 if size is None or size < 0 else max(0, size - len(prefix)))

    def readlines(self, hint: int = -1) -> List[bytes]:
        return list(iter(self.readline, b""))

    def __iter__(self) -> Any:
        return iter(self.readline, b"")

    def readinto(self, buffer: Any) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def _read_wsgi_body(environ: Mapping[str, Any], limit: int) -> bytes:
    stream = environ.get("wsgi.input")
    if stream is None or limit <= 0:
        return b""
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except (TypeError, ValueError):
        return b""
    if length <= 0:
        return b""
    data = stream.read(min(length, limit))
    if not isinstance(data, (bytes, bytearray)):
        data = str(data).encode("utf-8", "replace")
    data = bytes(data)
    if data:
        environ["wsgi.input"] = _ReplayInput(data, stream)  # type: ignore[index]
    return data


def view_from_wsgi(environ: Mapping[str, Any], limits: RequestLimits) -> RequestView:
    headers: List[Tuple[str, str]] = []
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            name = key[5:].replace("_", "-").title()
            headers.append((name, str(value)))
    if environ.get("CONTENT_TYPE"):
        headers.append(("Content-Type", str(environ["CONTENT_TYPE"])))
    if environ.get("CONTENT_LENGTH"):
        headers.append(("Content-Length", str(environ["CONTENT_LENGTH"])))
    content_type = str(environ.get("CONTENT_TYPE") or "").lower()
    body = b"" if content_type.startswith("multipart/form-data") else _read_wsgi_body(environ, limits.max_body_bytes)
    path = str(environ.get("PATH_INFO") or "/")
    script_name = str(environ.get("SCRIPT_NAME") or "")
    if script_name:
        path = script_name.rstrip("/") + path
    request_id = ""
    for name in ("HTTP_X_REQUEST_ID", "HTTP_X_CORRELATION_ID", "HTTP_TRACEPARENT"):
        if environ.get(name):
            request_id = str(environ[name])[:128]
            break
    return RequestView(
        method=str(environ.get("REQUEST_METHOD") or "GET").upper(),
        path=path,
        query=str(environ.get("QUERY_STRING") or ""),
        headers=tuple(headers),
        body=body.decode("utf-8", "replace"),
        request_id=request_id or uuid.uuid4().hex,
    )


def _forbidden_payload(exc: RASPBlockedError) -> bytes:
    return json.dumps({
        "error": "rasp_blocked",
        "phase": "request",
        "attack_type": getattr(exc, "attack_type", "unknown"),
        "rule_id": getattr(exc, "rule_id", ""),
    }, separators=(",", ":")).encode("utf-8")


def _scoped_iter(iterable: Iterable[Any], scope: Any) -> Any:
    try:
        yield from iterable
    finally:
        scope.__exit__(None, None, None)
        close = getattr(iterable, "close", None)
        if close is not None:
            close()


class RASPWSGIMiddleware:
    """WSGI middleware that inspects requests before the application runs."""

    def __init__(
        self,
        app: Callable[..., Any],
        pack: Optional[RulePack] = None,
        path: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> None:
        self.app = app
        self.enabled = enabled
        self._provider = _PackProvider(pack=pack, path=path)
        if get_config() is None:
            # The agent bootstrap normally installs the signed policy before the
            # application starts. Standalone WSGI/ASGI deployments rely on the
            # environment (RASP_MODE/RASP_BLOCK_ON_HIT), so bootstrap from it.
            try:
                load_config()
            except Exception:
                pass

    def _is_enabled(self) -> bool:
        return _hook_enabled(get_config(), self.enabled)

    def __call__(self, environ: Dict[str, Any], start_response: Callable[..., Any]) -> Any:
        config = get_config()
        if not self._is_enabled():
            return self.app(environ, start_response)
        pack = self._provider.get(config)
        if pack is None:
            return self.app(environ, start_response)
        view = view_from_wsgi(environ, _limits(pack, config))
        scope = request_scope(view.request_id)
        scope.__enter__()
        try:
            inspect_request(view, pack=pack, config=config)
        except RASPRequestBlocked as exc:
            scope.__exit__(None, None, None)
            payload = _forbidden_payload(exc)
            start_response("403 Forbidden", [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(payload))),
                ("X-Ly-RASP-Blocked", "1"),
            ])
            return [payload]
        except Exception:
            # Fail open on probe bugs; the sink hooks remain active.
            scope.__exit__(*sys.exc_info())
            return self.app(environ, start_response)
        try:
            iterable = self.app(environ, start_response)
        except BaseException:
            scope.__exit__(*sys.exc_info())
            raise
        return _scoped_iter(iterable, scope)


# --- ASGI ---------------------------------------------------------------


def view_from_asgi(scope: Mapping[str, Any], body: bytes, limits: RequestLimits) -> RequestView:
    headers = [
        (bytes(key).decode("latin-1"), bytes(value).decode("latin-1"))
        for key, value in scope.get("headers") or []
        if isinstance(key, (bytes, bytearray)) and isinstance(value, (bytes, bytearray))
    ]
    query_raw = scope.get("query_string") or b""
    if isinstance(query_raw, (bytes, bytearray)):
        query = bytes(query_raw).decode("latin-1")
    else:
        query = str(query_raw)
    request_id = ""
    for name, value in headers:
        if name.lower() in {"x-request-id", "x-correlation-id", "traceparent"}:
            request_id = value[:128]
            break
    return RequestView(
        method=str(scope.get("method") or "GET").upper(),
        path=str(scope.get("path") or "/"),
        query=query,
        headers=tuple(headers),
        body=body.decode("utf-8", "replace"),
        request_id=request_id or uuid.uuid4().hex,
    )


async def _consume_asgi_body(receive: Callable[..., Any], limit: int) -> Tuple[List[Dict[str, Any]], bytes]:
    messages: List[Dict[str, Any]] = []
    body = bytearray()
    while True:
        message = await receive()
        messages.append(message)
        if message.get("type") != "http.request":
            break
        chunk = message.get("body") or b""
        if isinstance(chunk, (bytes, bytearray)):
            body.extend(chunk)
        if not message.get("more_body", False):
            break
        if len(body) >= limit:
            break
    return messages, bytes(body)


class RASPASGIMiddleware:
    """ASGI middleware that inspects HTTP requests before the application runs."""

    def __init__(
        self,
        app: Callable[..., Any],
        pack: Optional[RulePack] = None,
        path: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> None:
        self.app = app
        self.enabled = enabled
        self._provider = _PackProvider(pack=pack, path=path)
        if get_config() is None:
            # The agent bootstrap normally installs the signed policy before the
            # application starts. Standalone WSGI/ASGI deployments rely on the
            # environment (RASP_MODE/RASP_BLOCK_ON_HIT), so bootstrap from it.
            try:
                load_config()
            except Exception:
                pass

    async def __call__(self, scope: Dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        config = get_config()
        if scope.get("type") != "http" or not _hook_enabled(config, self.enabled):
            await self.app(scope, receive, send)
            return
        pack = self._provider.get(config)
        if pack is None:
            await self.app(scope, receive, send)
            return
        limits = _limits(pack, config)
        messages, body = await _consume_asgi_body(receive, limits.max_body_bytes)
        view = view_from_asgi(scope, body[: limits.max_body_bytes], limits)

        async def replay() -> Dict[str, Any]:
            if messages:
                return messages.pop(0)
            return await receive()

        with request_scope(view.request_id):
            try:
                inspect_request(view, pack=pack, config=config)
            except RASPRequestBlocked as exc:
                payload = _forbidden_payload(exc)
                await send({
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json; charset=utf-8"),
                        (b"content-length", str(len(payload)).encode("ascii")),
                        (b"x-ly-rasp-blocked", b"1"),
                    ],
                })
                await send({"type": "http.response.body", "body": payload})
                return
            except Exception:
                # Fail open, but keep the already-consumed messages replayable.
                await self.app(scope, replay, send)
                return
            await self.app(scope, replay, send)


def protect_wsgi(app: Callable[..., Any], **kwargs: Any) -> RASPWSGIMiddleware:
    return RASPWSGIMiddleware(app, **kwargs)


def protect_asgi(app: Callable[..., Any], **kwargs: Any) -> RASPASGIMiddleware:
    return RASPASGIMiddleware(app, **kwargs)
