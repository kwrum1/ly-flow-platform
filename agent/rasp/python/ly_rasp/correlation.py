"""Per-request correlation and de-duplication for RASP events.

The request hook evaluates CRS rules at ingress, before application code runs.
Sink hooks then run inside the same request. Without correlation the same
attack would be reported twice (once as a request hit, once at the sink).

A :class:`RequestScope` is stored in a ``ContextVar`` so it follows both WSGI
threads and ASGI tasks. The first claim for a category wins; later claims for
the same category in the same request are suppressed. Outside a request scope
``claim_event`` always returns ``True``, preserving the original sink behavior.
"""
from __future__ import annotations

import contextvars
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator, Optional, Set

_SCOPE: contextvars.ContextVar[Optional["RequestScope"]] = contextvars.ContextVar(
    "ly_rasp_request_scope", default=None
)

SINK_CATEGORIES = {
    "sql_injection": "sqli",
    "sqli": "sqli",
    "xss": "xss",
    "command_injection": "rce",
    "rce": "rce",
    "sensitive_file_access": "path_traversal",
    "path_traversal": "path_traversal",
    "lfi": "lfi",
    "rfi": "rfi",
    "webshell": "webshell",
    "scanner": "scanner",
    "deserialize_injection": "deserialization",
    "deserialization": "deserialization",
    "ssrf": "ssrf",
}


@dataclass
class RequestScope:
    request_id: str
    claimed: Set[str] = field(default_factory=set)


def category_for_sink(event_type: str) -> str:
    return SINK_CATEGORIES.get(str(event_type or "").lower(), str(event_type or "unknown"))


@contextmanager
def request_scope(request_id: Optional[str] = None) -> Iterator[RequestScope]:
    scope = RequestScope(request_id=request_id or uuid.uuid4().hex)
    token = _SCOPE.set(scope)
    try:
        yield scope
    finally:
        _SCOPE.reset(token)


def current_scope() -> Optional[RequestScope]:
    return _SCOPE.get()


def current_request_id() -> str:
    scope = _SCOPE.get()
    return scope.request_id if scope is not None else ""


def claim_event(category: str) -> bool:
    """Return True when this category has not been reported in this request."""
    scope = _SCOPE.get()
    if scope is None:
        return True
    key = str(category or "unknown")
    if key in scope.claimed:
        return False
    scope.claimed.add(key)
    return True


def event_already_reported(category: str) -> bool:
    scope = _SCOPE.get()
    return scope is not None and str(category or "unknown") in scope.claimed
