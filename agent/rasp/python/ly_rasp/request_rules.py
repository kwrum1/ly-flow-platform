"""Load and evaluate the server-generated CRS request rule pack.

The pack is produced by ``GET /api/v1/rasp/request-rules/download`` and is the
only contract between the platform and runtime probes. It is intentionally
small: request-side OWASP CRS rules at paranoia level 1-2 translated to either
``rx`` (regular expression) or ``pm`` (phrase match).

Loading is fail-open. A missing, stale or malformed pack disables request
inspection; it never blocks traffic by itself.
"""
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import unquote, unquote_plus

SCHEMA_VERSION = "lyflow.rasp.request_rules.v1"
DEFAULT_PACK_PATH = "/etc/lyflow/rasp/request_rules.json"
PACK_PATH_ENV = "LY_RASP_REQUEST_RULES"
MAX_PACK_BYTES = 4 * 1024 * 1024
MAX_MATCHES = 8
MAX_PARAM_CANDIDATES = 64
MAX_VARIANTS = 6

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class RulePackError(ValueError):
    """Raised when a rule pack cannot be trusted or consumed."""


@dataclass(frozen=True)
class RequestLimits:
    max_path_bytes: int = 4096
    max_query_bytes: int = 8192
    max_body_bytes: int = 64 * 1024
    max_headers_bytes: int = 8192
    max_header_count: int = 100
    max_evidence_bytes: int = 256

    @classmethod
    def from_payload(cls, payload: Any) -> "RequestLimits":
        if not isinstance(payload, dict):
            return cls()
        def clamp(key: str, default: int, upper: int) -> int:
            value = payload.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                return default
            return min(value, upper)
        return cls(
            max_path_bytes=clamp("max_path_bytes", 4096, 64 * 1024),
            max_query_bytes=clamp("max_query_bytes", 8192, 128 * 1024),
            max_body_bytes=clamp("max_body_bytes", 64 * 1024, 1024 * 1024),
            max_headers_bytes=clamp("max_headers_bytes", 8192, 128 * 1024),
            max_header_count=clamp("max_header_count", 100, 512),
            max_evidence_bytes=clamp("max_evidence_bytes", 256, 2048),
        )


@dataclass(frozen=True)
class RequestRule:
    id: str
    category: str
    severity: str
    paranoia: int
    operator: str
    targets: Tuple[str, ...]
    message: str
    action: str
    pattern: str = ""
    phrases: Tuple[str, ...] = ()
    regex: Optional[re.Pattern] = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class RulePack:
    path: str
    schema_version: str
    source: str
    source_version: str
    generated_at: str
    paranoia_level: int
    digest: str
    limits: RequestLimits
    rules: Tuple[RequestRule, ...]
    skipped: int = 0


@dataclass(frozen=True)
class RequestMatch:
    rule_id: str
    category: str
    severity: str
    paranoia: int
    target: str
    evidence: str
    action: str
    message: str


@dataclass(frozen=True)
class RequestView:
    """Bounded, framework-neutral view of one HTTP request."""

    method: str
    path: str
    query: str = ""
    headers: Tuple[Tuple[str, str], ...] = ()
    body: str = ""
    request_id: str = ""

    def header_values(self, name: str) -> Tuple[str, ...]:
        wanted = name.strip().lower()
        return tuple(value for key, value in self.headers if key.strip().lower() == wanted)


_CACHE_LOCK = threading.Lock()
_CACHE: Dict[Tuple[str, int, int], RulePack] = {}


def pack_path(path: Optional[str] = None) -> str:
    return path or os.environ.get(PACK_PATH_ENV) or DEFAULT_PACK_PATH


def load_pack(path: Optional[str] = None, force: bool = False) -> RulePack:
    """Load the pack, reusing it until the file changes on disk."""
    resolved = pack_path(path)
    try:
        stat = os.stat(resolved)
    except OSError as error:
        raise RulePackError(f"request rule pack unavailable: {resolved}") from error
    key = (resolved, int(stat.st_mtime_ns), int(stat.st_size))
    with _CACHE_LOCK:
        if not force and key in _CACHE:
            return _CACHE[key]
    if stat.st_size > MAX_PACK_BYTES:
        raise RulePackError("request rule pack exceeds size limit")
    try:
        with open(resolved, "rb") as handle:
            raw = handle.read(MAX_PACK_BYTES + 1)
    except OSError as error:
        raise RulePackError(f"request rule pack unreadable: {resolved}") from error
    if len(raw) > MAX_PACK_BYTES:
        raise RulePackError("request rule pack exceeds size limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RulePackError("request rule pack is not valid JSON") from error
    pack = _parse_pack(resolved, payload)
    with _CACHE_LOCK:
        _CACHE[key] = pack
    return pack


def _parse_pack(path: str, payload: Any) -> RulePack:
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise RulePackError("request rule pack schema mismatch")
    raw_rules = payload.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RulePackError("request rule pack contains no rules")
    rules: List[RequestRule] = []
    skipped = 0
    for item in raw_rules:
        rule = _parse_rule(item)
        if rule is None:
            skipped += 1
            continue
        rules.append(rule)
    if not rules:
        raise RulePackError("request rule pack has no usable rules")
    return RulePack(
        path=path,
        schema_version=SCHEMA_VERSION,
        source=str(payload.get("source") or "owasp-crs"),
        source_version=str(payload.get("source_version") or ""),
        generated_at=str(payload.get("generated_at") or ""),
        paranoia_level=_int(payload.get("paranoia_level"), 2),
        digest=str(payload.get("digest") or ""),
        limits=RequestLimits.from_payload(payload.get("limits")),
        rules=tuple(rules),
        skipped=skipped,
    )


def _parse_rule(item: Any) -> Optional[RequestRule]:
    if not isinstance(item, dict):
        return None
    rule_id = item.get("id")
    category = item.get("category")
    operator = str(item.get("operator") or "").lower()
    targets = item.get("targets")
    if not isinstance(rule_id, str) or not rule_id or not isinstance(category, str) or not category:
        return None
    if not isinstance(targets, list) or not targets or not all(isinstance(t, str) and t for t in targets):
        return None
    if operator not in {"rx", "pm"}:
        return None
    pattern = item.get("pattern") or ""
    phrases = item.get("phrases") or []
    regex = None
    if operator == "rx":
        if not isinstance(pattern, str) or not pattern:
            return None
        try:
            regex = re.compile(pattern)
        except re.error:
            return None
    else:
        if not isinstance(phrases, list) or not phrases:
            return None
        phrases = tuple(str(value) for value in phrases if str(value))
        if not phrases:
            return None
    return RequestRule(
        id=rule_id,
        category=category,
        severity=str(item.get("severity") or "medium").lower(),
        paranoia=_int(item.get("paranoia"), 1),
        operator=operator,
        targets=tuple(targets),
        message=str(item.get("message") or rule_id),
        action=str(item.get("action") or "block"),
        pattern=pattern if isinstance(pattern, str) else "",
        phrases=tuple(phrases) if operator == "pm" else (),
        regex=regex,
    )


def _int(value: Any, fallback: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return fallback


def _truncate(value: str, limit: int) -> str:
    if not value:
        return ""
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return value
    return encoded[:limit].decode("utf-8", "ignore")


def _variants(value: str) -> Tuple[str, ...]:
    if not value:
        return ()
    variants: List[str] = [value]
    decoded = unquote(value)
    if decoded != value:
        variants.append(decoded)
    plus = unquote_plus(value)
    if plus not in variants:
        variants.append(plus)
    twice = unquote(decoded)
    if twice not in variants:
        variants.append(twice)
    if "\x00" in value:
        variants.append(value.replace("\x00", ""))
    return tuple(variants[:MAX_VARIANTS])


def _parameter_values(text: str) -> List[str]:
    values: List[str] = []
    if not text:
        return values
    for part in text.split("&")[:MAX_PARAM_CANDIDATES]:
        if not part:
            continue
        if "=" in part:
            name, value = part.split("=", 1)
            if name:
                values.append(name)
            values.append(value)
        else:
            values.append(part)
    return values


_JSON_STRING = re.compile(r'"((?:[^"\\]|\\.){0,4096})"')


def _json_strings(text: str) -> List[str]:
    if not text or not text.lstrip().startswith(("{", "[")):
        return []
    return _JSON_STRING.findall(text[:64 * 1024])


def _raw_target_values(view: RequestView, target: str, limits: RequestLimits) -> List[str]:
    if target == "path":
        return [_truncate(view.path, limits.max_path_bytes)]
    if target == "query":
        query = _truncate(view.query, limits.max_query_bytes)
        return [query, *_parameter_values(query)]
    if target == "body":
        body = _truncate(view.body, limits.max_body_bytes)
        return [body, *_parameter_values(body), *_json_strings(body)]
    if target == "headers":
        values: List[str] = []
        total = 0
        for name, value in view.headers[: limits.max_header_count]:
            line = f"{name}: {value}"
            if total + len(line) > limits.max_headers_bytes:
                break
            # CRS inspects REQUEST_HEADERS as individual header values, so
            # expose the line and the value; a joined blob would break
            # anchored patterns such as the Shellshock rule.
            values.append(line)
            values.append(value)
            total += len(line) + 1
        return values
    if target == "cookies":
        cookies = list(view.header_values("cookie"))
        for header in cookies:
            cookies.extend(part.split("=", 1)[-1] for part in header.split(";") if part.strip())
        return cookies
    if target == "method":
        return [view.method]
    if target == "request_line":
        query = _truncate(view.query, limits.max_query_bytes)
        suffix = f"?{query}" if query else ""
        return [f"{view.method} {_truncate(view.path, limits.max_path_bytes)}{suffix} HTTP/1.1"]
    if target.startswith("header:"):
        return list(view.header_values(target[len("header:"):]))
    return []


def build_field_index(view: RequestView, pack: RulePack) -> Dict[str, Tuple[str, ...]]:
    targets = sorted({target for rule in pack.rules for target in rule.targets})
    index: Dict[str, Tuple[str, ...]] = {}
    for target in targets:
        variants: List[str] = []
        for raw in _raw_target_values(view, target, pack.limits):
            variants.extend(_variants(raw))
        index[target] = tuple(dict.fromkeys(variants))
    return index


def match_request(view: RequestView, pack: RulePack) -> List[RequestMatch]:
    index = build_field_index(view, pack)
    found: List[RequestMatch] = []
    for rule in pack.rules:
        hit = _match_rule(rule, index)
        if hit is None:
            continue
        target, evidence = hit
        found.append(RequestMatch(
            rule_id=rule.id,
            category=rule.category,
            severity=rule.severity,
            paranoia=rule.paranoia,
            target=target,
            evidence=_truncate(evidence, pack.limits.max_evidence_bytes),
            action=rule.action,
            message=rule.message,
        ))
    if not found:
        return []
    found.sort(key=lambda match: (-_SEVERITY_RANK.get(match.severity, 0), match.rule_id))
    deduped: List[RequestMatch] = []
    seen: set[str] = set()
    for match in found:
        if match.category in seen:
            continue
        seen.add(match.category)
        deduped.append(match)
        if len(deduped) >= MAX_MATCHES:
            break
    return deduped


def _match_rule(rule: RequestRule, index: Mapping[str, Tuple[str, ...]]) -> Optional[Tuple[str, str]]:
    for target in rule.targets:
        for value in index.get(target, ()):
            if not value:
                continue
            if rule.operator == "pm":
                lowered = value.lower()
                for phrase in rule.phrases:
                    if phrase.lower() in lowered:
                        return target, phrase
                continue
            if rule.regex is None:
                continue
            match = rule.regex.search(value)
            if match:
                return target, match.group(0)
    return None
