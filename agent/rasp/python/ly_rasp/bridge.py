# noqa: SIZE_OK - authenticated bridge transport owns one integrity-chained client state.
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from .config import RASPConfig
from .control_health import CanonicalControlHealth, ControlHealthPublication


EVENT_SCHEMA = "lyflow.rasp_bridge_event.v1"
CONFIG_SCHEMA = "lyflow.rasp_bridge_config.v1"
TOKEN_HEADER = "X-Ly-RASP-Token"
AGENT_HEADER = "X-Lyflow-Agent-ID"


@dataclass(frozen=True, slots=True)
class BridgeConfigurationError(ValueError):
    reason: str

    def __str__(self) -> str:
        return self.reason


@dataclass(frozen=True, slots=True)
class ConfigIntegrityError(ValueError):
    reason: str

    def __str__(self) -> str:
        return self.reason


@dataclass(frozen=True, slots=True)
class ControlHealthPublicationError(OSError):
    attempts: int
    last_error: str

    def __str__(self) -> str:
        return f"control health publication exhausted after {self.attempts} attempts: {self.last_error}"


class BridgeClient:
    def __init__(self, config: RASPConfig):
        self.config = config
        self._queue_capacity_limit = max(1, config.queue_capacity)
        self.last_health_reason = "ready"
        self._last_config_pull = 0.0
        self._fallback_lock = threading.Lock()
        self._previous_fallback_hash = self._load_fallback_hash()
        self._opener = build_opener(ProxyHandler({}))
        self._publication_status = "healthy"
        self._publication_retry_count = 0
        self._publication_last_error = ""
        self.last_publication_error: ControlHealthPublicationError | None = None
        self._validate_local_url()

    def report(self, event: Dict[str, Any]) -> bool:
        strict_event = self.build_event(event)
        try:
            self._refresh_config()
            strict_event = self.build_event(event)
            request = Request(
                self.config.bridge_url.rstrip("/") + "/v1/rasp/events",
                data=json.dumps(strict_event, separators=(",", ":")).encode("utf-8"),
                headers=self._headers(),
                method="POST",
            )
            with self._opener.open(request, timeout=2.0) as response:
                if response.status != 202:
                    self._append_fallback(strict_event, f"http_{response.status}")
                    return False
            self.last_health_reason = "ready"
            return True
        except HTTPError as error:
            if error.code in {401, 403}:
                self.config.mode = "off"
                self.last_health_reason = "authorization_failed"
                self._record_control_failure(self.last_health_reason)
                return False
            self.last_health_reason = "exporter_unavailable"
            self._append_fallback(strict_event, type(error).__name__)
            self._record_control_failure(self.last_health_reason)
            return False
        except (URLError, TimeoutError, OSError) as error:
            self.last_health_reason = "exporter_unavailable"
            self._append_fallback(strict_event, type(error).__name__)
            self._record_control_failure(self.last_health_reason)
            return False
        except ConfigIntegrityError:
            self.config.mode = "off"
            self.last_health_reason = "config_signature_invalid"
            self._record_control_failure(self.last_health_reason)
            return False

    def build_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        attack_type = str(event.get("attack_type") or event.get("type") or "")
        event_type = {
            "sql_injection": "rasp.sql",
            "command_injection": "rasp.command",
            "sensitive_file_access": "rasp.file",
            "path_traversal": "rasp.file",
            "deserialize_injection": "rasp.deserialization",
            "deserialization": "rasp.deserialization",
            "ssrf": "rasp.http",
        }.get(attack_type, "")
        details = event.get("details")
        evidence = event.get("evidence") or event.get("message")
        if not evidence and isinstance(details, dict):
            evidence = details.get("evidence") or details.get("matched_pattern")
        observed_at = event.get("occurred_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return {
            "schema_version": EVENT_SCHEMA,
            "event_id": str(event.get("event_id") or uuid.uuid4()),
            "agent_id": self.config.agent_id,
            "policy_id": self.config.policy_id,
            "policy_version": self.config.policy_version,
            "language": "python",
            "event_type": event_type,
            "severity": str(event.get("severity") or "medium"),
            "observed_at": str(observed_at),
            "application": str(event.get("app") or self.config.app),
            "rule_id": str(event.get("rule_id") or f"python-{attack_type}"),
            "evidence": str(evidence or attack_type),
            "trace_id": str(event.get("trace_id") or ""),
        }

    def _refresh_config(self) -> None:
        now = time.monotonic()
        if now - self._last_config_pull < self.config.config_refresh_seconds:
            return
        request = Request(
            self.config.bridge_url.rstrip("/") + "/v1/rasp/config",
            headers=self._headers(),
            method="GET",
        )
        with self._opener.open(request, timeout=2.0) as response:
            raw = response.read(self.config.read_limit_bytes + 1)
        if len(raw) > self.config.read_limit_bytes:
            raise ConfigIntegrityError("config_read_limit_exceeded")
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ConfigIntegrityError("config_payload_invalid") from error
        if body.get("schema_version") != CONFIG_SCHEMA or body.get("agent_id") != self.config.agent_id:
            raise ConfigIntegrityError("config_binding_invalid")
        policy_id = body.get("policy_id")
        policy_version = body.get("policy_version")
        bridge_token = body.get("bridge_token")
        policy_mode = body.get("policy_mode")
        limits = body.get("limits")
        signature = body.get("config_signature")
        if not isinstance(policy_id, str) or not isinstance(policy_version, int) or not isinstance(bridge_token, str) or policy_mode not in {"monitor", "off"}:
            raise ConfigIntegrityError("config_fields_invalid")
        if not isinstance(limits, dict) or not isinstance(signature, str):
            raise ConfigIntegrityError("config_signature_missing")
        signed = {
            "agent_id": body["agent_id"],
            "bridge_token": bridge_token,
            "expires_at": body.get("expires_at"),
            "limits": limits,
            "policy_id": policy_id,
            "policy_mode": policy_mode,
            "policy_version": policy_version,
            "schema_version": body["schema_version"],
        }
        canonical = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(self.config.bridge_token.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ConfigIntegrityError("config_signature_invalid")
        self._apply_limits(limits)
        self.config.policy_id = policy_id
        self.config.policy_version = policy_version
        self.config.bridge_token = bridge_token
        self.config.mode = policy_mode
        self._last_config_pull = now

    def _apply_limits(self, limits: Dict[str, Any]) -> None:
        values = {
            "queue_capacity": limits.get("queue_capacity"),
            "read_limit_bytes": limits.get("read_bytes"),
            "cpu_budget_ms": limits.get("cpu_budget_ms"),
            "memory_budget_bytes": limits.get("memory_bytes"),
            "restart_budget": limits.get("restart_budget"),
        }
        if not all(isinstance(value, int) and value > 0 for value in values.values()):
            raise ConfigIntegrityError("config_limits_invalid")
        self.config.queue_capacity = min(values["queue_capacity"], 1024, self._queue_capacity_limit)
        self.config.read_limit_bytes = min(values["read_limit_bytes"], 1024 * 1024)
        self.config.cpu_budget_ms = min(values["cpu_budget_ms"], 5000)
        self.config.memory_budget_bytes = min(values["memory_budget_bytes"], 16 * 1024 * 1024)
        self.config.restart_budget = min(values["restart_budget"], 10)

    def record_control_failure(
        self,
        reason: str,
        restart_count: int = 0,
        watchdog_at: str | None = None,
    ) -> None:
        attempts = 3
        for attempt in range(1, attempts + 1):
            health = self.control_health(reason, restart_count, watchdog_at)
            request = Request(
                self.config.bridge_url.rstrip("/") + "/v1/rasp/health",
                data=json.dumps(health, separators=(",", ":")).encode("utf-8"),
                headers=self._headers(),
                method="POST",
            )
            try:
                with self._opener.open(request, timeout=2.0) as response:
                    if response.status != 202:
                        raise OSError(f"control health bridge returned {response.status}")
                self._publication_status = "healthy"
                self._publication_last_error = ""
                self.last_publication_error = None
                return
            except (HTTPError, URLError, TimeoutError, OSError) as error:
                self._publication_status = "degraded"
                self._publication_retry_count += 1
                self._publication_last_error = f"{type(error).__name__}: {error}"
                if attempt < attempts:
                    time.sleep(0.01 * (2 ** (attempt - 1)))
        failure = ControlHealthPublicationError(attempts, self._publication_last_error)
        self.last_publication_error = failure
        self._append_fallback(self.control_health(reason, restart_count, watchdog_at), reason)
        raise failure

    def _record_control_failure(
        self,
        reason: str,
        restart_count: int = 0,
        watchdog_at: str | None = None,
    ) -> None:
        try:
            self.record_control_failure(reason, restart_count, watchdog_at)
        except ControlHealthPublicationError as error:
            self.last_publication_error = error

    def control_health(
        self,
        reason: str | None = None,
        restart_count: int = 0,
        watchdog_at: str | None = None,
    ) -> Dict[str, Any]:
        health_reason = reason or self.last_health_reason
        status = "healthy" if health_reason in {"", "ready"} else "degraded"
        return CanonicalControlHealth(
            config=self.config,
            status=status,
            reason=health_reason,
            restart_count=restart_count,
            watchdog_at=watchdog_at,
            publication=ControlHealthPublication(
                status=self._publication_status,
                retry_count=self._publication_retry_count,
                last_error=self._publication_last_error,
            ),
        ).as_dict()

    def _headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            TOKEN_HEADER: self.config.bridge_token,
            AGENT_HEADER: self.config.agent_id,
        }

    def _validate_local_url(self) -> None:
        parsed = urlsplit(self.config.bridge_url)
        if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise BridgeConfigurationError("RASP bridge must use a plain local HTTP URL")
        if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise BridgeConfigurationError("RASP bridge host must be loopback")

    def _append_fallback(self, event: Dict[str, Any], reason: str) -> None:
        payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with self._fallback_lock:
            record = {
                "schema_version": "lyflow.rasp_fallback.v1",
                "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "reason": reason,
                "agent_id": self.config.agent_id,
                "policy_id": self.config.policy_id,
                "policy_version": self.config.policy_version,
                "event_id": event.get("event_id") or str(uuid.uuid4()),
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "previous_record_sha256": self._previous_fallback_hash,
                "event": event,
            }
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
            record_hash = hashlib.sha256(canonical).hexdigest()
            record["record_sha256"] = record_hash
            path = Path(self.config.fallback_path)
            path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
            descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o640)
            with os.fdopen(descriptor, "ab") as fallback:
                fallback.write(json.dumps(record, separators=(",", ":")).encode("utf-8") + b"\n")
                fallback.flush()
                os.fsync(fallback.fileno())
            self._previous_fallback_hash = record_hash

    def _load_fallback_hash(self) -> str:
        path = Path(self.config.fallback_path)
        if not path.exists():
            return ""
        last_hash = ""
        with path.open("r", encoding="utf-8") as fallback:
            for line in fallback:
                if line.strip():
                    record = json.loads(line)
                    record_hash = record.pop("record_sha256", "")
                    event = record.get("event")
                    payload_hash = record.get("payload_sha256")
                    previous_hash = record.get("previous_record_sha256")
                    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    if not isinstance(event, dict):
                        raise BridgeConfigurationError("RASP fallback event is invalid")
                    payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    valid_record_hash = isinstance(record_hash, str) and hmac.compare_digest(
                        record_hash,
                        hashlib.sha256(canonical).hexdigest(),
                    )
                    if previous_hash != last_hash or payload_hash != hashlib.sha256(payload).hexdigest() or not valid_record_hash:
                        raise BridgeConfigurationError("RASP fallback integrity verification failed")
                    last_hash = record_hash
        return last_hash
