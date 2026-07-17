from __future__ import annotations

import hashlib
import hmac
import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Protocol

from .bridge import BridgeClient, BridgeConfigurationError
from .control_health import CanonicalControlHealth, ControlHealthPublication
from .bridge import ControlHealthPublicationError


class WatchdogClock(Protocol):
    def monotonic(self) -> float: ...

    def utc_now(self) -> str: ...

    def wait(self, stopped: threading.Event, timeout: float) -> bool: ...


class SystemWatchdogClock:
    def monotonic(self) -> float:
        import time

        return time.monotonic()

    def utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def wait(self, stopped: threading.Event, timeout: float) -> bool:
        return stopped.wait(timeout)


@dataclass(frozen=True, slots=True)
class WatchdogRuntime:
    clock: WatchdogClock = field(default_factory=SystemWatchdogClock)
    stale_after_seconds: float = 15.0
    check_interval_seconds: float = 1.0
    restart_backoff_seconds: float = 0.25


class RuntimeHealthMixin:
    def _allow_event(self) -> bool:
        second = int(time.monotonic())
        if second != self._rate_second:
            self._rate_second = second
            self._rate_count = 0
        if self._rate_count >= self.config.max_events_per_second:
            return False
        self._rate_count += 1
        return True

    def delivery_health(self) -> Dict[str, Any]:
        self._ensure_runtime_health_state()
        publication = self._publication
        if self.bridge_client is not None:
            bridge_health = self.bridge_client.control_health()
            bridge_publication = bridge_health["publication"]
            publication = ControlHealthPublication(
                status=str(bridge_publication["status"]),
                retry_count=int(bridge_publication["retry_count"]),
                last_error=str(bridge_publication["last_error"]),
            )
        return CanonicalControlHealth(
            config=self.config,
            status=self._health_status,
            reason=self._health_reason,
            restart_count=self._restart_count,
            watchdog_at=self._watchdog_at,
            queue_capacity=self.queue_capacity,
            publication=publication,
        ).as_dict()

    def record_watchdog_restart(self) -> bool:
        self._ensure_runtime_health_state()
        with self._runtime_health_lock:
            self._watchdog_at = self._utc_now()
            if self._restart_count >= self.config.restart_budget:
                self.config.mode = "off"
                self._health_status = "degraded"
                self._health_reason = "restart_budget_exhausted"
                return False
            self._restart_count += 1
            return True

    def _ensure_runtime_health_state(self) -> None:
        if not hasattr(self, "_runtime_health_lock"):
            self._runtime_health_lock = threading.RLock()
        if not hasattr(self, "_watchdog_runtime"):
            self._watchdog_runtime = WatchdogRuntime()
        if not hasattr(self, "_watchdog_activity_at"):
            self._watchdog_activity_at = self._watchdog_runtime.clock.monotonic()
        if not hasattr(self, "_watchdog_work_active"):
            self._watchdog_work_active = False
        if not hasattr(self, "_publication"):
            self._publication = ControlHealthPublication()

    def start(self) -> None:
        with self._watchdog_lifecycle_lock:
            if self._watchdog_thread is not None and self._watchdog_thread.is_alive():
                return
            self._watchdog_stopped.clear()
            self._watchdog_thread = threading.Thread(
                target=self.run_watchdog,
                name="ly-rasp-watchdog",
                daemon=True,
            )
            self._watchdog_thread.start()

    def run_watchdog(self) -> None:
        runtime = self._watchdog_runtime
        while not runtime.clock.wait(self._watchdog_stopped, runtime.check_interval_seconds):
            now = runtime.clock.monotonic()
            with self._runtime_health_lock:
                unhealthy = self._watchdog_work_active or not self._exporter_available
                stale = unhealthy and now - self._watchdog_activity_at > runtime.stale_after_seconds
                restart_ready = now >= self._watchdog_next_restart_at
                prevention_enabled = self.config.mode != "off"
                if not stale or not restart_ready or not prevention_enabled:
                    continue
                self._health_status = "degraded"
                self._health_reason = "watchdog_stale"
                self._watchdog_at = self._utc_now()
            if not self.record_watchdog_restart():
                self._emit_control_health()
                self._watchdog_stopped.set()
                return
            self._emit_control_health()
            self._restart_delivery()
            with self._runtime_health_lock:
                backoff = runtime.restart_backoff_seconds * (2 ** (self._restart_count - 1))
                self._watchdog_next_restart_at = now + backoff

    def _restart_delivery(self) -> None:
        if self.bridge_client is not None:
            self.bridge_client = BridgeClient(self.config)
            with self._runtime_health_lock:
                self._exporter_available = True
                self._health_status = "healthy"
                self._health_reason = "ready"
                self._watchdog_activity_at = self._watchdog_runtime.clock.monotonic()
            return
        self._connect_redis()
        with self._runtime_health_lock:
            self._watchdog_activity_at = self._watchdog_runtime.clock.monotonic()

    def shutdown(self) -> None:
        self._watchdog_stopped.set()
        with self._watchdog_lifecycle_lock:
            thread = self._watchdog_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join()
        with self._watchdog_lifecycle_lock:
            if self._watchdog_thread is not None and not self._watchdog_thread.is_alive():
                self._watchdog_thread = None

    @property
    def watchdog_running(self) -> bool:
        with self._watchdog_lifecycle_lock:
            return self._watchdog_thread is not None and self._watchdog_thread.is_alive()

    def _verify_binary_integrity(self) -> None:
        expected = self.config.binary_sha256.strip().lower()
        if not expected:
            return
        path = Path(self.config.binary_path) if self.config.binary_path else Path(__file__)
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            actual = ""
        if not hmac.compare_digest(expected, actual):
            self.config.mode = "off"
            self._health_status = "degraded"
            self._health_reason = "binary_integrity_failed"
            self._emit_control_health()

    def _utc_now(self) -> str:
        runtime = getattr(self, "_watchdog_runtime", None)
        if runtime is not None:
            return runtime.clock.utc_now()
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def _emit_control_health(self) -> bool:
        client = self.bridge_client or BridgeClient(self.config)
        try:
            client.record_control_failure(
                self._health_reason,
                self._restart_count,
                self._watchdog_at,
            )
            self._publication = ControlHealthPublication()
            return True
        except ControlHealthPublicationError:
            bridge_publication = client.control_health()["publication"]
            self._publication = ControlHealthPublication(
                status=str(bridge_publication["status"]),
                retry_count=int(bridge_publication["retry_count"]),
                last_error=str(bridge_publication["last_error"]),
            )
            return False
        except BridgeConfigurationError as error:
            self._publication = ControlHealthPublication(status="degraded", retry_count=0, last_error=str(error))
            return False
