from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict

from .config import RASPConfig, effective_mode


@dataclass(frozen=True, slots=True)
class ControlHealthPublication:
    status: str = "healthy"
    retry_count: int = 0
    last_error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "retry_count": self.retry_count,
            "last_error": self.last_error,
        }


@dataclass(frozen=True, slots=True)
class CanonicalControlHealth:
    config: RASPConfig
    status: str
    reason: str
    runtime: str = "python-rasp"
    restart_count: int = 0
    watchdog_at: str | None = None
    queue_capacity: int | None = None
    publication: ControlHealthPublication = field(default_factory=ControlHealthPublication)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "lyflow.control_health.v1",
            "event_type": "control.health",
            "runtime": self.runtime,
            "status": self.status,
            "reason": self.reason,
            "prevention_enabled": self.config.policy_version > 0 and effective_mode(self.config) != "off",
            "fail_policy": {
                "observation": "fail_open",
                "integrity": "fail_closed",
                "authorization": "fail_closed",
            },
            "limits": {
                "queue_capacity": self.queue_capacity or self.config.queue_capacity,
                "read_bytes": self.config.read_limit_bytes,
                "cpu_budget_ms": self.config.cpu_budget_ms,
                "memory_bytes": self.config.memory_budget_bytes,
                "restart_budget": self.config.restart_budget,
            },
            "restart_count": self.restart_count,
            "watchdog_at": self.watchdog_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "publication": self.publication.as_dict(),
        }
