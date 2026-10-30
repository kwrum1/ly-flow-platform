from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Final
from unittest import TestCase

from ly_rasp.config import RASPConfig
from ly_rasp.detector.command_injection import detect_command_injection
from ly_rasp.detector.file_access import detect_sensitive_file
from ly_rasp.detector.sql_injection import detect_sql_injection
from ly_rasp.reporter import Reporter


POLICY_VERSION: Final = 13
CANONICAL_FIELDS: Final = (
    "type",
    "agent_id",
    "language",
    "app",
    "attack_type",
    "blocked",
    "action",
    "mode",
    "severity",
    "rule_id",
    "policy_version",
)


class InMemoryExporter:
    available: Final = True

    def __init__(self) -> None:
        self.events: list[dict[str, str]] = []

    def xadd(self, _stream: str, event: dict[str, str]) -> None:
        self.events.append(event)


class UnavailableExporter:
    available: Final = False

    def xadd(self, _stream: str, _event: dict[str, str]) -> None:
        raise OSError("inert exporter outage")


class MockRuntimeAPIs:
    def __init__(self, reporter: Reporter) -> None:
        self._reporter = reporter

    def command(self, value: str) -> str:
        result = detect_command_injection(value)
        if result is not None:
            self._reporter.report({"type": "command_injection", "details": result})
        return "mock-command-ok"

    def file(self, value: str) -> str:
        result = detect_sensitive_file(value)
        if result is not None:
            self._reporter.report({"type": "sensitive_file_access", "details": result})
        return "mock-file-ok"

    def sql(self, value: str) -> str:
        result = detect_sql_injection(value)
        if result is not None:
            self._reporter.report({"type": "sql_injection", "details": result})
        return "mock-sql-ok"


def make_reporter(
    exporter: InMemoryExporter | UnavailableExporter,
    policy_version: int = POLICY_VERSION,
    fallback_path: str | None = None,
) -> Reporter:
    reporter = Reporter.__new__(Reporter)
    reporter.config = RASPConfig(
        agent_id="conformance-agent",
        app="conformance-fixture",
        mode="monitor",
        policy_version=policy_version,
        fail_behavior="monitor" if policy_version else "disable",
        fallback_path=fallback_path
        or str(Path(tempfile.mkdtemp(prefix="lyflow-rasp-conformance-")) / "fallback.jsonl"),
    )
    reporter.bridge_client = None
    reporter.redis_client = exporter
    reporter._rate_second = -1
    reporter._rate_count = 0
    reporter._health_status = "healthy"
    reporter._health_reason = "ready"
    reporter._exporter_available = exporter.available
    reporter._restart_count = 0
    return reporter


class TestPythonRASPConformance(TestCase):
    def test_inert_apis_emit_canonical_monitor_events(self) -> None:
        # Given
        exporter = InMemoryExporter()
        runtime = MockRuntimeAPIs(make_reporter(exporter))

        # When
        outcomes = (
            runtime.command("mock-tool; rm inert-target"),
            runtime.file("/etc/passwd"),
            runtime.sql("SELECT 1 UNION SELECT 2"),
        )

        # Then
        self.assertEqual(outcomes, ("mock-command-ok", "mock-file-ok", "mock-sql-ok"))
        actual = [
            {key: decoded[key] for key in CANONICAL_FIELDS}
            for decoded in (json.loads(event["data"]) for event in exporter.events)
        ]
        fixture = Path(__file__).with_name("fixtures") / "canonical-events.json"
        self.assertEqual(actual, json.loads(fixture.read_text(encoding="utf-8")))

    def test_missing_policy_fails_disabled_with_health(self) -> None:
        # Given
        reporter = make_reporter(InMemoryExporter(), policy_version=0)

        # When
        delivered = reporter.report({"type": "sql_injection"})

        # Then
        self.assertFalse(delivered)
        health = reporter.delivery_health()
        watchdog_at = health.pop("watchdog_at")
        self.assertTrue(watchdog_at.endswith("Z"))
        self.assertEqual(
            health,
            {
                "status": "degraded",
                "reason": "missing_policy_version",
                "schema_version": "lyflow.control_health.v1",
                "event_type": "control.health",
                "runtime": "python-rasp",
                "prevention_enabled": False,
                "fail_policy": {"observation": "fail_open", "integrity": "fail_closed", "authorization": "fail_closed"},
                "limits": {"queue_capacity": 128, "read_bytes": 65536, "cpu_budget_ms": 50, "memory_bytes": 1048576, "restart_budget": 3},
                "restart_count": 0,
                "publication": {"status": "healthy", "retry_count": 0, "last_error": ""},
            },
        )

    def test_exporter_outage_fails_monitor_with_health(self) -> None:
        # Given
        reporter = make_reporter(UnavailableExporter())

        # When
        delivered = reporter.report({"type": "sql_injection"})

        # Then
        self.assertFalse(delivered)
        health = reporter.delivery_health()
        watchdog_at = health.pop("watchdog_at")
        publication = health.pop("publication")
        self.assertTrue(watchdog_at.endswith("Z"))
        self.assertEqual(publication["status"], "degraded")
        self.assertEqual(publication["retry_count"], 3)
        self.assertTrue(publication["last_error"])
        self.assertEqual(
            health,
            {
                "status": "degraded",
                "reason": "exporter_unavailable",
                "schema_version": "lyflow.control_health.v1",
                "event_type": "control.health",
                "runtime": "python-rasp",
                "prevention_enabled": True,
                "fail_policy": {"observation": "fail_open", "integrity": "fail_closed", "authorization": "fail_closed"},
                "limits": {"queue_capacity": 128, "read_bytes": 65536, "cpu_budget_ms": 50, "memory_bytes": 1048576, "restart_budget": 3},
                "restart_count": 0,
            },
        )

    def test_unwritable_fallback_does_not_break_reporting(self) -> None:
        # Given: a spool path whose parent can never become a directory.
        blocker = Path(tempfile.mkdtemp(prefix="lyflow-rasp-blocker-")) / "not-a-dir"
        blocker.write_text("x", encoding="utf-8")
        reporter = make_reporter(UnavailableExporter(), fallback_path=str(blocker / "fallback.jsonl"))

        # When
        delivered = reporter.report({"type": "sql_injection"})

        # Then: the protected application still gets a normal return path.
        self.assertFalse(delivered)
        self.assertEqual(reporter.delivery_health()["reason"], "exporter_unavailable")
