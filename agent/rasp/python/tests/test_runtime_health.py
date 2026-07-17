from __future__ import annotations

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from ly_rasp.config import RASPConfig
from ly_rasp.control_health import CanonicalControlHealth, ControlHealthPublication
from ly_rasp.reporter import Reporter


CANONICAL_HEALTH_FIELDS = {
    "schema_version",
    "event_type",
    "runtime",
    "status",
    "reason",
    "prevention_enabled",
    "fail_policy",
    "limits",
    "publication",
    "restart_count",
    "watchdog_at",
}


class BlockingBridge:
    def __init__(self, started: threading.Barrier, release: threading.Event) -> None:
        self.last_health_reason = "ready"
        self._started = started
        self._release = release

    def report(self, _event: dict[str, str | int | float | bool | None]) -> bool:
        self._started.wait(timeout=5)
        return self._release.wait(timeout=5)

    def control_health(self) -> dict[str, dict[str, str | int]]:
        return {"publication": {"status": "healthy", "retry_count": 0, "last_error": ""}}


class TestPythonRuntimeHealth(TestCase):
    def test_shared_canonical_fixture_matches_bytes(self) -> None:
        # Given
        config = RASPConfig(
            policy_version=15,
            queue_capacity=128,
            read_limit_bytes=1 << 20,
            cpu_budget_ms=100,
            memory_budget_bytes=256 << 10,
            restart_budget=3,
        )
        fixture = Path(__file__).parents[4] / "contracts" / "control-health" / "v1" / "fixture.json"
        health = CanonicalControlHealth(
            config=config,
            status="degraded",
            reason="control_health_delivery_unavailable",
            runtime="fixture-runtime",
            restart_count=2,
            watchdog_at="2026-07-15T00:00:00Z",
            publication=ControlHealthPublication(
                status="degraded",
                retry_count=3,
                last_error="fixture publication unavailable",
            ),
        )

        # When
        generated = json.dumps(health.as_dict(), separators=(",", ":")).encode("utf-8")

        # Then
        self.assertEqual(generated, fixture.read_bytes().strip())

    def test_health_reports_fail_policy_and_resource_limits(self) -> None:
        # Given
        config = RASPConfig(policy_version=15, fail_behavior="monitor")
        reporter = Reporter.__new__(Reporter)
        reporter.config = config
        reporter.bridge_client = None
        reporter.redis_client = None
        reporter._rate_second = -1
        reporter._rate_count = 0
        reporter._health_status = "healthy"
        reporter._health_reason = "ready"
        reporter._exporter_available = True
        reporter._restart_count = 0
        reporter._watchdog_at = "2026-07-15T00:00:00Z"

        # When
        health = reporter.delivery_health()

        # Then
        self.assertEqual(set(health), CANONICAL_HEALTH_FIELDS)
        self.assertEqual(health["schema_version"], "lyflow.control_health.v1")
        self.assertEqual(health["fail_policy"], {"observation": "fail_open", "integrity": "fail_closed", "authorization": "fail_closed"})
        self.assertEqual(health["limits"]["queue_capacity"], 128)
        self.assertGreater(health["limits"]["memory_bytes"], 0)
        self.assertEqual(health["watchdog_at"], "2026-07-15T00:00:00Z")
        self.assertTrue(health["prevention_enabled"])
        self.assertEqual(health["publication"], {"status": "healthy", "retry_count": 0, "last_error": ""})

    def test_restart_loop_is_bounded_and_degrades_health(self) -> None:
        # Given
        reporter = Reporter.__new__(Reporter)
        reporter.config = RASPConfig(policy_version=15, restart_budget=2)
        reporter.bridge_client = None
        reporter.redis_client = None
        reporter._rate_second = -1
        reporter._rate_count = 0
        reporter._health_status = "healthy"
        reporter._health_reason = "ready"
        reporter._exporter_available = True
        reporter._restart_count = 0
        reporter._watchdog_at = "2026-07-15T00:00:00Z"

        # When
        first = reporter.record_watchdog_restart()
        second = reporter.record_watchdog_restart()
        third = reporter.record_watchdog_restart()

        # Then
        self.assertTrue(first)
        self.assertTrue(second)
        self.assertFalse(third)
        self.assertEqual(reporter.delivery_health()["reason"], "restart_budget_exhausted")

    def test_memory_limit_rejects_event_without_blocking_application(self) -> None:
        # Given
        reporter = Reporter.__new__(Reporter)
        reporter.config = RASPConfig(policy_version=15, memory_budget_bytes=128, fail_behavior="monitor")
        reporter.bridge_client = None
        reporter.redis_client = None
        reporter._rate_second = -1
        reporter._rate_count = 0
        reporter._health_status = "healthy"
        reporter._health_reason = "ready"
        reporter._exporter_available = False
        reporter._restart_count = 0
        reporter._watchdog_at = "2026-07-15T00:00:00Z"

        # When
        delivered = reporter.report({"type": "sql_injection", "evidence": "x" * 1024})

        # Then
        self.assertFalse(delivered)
        self.assertEqual(reporter.delivery_health()["reason"], "memory_budget_exceeded")
        self.assertEqual(reporter.config.mode, "monitor")
        self.assertTrue(reporter.delivery_health()["prevention_enabled"])

    def test_binary_integrity_failure_disables_runtime(self) -> None:
        # Given
        with TemporaryDirectory() as temporary:
            binary = Path(temporary) / "runtime.bin"
            fallback = Path(temporary) / "fallback.jsonl"
            binary.write_bytes(b"trusted")
            config = RASPConfig(
                policy_version=15,
                fallback_path=str(fallback),
                binary_path=str(binary),
                binary_sha256=hashlib.sha256(b"different").hexdigest(),
            )

            # When
            reporter = Reporter(config)

            # Then
            health = reporter.delivery_health()
            self.assertEqual(health["reason"], "binary_integrity_failed")
            self.assertFalse(health["prevention_enabled"])
            self.assertTrue(fallback.is_file())

    def test_binary_integrity_failure_emits_canonical_control_health(self) -> None:
        # Given
        with TemporaryDirectory() as temporary:
            binary = Path(temporary) / "runtime.bin"
            fallback = Path(temporary) / "fallback.jsonl"
            binary.write_bytes(b"trusted")
            config = RASPConfig(
                bridge_token="bridge-secret",
                fallback_path=str(fallback),
                policy_version=15,
                binary_path=str(binary),
                binary_sha256=hashlib.sha256(b"different").hexdigest(),
            )

            # When
            Reporter(config)
            record = json.loads(fallback.read_text(encoding="utf-8"))

            # Then
            self.assertEqual(set(record["event"]), CANONICAL_HEALTH_FIELDS)
            self.assertEqual(record["event"]["reason"], "binary_integrity_failed")
            self.assertFalse(record["event"]["prevention_enabled"])

    def test_watchdog_timestamp_is_canonical_utc(self) -> None:
        # Given
        reporter = Reporter.__new__(Reporter)
        reporter.config = RASPConfig(policy_version=15)
        reporter.bridge_client = None
        reporter.redis_client = None
        reporter._rate_second = -1
        reporter._rate_count = 0
        reporter._health_status = "healthy"
        reporter._health_reason = "ready"
        reporter._exporter_available = True
        reporter._restart_count = 0
        reporter._watchdog_at = "2026-07-15T00:00:00Z"

        # When
        watchdog_at = reporter.delivery_health()["watchdog_at"]

        # Then
        self.assertEqual(datetime.fromisoformat(watchdog_at.replace("Z", "+00:00")).utcoffset().total_seconds(), 0)

    def test_cpu_budget_rejects_event_without_blocking_application(self) -> None:
        # Given
        reporter = Reporter.__new__(Reporter)
        reporter.config = RASPConfig(policy_version=15, cpu_budget_ms=1, fail_behavior="monitor")
        reporter.bridge_client = None
        reporter.redis_client = None
        reporter._rate_second = -1
        reporter._rate_count = 0
        reporter._health_status = "healthy"
        reporter._health_reason = "ready"
        reporter._exporter_available = False
        reporter._restart_count = 0
        reporter._watchdog_at = "2026-07-15T00:00:00Z"

        # When
        with patch("ly_rasp.reporter.time.perf_counter", side_effect=(0.0, 1.0)):
            delivered = reporter.report({"type": "sql_injection"})

        # Then
        self.assertFalse(delivered)
        self.assertEqual(reporter.delivery_health()["reason"], "cpu_budget_exceeded")

    def test_real_queue_rejects_work_at_reported_capacity(self) -> None:
        # Given
        config = RASPConfig(policy_version=15, queue_capacity=2)
        reporter = Reporter.__new__(Reporter)
        reporter._initialize_runtime_state(config)
        started = threading.Barrier(3)
        release = threading.Event()
        reporter.bridge_client = BlockingBridge(started, release)

        # When
        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(reporter.report, {"type": "sql_injection"}) for _ in range(2)]
            started.wait(timeout=5)
            rejected = reporter.report({"type": "sql_injection"})
            health = reporter.delivery_health()
            release.set()
            delivered = [future.result(timeout=5) for future in futures]

        # Then
        self.assertFalse(rejected)
        self.assertEqual(delivered, [True, True])
        self.assertEqual(reporter.queue_capacity, health["limits"]["queue_capacity"])
        self.assertEqual(reporter.queue_capacity, 2)
        self.assertEqual(health["reason"], "queue_capacity_exceeded")
