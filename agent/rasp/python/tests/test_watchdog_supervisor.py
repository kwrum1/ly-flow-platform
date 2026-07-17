from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from ly_rasp.config import RASPConfig
from ly_rasp.reporter import Reporter
from ly_rasp.runtime_health import WatchdogRuntime


class ScriptedWatchdogClock:
    def __init__(self) -> None:
        self._monotonic = 0.0
        self._utc = datetime(2026, 7, 15, tzinfo=timezone.utc)

    def monotonic(self) -> float:
        return self._monotonic

    def utc_now(self) -> str:
        return self._utc.isoformat().replace("+00:00", "Z")

    def wait(self, stopped: threading.Event, _timeout: float) -> bool:
        if stopped.is_set():
            return True
        self._monotonic += 2.0
        self._utc += timedelta(seconds=2)
        return False


class TestWatchdogSupervisor(TestCase):
    def test_production_supervisor_exhausts_restart_budget_count10(self) -> None:
        for iteration in range(10):
            # Given
            with TemporaryDirectory() as temporary:
                fallback = Path(temporary) / f"watchdog-{iteration}.jsonl"
                clock = ScriptedWatchdogClock()
                runtime = WatchdogRuntime(
                    clock=clock,
                    stale_after_seconds=1.0,
                    check_interval_seconds=0.1,
                    restart_backoff_seconds=0.25,
                )
                config = RASPConfig(
                    policy_version=15,
                    restart_budget=2,
                    fallback_path=str(fallback),
                )
                with patch("ly_rasp.reporter.REDIS_AVAILABLE", False):
                    reporter = Reporter(config, runtime)

                    # When
                    reporter.run_watchdog()

                    # Then
                    health = reporter.delivery_health()
                    self.assertEqual(health["schema_version"], "lyflow.control_health.v1")
                    self.assertEqual(health["reason"], "restart_budget_exhausted")
                    self.assertEqual(health["restart_count"], 2)
                    self.assertFalse(health["prevention_enabled"])
                    self.assertEqual(config.mode, "off")
                    records = [json.loads(line) for line in fallback.read_text(encoding="utf-8").splitlines()]
                    self.assertEqual(records[-1]["event"]["reason"], "restart_budget_exhausted")
                    reporter.shutdown()
                    self.assertFalse(reporter.watchdog_running)

    def test_started_supervisor_has_clean_shutdown(self) -> None:
        # Given
        runtime = WatchdogRuntime(stale_after_seconds=60.0, check_interval_seconds=60.0)
        with patch("ly_rasp.reporter.REDIS_AVAILABLE", False):
            reporter = Reporter(RASPConfig(policy_version=15), runtime)

            # When
            reporter.start()
            reporter.shutdown()

            # Then
            self.assertFalse(reporter.watchdog_running)
