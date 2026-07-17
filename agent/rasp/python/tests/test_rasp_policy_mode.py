from datetime import datetime, timedelta, timezone
import importlib
import sys

from ly_rasp.config import RASPConfig, effective_mode, normalize_mode, should_block


def test_invalid_mode_falls_back_to_monitor():
    assert normalize_mode("godmode") == "monitor"


def test_protect_mode_cannot_activate_without_signed_lifecycle():
    assert normalize_mode("protect") == "monitor"
    assert should_block(RASPConfig(mode="protect", block_on_hit=True)) is False
    assert should_block(RASPConfig(mode="protect", block_on_hit=False)) is False
    assert should_block(RASPConfig(mode="monitor", block_on_hit=True)) is False


def test_expired_policy_applies_declared_fail_behavior():
    now = datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc)
    expired = now - timedelta(seconds=1)

    assert effective_mode(RASPConfig(mode="monitor", expires_at=expired, fail_behavior="disable"), now) == "off"
    assert effective_mode(RASPConfig(mode="off", expires_at=expired, fail_behavior="monitor"), now) == "monitor"


def test_sitecustomize_does_not_autoload_without_verified_policy_ack(monkeypatch):
    calls = []
    monkeypatch.setenv("LY_RASP_AUTOLOAD", "true")
    monkeypatch.delenv("RASP_POLICY_VERIFIED_ACK", raising=False)
    monkeypatch.setattr("ly_rasp.enable", lambda: calls.append(True))
    sys.modules.pop("ly_rasp.sitecustomize", None)

    importlib.import_module("ly_rasp.sitecustomize")

    assert calls == []


def test_sitecustomize_autoloads_after_verified_policy_ack(monkeypatch):
    calls = []
    monkeypatch.setenv("LY_RASP_AUTOLOAD", "true")
    monkeypatch.setenv("RASP_POLICY_VERIFIED_ACK", "true")
    monkeypatch.setattr("ly_rasp.enable", lambda: calls.append(True))
    sys.modules.pop("ly_rasp.sitecustomize", None)

    importlib.import_module("ly_rasp.sitecustomize")

    assert calls == [True]
