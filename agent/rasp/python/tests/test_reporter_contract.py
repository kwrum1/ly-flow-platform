"""RASP reporter contract tests."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ly_rasp.config import RASPConfig
from ly_rasp.bridge import BridgeClient
from ly_rasp.reporter import Reporter


def test_reporter_passes_acl_credentials_to_redis(monkeypatch):
    captured = {}

    class FakeRedis:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def ping(self):
            return True

    monkeypatch.setattr("ly_rasp.reporter.REDIS_AVAILABLE", True)
    monkeypatch.setattr("ly_rasp.reporter.redis.Redis", FakeRedis)
    config = RASPConfig(
        server_addr="redis:6379",
        redis_username="lyflow",
        redis_password="new-secret",
        redis_legacy_password="legacy-secret",
    )

    Reporter(config)

    assert captured["username"] == "lyflow"
    assert captured["password"] == "new-secret"


def test_sql_detector_event_normalizes_to_alerts_rasp_contract():
    config = RASPConfig(server_addr="nonexistent:9999", agent_id="agent-python", app="checkout-api")
    reporter = Reporter(config)

    event = reporter.normalize_event({
        "type": "sql_injection",
        "details": {"rule_id": "py-sqli-001", "severity": "high", "matched_pattern": "UNION SELECT"},
    })

    assert event["type"] == "rasp.attack"
    assert event["agent_id"] == "agent-python"
    assert event["language"] == "python"
    assert event["app"] == "checkout-api"
    assert event["attack_type"] == "sql_injection"
    assert event["blocked"] is False
    assert event["action"] == "log"
    assert event["mode"] == "monitor"
    assert event["rule_id"] == "py-sqli-001"


def test_benign_sql_has_no_detector_event():
    from ly_rasp.detector.sql_injection import detect_sql_injection

    assert detect_sql_injection("SELECT id, name FROM users WHERE status = 'active'") is None


def test_reporter_enforces_max_events_per_second(monkeypatch):
    class FakeRedisClient:
        def __init__(self):
            self.events = []

        def xadd(self, stream, event):
            self.events.append((stream, event))

    monkeypatch.setattr("ly_rasp.reporter.time.monotonic", lambda: 100.0)
    reporter = Reporter.__new__(Reporter)
    reporter.config = RASPConfig(policy_version=1, max_events_per_second=2)
    reporter.bridge_client = None
    reporter.redis_client = FakeRedisClient()
    reporter._rate_second = -1
    reporter._rate_count = 0
    reporter._health_status = "healthy"
    reporter._health_reason = "ready"
    reporter._exporter_available = True

    assert reporter.report({"type": "sql_injection"}) is True
    assert reporter.report({"type": "sql_injection"}) is True
    assert reporter.report({"type": "sql_injection"}) is False
    assert len(reporter.redis_client.events) == 2


def test_bridge_client_builds_only_policy_bound_event_fields():
    config = RASPConfig(
        agent_id="agent-python",
        app="checkout-api",
        bridge_token="bridge-secret",
        policy_id="policy-12",
        policy_version=12,
    )
    client = BridgeClient(config)

    event = client.build_event({
        "type": "rasp.attack",
        "attack_type": "command_injection",
        "severity": "low",
        "rule_id": "inert-command",
        "evidence": "echo todo12-inert",
        "arbitrary": {"nested": True},
    })

    assert event["schema_version"] == "lyflow.rasp_bridge_event.v1"
    assert event["agent_id"] == "agent-python"
    assert event["policy_id"] == "policy-12"
    assert event["policy_version"] == 12
    assert event["event_type"] == "rasp.command"
    assert "arbitrary" not in event


def test_reporter_uses_authenticated_bridge_when_configured(monkeypatch):
    captured = []
    monkeypatch.setattr("ly_rasp.reporter.BridgeClient.report", lambda _client, event: captured.append(event) or True)
    monkeypatch.setattr("ly_rasp.reporter.REDIS_AVAILABLE", False)
    reporter = Reporter(RASPConfig(
        agent_id="agent-python",
        bridge_token="bridge-secret",
        policy_id="policy-12",
        policy_version=12,
    ))

    delivered = reporter.report({"type": "command_injection", "evidence": "echo todo12-inert"})

    assert delivered is True
    assert captured[0]["agent_id"] == "agent-python"
