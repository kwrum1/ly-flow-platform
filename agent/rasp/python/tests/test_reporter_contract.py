"""RASP reporter contract tests."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ly_rasp.config import RASPConfig
from ly_rasp.reporter import Reporter


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
