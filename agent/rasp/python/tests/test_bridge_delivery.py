from __future__ import annotations

import json
import hashlib
import hmac
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar, NoReturn
from unittest import TestCase
from urllib.error import HTTPError
from urllib.request import Request

from ly_rasp.bridge import BridgeClient, ControlHealthPublicationError
from ly_rasp.config import RASPConfig


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


class RejectingOpener:
    def open(self, request: Request, timeout: float) -> NoReturn:
        del request, timeout
        raise HTTPError("http://127.0.0.1", 401, "Unauthorized", {}, None)


class AcceptedResponse:
    status = 202

    def __enter__(self) -> "AcceptedResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class RecoveringControlHealthOpener:
    def __init__(self) -> None:
        self.failing = True

    def open(self, request: Request, timeout: float) -> AcceptedResponse:
        del request, timeout
        if self.failing:
            raise OSError("fixture control health outage")
        return AcceptedResponse()


JSONScalar = str | int | float | bool | None


class BridgeHandler(BaseHTTPRequestHandler):
    delivered: ClassVar[dict[str, JSONScalar] | None] = None
    invalid_signature: ClassVar[bool] = False

    def do_GET(self) -> None:
        self._require_authentication()
        response = {
            "schema_version": "lyflow.rasp_bridge_config.v1",
            "agent_id": "agent-python",
            "policy_id": "policy-12",
            "policy_version": 12,
            "policy_mode": "monitor",
            "expires_at": "2099-01-01T00:00:00Z",
            "bridge_token": "bridge-secret",
            "limits": {
                "queue_capacity": 128,
                "read_bytes": 65536,
                "cpu_budget_ms": 50,
                "memory_bytes": 1048576,
                "restart_budget": 3,
            },
        }
        canonical = json.dumps(response, sort_keys=True, separators=(",", ":")).encode("utf-8")
        response["config_signature"] = hmac.new(b"bridge-secret", canonical, hashlib.sha256).hexdigest()
        if type(self).invalid_signature:
            response["config_signature"] = "0" * 64
        body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        self._require_authentication()
        length = int(self.headers["Content-Length"])
        type(self).delivered = json.loads(self.rfile.read(length))
        self.send_response(202)
        self.end_headers()

    def log_message(self, _format: str, *args: JSONScalar) -> None:
        del args

    def _require_authentication(self) -> None:
        if self.headers.get("X-Ly-RASP-Token") != "bridge-secret":
            raise AssertionError("bridge token missing")
        if self.headers.get("X-Lyflow-Agent-ID") != "agent-python":
            raise AssertionError("agent binding missing")


class TestPythonBridgeDelivery(TestCase):
    def test_control_health_publication_retries_and_recovers(self) -> None:
        # Given
        with tempfile.TemporaryDirectory() as directory:
            client = BridgeClient(RASPConfig(
                bridge_token="bridge-secret",
                agent_id="agent-python",
                policy_version=12,
                fallback_path=str(Path(directory) / "fallback.jsonl"),
            ))
            opener = RecoveringControlHealthOpener()
            client._opener = opener

            # When
            with self.assertRaises(ControlHealthPublicationError):
                client.record_control_failure("exporter_unavailable")
            failed = client.control_health("exporter_unavailable")
            opener.failing = False
            client.record_control_failure("ready")
            recovered = client.control_health("ready")

        # Then
        self.assertEqual(failed["publication"]["status"], "degraded")
        self.assertEqual(failed["publication"]["retry_count"], 3)
        self.assertEqual(recovered["publication"], {"status": "healthy", "retry_count": 3, "last_error": ""})
        self.assertTrue(recovered["prevention_enabled"])

    def test_authenticated_local_delivery_uses_strict_policy_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            server = ThreadingHTTPServer(("127.0.0.1", 0), BridgeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                config = RASPConfig(
                    bridge_url=f"http://127.0.0.1:{server.server_port}",
                    bridge_token="bridge-secret",
                    agent_id="agent-python",
                    fallback_path=str(Path(directory) / "fallback.jsonl"),
                    config_refresh_seconds=0,
                    queue_capacity=2,
                )
                delivered = BridgeClient(config).report({
                    "attack_type": "command_injection",
                    "severity": "low",
                    "rule_id": "inert-command",
                    "evidence": "echo todo12-inert",
                    "app": "todo12-python-fixture",
                    "arbitrary": {"nested": True},
                })
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

        self.assertTrue(delivered)
        event = BridgeHandler.delivered
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["schema_version"], "lyflow.rasp_bridge_event.v1")
        self.assertEqual(event["agent_id"], "agent-python")
        self.assertEqual(event["policy_id"], "policy-12")
        self.assertEqual(event["policy_version"], 12)
        self.assertEqual(config.queue_capacity, 2)
        self.assertNotIn("arbitrary", event)

    def test_invalid_config_signature_disables_prevention_and_persists_control_health(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fallback = Path(directory) / "fallback.jsonl"
            server = ThreadingHTTPServer(("127.0.0.1", 0), BridgeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            BridgeHandler.invalid_signature = True
            thread.start()
            try:
                config = RASPConfig(
                    bridge_url=f"http://127.0.0.1:{server.server_port}",
                    bridge_token="bridge-secret",
                    agent_id="agent-python",
                    fallback_path=str(fallback),
                    config_refresh_seconds=0,
                )
                delivered = BridgeClient(config).report({"attack_type": "sql_injection", "evidence": "SELECT 1"})
            finally:
                BridgeHandler.invalid_signature = False
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            health = BridgeHandler.delivered

        self.assertFalse(delivered)
        self.assertEqual(config.mode, "off")
        self.assertIsNotNone(health)
        assert health is not None
        self.assertEqual(set(health), CANONICAL_HEALTH_FIELDS)
        self.assertEqual(health["schema_version"], "lyflow.control_health.v1")
        self.assertEqual(health["reason"], "config_signature_invalid")
        self.assertFalse(health["prevention_enabled"])

    def test_unavailable_bridge_persists_integrity_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fallback = Path(directory) / "fallback.jsonl"
            client = BridgeClient(RASPConfig(
                bridge_url="http://127.0.0.1:1",
                bridge_token="bridge-secret",
                agent_id="agent-python",
                policy_id="policy-12",
                policy_version=12,
                fallback_path=str(fallback),
                config_refresh_seconds=0,
            ))
            delivered = client.report({"attack_type": "sql_injection", "evidence": "SELECT 1"})
            records = [json.loads(line) for line in fallback.read_text(encoding="utf-8").splitlines()]

        self.assertFalse(delivered)
        self.assertTrue(records[0]["payload_sha256"])
        self.assertTrue(records[-1]["record_sha256"])
        self.assertEqual(records[-1]["policy_version"], 12)
        self.assertEqual(records[-1]["event"]["publication"]["retry_count"], 3)

    def test_authorization_failure_fails_closed_and_emits_canonical_health(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fallback = Path(directory) / "fallback.jsonl"
            config = RASPConfig(
                bridge_token="invalid-secret",
                agent_id="agent-python",
                policy_version=12,
                fallback_path=str(fallback),
                config_refresh_seconds=0,
            )
            client = BridgeClient(config)
            client._opener = RejectingOpener()

            delivered = client.report({"attack_type": "sql_injection", "evidence": "SELECT 1"})
            record = json.loads(fallback.read_text(encoding="utf-8"))

        self.assertFalse(delivered)
        self.assertEqual(config.mode, "off")
        self.assertEqual(client.last_health_reason, "authorization_failed")
        self.assertEqual(set(record["event"]), CANONICAL_HEALTH_FIELDS)
        self.assertEqual(record["event"]["reason"], "authorization_failed")

    def test_exporter_outage_remains_fail_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = RASPConfig(
                bridge_url="http://127.0.0.1:1",
                bridge_token="bridge-secret",
                agent_id="agent-python",
                policy_version=12,
                fallback_path=str(Path(directory) / "fallback.jsonl"),
                config_refresh_seconds=0,
            )
            client = BridgeClient(config)

            delivered = client.report({"attack_type": "sql_injection", "evidence": "SELECT 1"})

        self.assertFalse(delivered)
        self.assertEqual(config.mode, "monitor")
        self.assertEqual(client.last_health_reason, "exporter_unavailable")
        self.assertTrue(client.control_health()["prevention_enabled"])
        self.assertEqual(client.control_health()["publication"]["status"], "degraded")
        self.assertEqual(client.control_health()["publication"]["retry_count"], 3)
