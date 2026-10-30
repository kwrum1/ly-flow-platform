import asyncio
import io
import json
from dataclasses import replace
from pathlib import Path

import pytest

from ly_rasp.blocking import RASPBlockedError, handle_detection
from ly_rasp.bridge import BridgeClient
from ly_rasp.config import RASPConfig, set_config
from ly_rasp.correlation import request_scope
from ly_rasp.reporter import set_reporter
from ly_rasp.request_hook import (
    RASPASGIMiddleware,
    RASPRequestBlocked,
    RASPWSGIMiddleware,
    inspect_http_request,
    inspect_request,
    view_from_asgi,
    view_from_wsgi,
)
from ly_rasp.request_rules import (
    RequestLimits,
    RequestView,
    RulePackError,
    load_pack,
    match_request,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
PACK_PATH = REPO_ROOT / "rules" / "rasp" / "request_rules.json"


class RecordingReporter:
    def __init__(self):
        self.events = []

    def report(self, event):
        self.events.append(event)
        return True


@pytest.fixture(scope="module")
def pack():
    return load_pack(str(PACK_PATH))


@pytest.fixture(autouse=True)
def clean_globals():
    yield
    set_reporter(None)
    set_config(None)


def configure(mode="monitor", block_on_hit=False, version=7, **kwargs):
    config = RASPConfig(
        mode=mode,
        block_on_hit=block_on_hit,
        policy_version=version,
        expires_at=None,
        app="test-app",
        **kwargs,
    )
    set_config(config)
    return config


def request(method="GET", path="/api/products", query="", headers=(), body="", request_id="req-1"):
    return RequestView(
        method=method,
        path=path,
        query=query,
        headers=tuple(headers),
        body=body,
        request_id=request_id,
    )


def test_pack_contains_all_request_categories(pack):
    assert pack.schema_version == "lyflow.rasp.request_rules.v1"
    assert pack.paranoia_level == 2
    assert pack.digest
    categories = {rule.category for rule in pack.rules}
    assert {"sqli", "xss", "path_traversal", "lfi", "rfi", "rce", "webshell", "scanner"} <= categories
    assert all(rule.paranoia <= 2 for rule in pack.rules)


def test_benign_request_is_not_matched(pack):
    view = request(
        path="/api/products",
        query="category=books&page=2&sort=name",
        headers=(("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)"), ("Accept", "application/json")),
        body='{"page": 2, "category": "books"}',
    )
    assert match_request(view, pack) == []
    configure()
    inspection = inspect_request(view, pack=pack)
    assert inspection.detected is False
    assert inspection.blocked is False


def test_sqli_request_is_matched(pack):
    view = request(query="id=1%27%20UNION%20SELECT%20username%20FROM%20users--")
    matches = match_request(view, pack)
    assert [match.category for match in matches] == ["sqli"]
    assert matches[0].rule_id == "owasp-crs-942270"


def test_xss_request_is_matched(pack):
    view = request(method="POST", path="/comment", body="<script>alert(document.cookie)</script>")
    matches = match_request(view, pack)
    assert "xss" in {match.category for match in matches}


def test_path_traversal_is_matched(pack):
    view = request(path="/static/../../etc/passwd")
    matches = match_request(view, pack)
    assert [match.category for match in matches] == ["path_traversal"]
    assert matches[0].rule_id == "owasp-crs-930110"


def test_encoded_path_traversal_is_matched(pack):
    view = request(query="file=%2e%2e%2f%2e%2e%2fetc%2fpasswd")
    assert "path_traversal" in {match.category for match in match_request(view, pack)}


def test_scanner_user_agent_is_matched(pack):
    view = request(headers=(("User-Agent", "sqlmap/1.8.2#stable"),))
    matches = match_request(view, pack)
    assert [match.category for match in matches] == ["scanner"]
    assert matches[0].rule_id == "owasp-crs-913100"


def test_json_body_values_are_inspected_like_crs_args(pack):
    sqli = request(method="POST", body='{"id": "1 UNION SELECT name FROM users", "page": 1}')
    assert "sqli" in {match.category for match in match_request(sqli, pack)}
    xss = request(method="POST", body='{"comment": "<script>alert(1)</script>"}')
    assert "xss" in {match.category for match in match_request(xss, pack)}


def test_rce_lfi_rfi_and_webshell_categories(pack):
    assert "rce" in {m.category for m in match_request(request(query="cmd=$(cat /etc/passwd)"), pack)}
    assert "rfi" in {m.category for m in match_request(request(query="url=http://1.2.3.4/shell.txt"), pack)}
    assert "lfi" in {m.category for m in match_request(request(query="tpl=php://filter/read=convert.base64-encode/resource=index.php"), pack)}
    assert "webshell" in {m.category for m in match_request(request(method="POST", body="<?php system($_GET['c']); ?>"), pack)}


def test_detected_request_in_monitor_mode_only_reports(pack):
    configure(mode="monitor")
    reporter = RecordingReporter()
    set_reporter(reporter)
    inspection = inspect_request(request(query="id=1%20UNION%20SELECT%20name%20FROM%20users"), pack=pack)

    assert inspection.detected is True
    assert inspection.blocked is False
    assert inspection.would_block is False
    assert len(reporter.events) == 1
    event = reporter.events[0]
    assert event["blocked"] is False
    assert event["would_block"] is False
    assert event["mode"] == "monitor"
    assert event["attack_type"] == "sql_injection"
    assert event["rule_id"] == "request-sqli-owasp-crs-942270"
    assert event["details"]["phase"] == "request"
    assert event["details"]["rule_pack_digest"] == pack.digest


def test_detected_request_in_dry_run_reports_would_block(pack):
    configure(mode="block", block_on_hit=False)
    reporter = RecordingReporter()
    set_reporter(reporter)

    inspection = inspect_request(request(body="<script>alert(1)</script>"), pack=pack)

    assert inspection.blocked is False
    assert inspection.would_block is True
    assert len(reporter.events) == 1
    event = reporter.events[0]
    assert event["blocked"] is False
    assert event["would_block"] is True
    assert event["mode"] == "dry_run"


def test_detected_request_in_block_mode_raises(pack):
    configure(mode="block", block_on_hit=True)
    reporter = RecordingReporter()
    set_reporter(reporter)

    with pytest.raises(RASPRequestBlocked) as caught:
        inspect_request(request(path="/download", query="file=../../etc/shadow"), pack=pack)

    assert isinstance(caught.value, RASPBlockedError)
    assert caught.value.attack_type == "path_traversal"
    assert caught.value.rule_id == "owasp-crs-930110"
    assert len(reporter.events) == 1
    assert reporter.events[0]["blocked"] is True
    assert reporter.events[0]["mode"] == "protect"


def test_unsigned_block_policy_degrades_to_dry_run(pack):
    configure(mode="block", block_on_hit=True, version=0)
    reporter = RecordingReporter()
    set_reporter(reporter)

    inspection = inspect_request(request(query="id=1%20UNION%20SELECT%20a%20FROM%20b"), pack=pack)
    assert inspection.blocked is False
    assert inspection.would_block is True


def test_request_and_sink_events_are_deduplicated(pack):
    configure(mode="monitor")
    reporter = RecordingReporter()
    set_reporter(reporter)

    with request_scope("req-dedupe-request-first"):
        inspect_request(request(query="id=1%20UNION%20SELECT%20a%20FROM%20b"), pack=pack)
        handle_detection("sql_injection", {"evidence": "union select"}, "cursor.execute", "SELECT 1")

    assert len(reporter.events) == 1
    assert reporter.events[0]["details"]["phase"] == "request"


def test_sink_event_first_suppresses_request_duplicate(pack):
    configure(mode="monitor")
    reporter = RecordingReporter()
    set_reporter(reporter)

    with request_scope("req-dedupe-sink-first"):
        handle_detection("sql_injection", {"evidence": "union select"}, "cursor.execute", "SELECT 1")
        inspection = inspect_request(request(query="id=1%20UNION%20SELECT%20a%20FROM%20b"), pack=pack)

    assert inspection.detected is True
    assert len(reporter.events) == 1
    assert "hooked_function" in reporter.events[0]["details"]


def test_missing_pack_fails_open(tmp_path):
    config = configure(request_rules_path=str(tmp_path / "missing.json"))
    reporter = RecordingReporter()
    set_reporter(reporter)

    inspection = inspect_request(request(query="id=1%20UNION%20SELECT%20a%20FROM%20b"), pack=None, config=config)
    assert inspection.enabled is False
    assert inspection.detected is False
    assert "unavailable" in inspection.reason
    assert reporter.events == []


def test_body_limit_bounds_inspection(pack):
    limited = replace(pack, limits=replace(pack.limits, max_body_bytes=64))
    body = "A" * 100 + "<script>alert(1)</script>"
    assert match_request(request(method="POST", body=body), limited) == []
    assert match_request(request(method="POST", body=body), pack)


def test_wsgi_view_reads_and_replays_body(pack):
    stream = io.BytesIO(b'{"url": "http://127.0.0.1/admin"}')
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/proxy",
        "QUERY_STRING": "",
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(stream.getvalue())),
        "HTTP_X_REQUEST_ID": "wsgi-req-1",
        "wsgi.input": stream,
    }
    view = view_from_wsgi(environ, RequestLimits())
    assert view.method == "POST"
    assert view.request_id == "wsgi-req-1"
    assert "127.0.0.1" in view.body
    assert environ["wsgi.input"].read() == b'{"url": "http://127.0.0.1/admin"}'


def test_wsgi_middleware_blocks_in_block_mode(pack):
    configure(mode="block", block_on_hit=True)
    set_reporter(RecordingReporter())
    called = []
    status = {}

    def app(environ, start_response):
        called.append(True)
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]

    def start_response(value, headers):
        status["value"] = value
        status["headers"] = dict(headers)

    middleware = RASPWSGIMiddleware(app, pack=pack)
    body = b"".join(middleware({
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/download",
        "QUERY_STRING": "file=../../etc/passwd",
        "CONTENT_LENGTH": "0",
        "wsgi.input": io.BytesIO(b""),
    }, start_response))

    assert status["value"].startswith("403")
    assert "Connection" not in status["headers"]
    assert called == []
    assert json.loads(body)["error"] == "rasp_blocked"


def test_wsgi_middleware_passes_monitor_mode(pack):
    configure(mode="monitor")
    set_reporter(RecordingReporter())
    called = []
    status = {}

    def app(environ, start_response):
        called.append(True)
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]

    middleware = RASPWSGIMiddleware(app, pack=pack)
    body = b"".join(middleware({
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/download",
        "QUERY_STRING": "file=../../etc/passwd",
        "CONTENT_LENGTH": "0",
        "wsgi.input": io.BytesIO(b""),
    }, lambda value, headers: status.update(value=value)))

    assert status["value"].startswith("200")
    assert called == [True]
    assert body == b"ok"


def test_wsgi_middleware_bootstraps_config_from_env(pack, monkeypatch):
    monkeypatch.setenv("RASP_MODE", "block")
    monkeypatch.setenv("RASP_BLOCK_ON_HIT", "true")
    monkeypatch.setenv("RASP_POLICY_VERSION", "9")
    set_config(None)
    set_reporter(RecordingReporter())
    status = {}

    middleware = RASPWSGIMiddleware(lambda environ, start_response: [b"ok"], pack=pack)
    body = b"".join(middleware({
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/download",
        "QUERY_STRING": "file=../../etc/passwd",
        "CONTENT_LENGTH": "0",
        "wsgi.input": io.BytesIO(b""),
    }, lambda value, headers: status.update(value=value)))

    assert status["value"].startswith("403")
    assert json.loads(body)["error"] == "rasp_blocked"


def test_asgi_middleware_blocks_in_block_mode(pack):
    configure(mode="block", block_on_hit=True)
    set_reporter(RecordingReporter())
    sent = []
    called = []

    async def app(scope, receive, send):
        called.append(True)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    queue = [{"type": "http.request", "body": b"", "more_body": False}]

    async def receive():
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/download",
        "query_string": b"file=../../etc/passwd",
        "headers": [(b"user-agent", b"Mozilla/5.0")],
    }
    asyncio.run(RASPASGIMiddleware(app, pack=pack)(scope, receive, send))

    assert called == []
    assert sent[0]["status"] == 403
    assert json.loads(sent[1]["body"])["error"] == "rasp_blocked"


def test_asgi_middleware_passes_monitor_mode(pack):
    configure(mode="monitor")
    set_reporter(RecordingReporter())
    sent = []
    called = []

    async def app(scope, receive, send):
        called.append(True)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    queue = [{"type": "http.request", "body": b"", "more_body": False}]

    async def receive():
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/download",
        "query_string": b"file=../../etc/passwd",
        "headers": [],
    }
    asyncio.run(RASPASGIMiddleware(app, pack=pack)(scope, receive, send))

    assert called == [True]
    assert sent[0]["status"] == 200


def test_asgi_view_and_generic_helper(pack):
    view = view_from_asgi({
        "type": "http",
        "method": "POST",
        "path": "/comment",
        "query_string": b"",
        "headers": [(b"x-request-id", b"asgi-req-1"), (b"user-agent", b"sqlmap")],
    }, b"<script>alert(1)</script>", RequestLimits())
    assert view.request_id == "asgi-req-1"
    configure(mode="monitor")
    set_reporter(RecordingReporter())
    inspection = inspect_http_request(
        "POST", "/comment", headers={"User-Agent": "sqlmap/1.8"}, body="<script>alert(1)</script>", pack=pack
    )
    assert inspection.detected is True
    assert {match.category for match in inspection.matches} >= {"scanner", "xss"}


def test_bridge_event_types_stay_in_canonical_set():
    config = RASPConfig(
        agent_id="agent-1",
        policy_id="policy-1",
        policy_version=1,
        app="app",
        bridge_token="token",
    )
    client = BridgeClient(config)
    expected = {
        "sqli": "rasp.sql",
        "xss": "rasp.http",
        "path_traversal": "rasp.file",
        "lfi": "rasp.file",
        "rfi": "rasp.http",
        "rce": "rasp.command",
        "webshell": "rasp.command",
        "scanner": "rasp.http",
    }
    for attack_type, event_type in expected.items():
        event = client.build_event({"attack_type": attack_type, "rule_id": "rule-1", "evidence": "evidence"})
        assert event["event_type"] == event_type
