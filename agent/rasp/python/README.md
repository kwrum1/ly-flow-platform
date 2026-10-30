# LyFlow Python RASP — request-level hook (P3)

This package provides two layers:

| Layer | What it protects | How it is enabled |
| --- | --- | --- |
| Sink hook | SQL, command, file, deserialization, SSRF sinks | `LY_RASP_AUTOLOAD=true` + `RASP_POLICY_VERIFIED_ACK=true` (auto_prepend / `sitecustomize`) |
| Request hook | OWASP CRS request rules (SQLi, XSS, LFI/RFI, RCE, webshell, scanner, path traversal) | Add the WSGI/ASGI middleware, or call `inspect_http_request(...)` at request ingress |

The request hook is **monitor-first**. It never blocks unless the signed policy
is `block`, the server promoted it (`block_on_hit=true`) and the policy has not
expired. In dry-run it reports `would_block=true` and lets the request run.

## 1. Install the rule pack

The server exposes a deterministic JSON pack generated from OWASP CRS request
rules at paranoia level 1-2:

```bash
# metadata (rule count, categories, digest, limits)
curl -fsS "$API_SERVER/api/v1/rasp/request-rules/status"

# probe-consumable pack (default paranoia level 2)
curl -fsS "$API_SERVER/api/v1/rasp/request-rules/download" \
  -o /etc/lyflow/rasp/request_rules.json

# paranoia level 1 only
curl -fsS "$API_SERVER/api/v1/rasp/request-rules/download?paranoia=1" \
  -o /etc/lyflow/rasp/request_rules.json
```

The response is the bare pack (not wrapped in `{code,data}`) so a probe can
write it to disk directly. It carries an `ETag` (the pack digest); conditional
requests with `If-None-Match` return `304`.

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `LY_RASP_REQUEST_HOOK` | `true` | Enable/disable request inspection in the middleware |
| `LY_RASP_REQUEST_RULES` | `/etc/lyflow/rasp/request_rules.json` | Pack path |
| `LY_RASP_REQUEST_MAX_BODY_BYTES` | `65536` | Upper bound for body inspection (the pack limit can only lower it) |

A missing, stale or malformed pack disables request inspection (fail-open). It
never blocks traffic.

## 2. WSGI integration

Generic WSGI (the outermost middleware is the cheapest place to inspect):

```python
# wsgi.py
from myapp import application
from ly_rasp import RASPWSGIMiddleware

application = RASPWSGIMiddleware(application)
```

Flask:

```python
from flask import Flask
from ly_rasp import RASPWSGIMiddleware

app = Flask(__name__)
# ... routes ...

# Gunicorn/uWSGI entry point
application = RASPWSGIMiddleware(app)
```

Django (`wsgi.py`):

```python
import os
from django.core.wsgi import get_wsgi_application
from ly_rasp import RASPWSGIMiddleware

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project.settings")
application = RASPWSGIMiddleware(get_wsgi_application())
```

The middleware reads `method`, `path`, `query`, headers and body (bounded by
the pack limits), reports through the existing RASP reporter/bridge, and
returns `403` with a JSON body when blocking is promoted:

```json
{"error":"rasp_blocked","phase":"request","attack_type":"sqli","rule_id":"owasp-crs-942270"}
```

Requests hitting `multipart/form-data` are inspected without reading the body
(file names and other headers are still covered). Bodies are replayed to the
application unchanged.

## 3. ASGI integration

FastAPI / Starlette:

```python
from fastapi import FastAPI
from ly_rasp import RASPASGIMiddleware

app = FastAPI()
app.add_middleware(RASPASGIMiddleware)
```

The middleware consumes only enough `http.request` messages to fill the body
limit, inspects the request, then replays the consumed messages to the
application. `websocket` and `lifespan` scopes pass through untouched.

## 4. Framework-neutral helper (Django middleware, aiohttp, custom servers)

```python
from ly_rasp import inspect_http_request

inspection = inspect_http_request(
    method=request.method,
    path=request.path,
    query=request.META.get("QUERY_STRING", ""),
    headers=dict(request.headers),
    body=request.body[:65536].decode("utf-8", "replace"),
    request_id=request.headers.get("X-Request-ID", ""),
)
if inspection.detected:
    logger.info("RASP request hit: %s", [m.rule_id for m in inspection.matches])
```

`inspect_http_request` raises `RASPBlockedError` in block mode. For full
request-level de-duplication with sink hooks, wrap the request in
`ly_rasp.correlation.request_scope(...)` (the middleware already does this).

## 5. Enabling with auto_prepend (`sitecustomize` / `PYTHONPATH`)

The sink hooks can be loaded without touching application code:

```bash
export PYTHONPATH=/opt/ly-agent/rasp/python:$PYTHONPATH
export LY_RASP_AUTOLOAD=true
export RASP_POLICY_VERIFIED_ACK=true
```

That path enables **sink** hooks only. Python has no portable way to wrap an
arbitrary WSGI/ASGI application from `sitecustomize`, so request-level
inspection must be attached at the application entry point (section 2/3/4).
The single-file probe served at `/api/v1/agent/rasp/probe/python` remains the
sink-level auto_prepend asset; deploy the `ly_rasp` package alongside it to use
the request hook.

## 6. Policy and modes

The hook reuses the signed RASP policy delivered over the bridge. It does not
create a second policy surface.

| Policy | `block_on_hit` | Result |
| --- | --- | --- |
| `monitor` | any | report `blocked=false`, `would_block=false`, request continues |
| `block` | `false` | dry-run: report `would_block=true`, request continues |
| `block` | `true` | report `blocked=true`, raise `RASPBlockedError`, middleware returns 403 |
| `off` / expired | any | no inspection |

Events use the existing bridge event schema, whose canonical `event_type` set is
`rasp.sql`, `rasp.command`, `rasp.file`, `rasp.deserialization` and `rasp.http`.
The precise request category travels in `rule_id`
(`request-<category>-<crs-rule-id>`) and in the event details (`phase=request`,
`category`, `rule_id`, `rule_pack_digest`, `http_method`, `http_path`, `target`,
`request_id`, bounded `evidence`).

### De-duplication

Each request gets a `RequestScope` (ContextVar). The first event per attack
category wins; later request rules and sink hooks for the same category in the
same request are suppressed. This is intentionally coarse: it prevents
duplicate alerts, not duplicate enforcement. Enforcement still follows the
policy even when the event was already reported.

## 7. Rule pack format

```json
{
  "schema_version": "lyflow.rasp.request_rules.v1",
  "source": "owasp-crs",
  "source_version": "4.31.0-dev",
  "paranoia_level": 2,
  "limits": {
    "max_path_bytes": 4096,
    "max_query_bytes": 8192,
    "max_body_bytes": 65536,
    "max_headers_bytes": 8192,
    "max_header_count": 100,
    "max_evidence_bytes": 256
  },
  "rules": [
    {
      "id": "owasp-crs-942270",
      "category": "sqli",
      "severity": "critical",
      "paranoia": 1,
      "operator": "rx",
      "pattern": "(?i)union.*?select.*?from",
      "targets": ["body", "cookies", "query"],
      "message": "Looking for basic sql injection...",
      "action": "block",
      "source": "owasp-crs"
    }
  ],
  "digest": "sha256:..."
}
```

Supported targets: `path`, `query`, `body`, `headers`, `cookies`, `method`,
`request_line`, `header:<name>`. `ARGS` in CRS is expanded to `query` + `body`;
individual URL-encoded / JSON string parameter values are inspected in addition
to the raw field (mirroring CRS `ARGS` semantics). URL-decoding is applied up
to two passes.

Only `rx` and `pm` operators are shipped. `@detectSQLi` cannot be represented
as a regular expression; it stays covered by the sink-level SQL detector and
the platform engine. Rule 913100 (`@pmFromFile`) is shipped as `pm` with the
scanner User-Agent list inlined.

The canonical pack is generated by the server and checked in at
`rules/rasp/request_rules.json`; do not edit it by hand. Regenerate with:

```bash
cd server
LY_RASP_WRITE_REQUEST_RULES=1 go test ./cmd -run TestRASPRequestRulePackArtifactMatchesGenerator
```

## 8. Extending to Java / PHP / Node.js

The pack is language-neutral. A runtime only needs three things:

1. A bounded request view: method, path, query, headers, body.
2. The same target expansion (`ARGS` → query + body, decoded variants).
3. `rx` (with a PCRE/RE2-compatible engine) and `pm` evaluators.

Suggested extension points:

| Runtime | Hook |
| --- | --- |
| Java | Servlet `Filter` before `chain.doFilter`, or Spring `HandlerInterceptor` |
| PHP | `auto_prepend_file` that inspects `$_SERVER` + `php://input` before the framework boots |
| Node.js | Express middleware (`app.use`) or an `http.Server` `'request'` listener |

All runtimes must reuse the existing policy (`mode` + `block_on_hit` +
`expires_at`) and report the same event fields, otherwise the platform cannot
correlate request and sink events.

## 9. Rollback

1. Set `LY_RASP_REQUEST_HOOK=false` (no restart needed for new requests in
   process-based servers that re-read the env; restart workers for certainty).
2. Or remove the middleware from the WSGI/ASGI entry point.
3. Or revert the policy to an active `monitor` version; the hook then reports
   without blocking.
4. Deleting the pack file disables request inspection (fail-open) and leaves
   sink hooks untouched.
