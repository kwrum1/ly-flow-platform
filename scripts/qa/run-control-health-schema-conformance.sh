#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

python3 - "$root/contracts/control-health/v1/schema.json" "$root/contracts/control-health/v1/fixture.json" <<'PY'
import json
import sys
from datetime import datetime
from pathlib import Path

schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
fixture = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
required = schema["required"]
assert list(fixture) == required
assert set(schema["properties"]) == set(required)
assert fixture["schema_version"] == "lyflow.control_health.v1"
assert fixture["event_type"] == "control.health"
assert isinstance(fixture["prevention_enabled"], bool)
assert isinstance(fixture["restart_count"], int) and fixture["restart_count"] >= 0
datetime.fromisoformat(fixture["watchdog_at"].replace("Z", "+00:00"))
assert list(fixture["fail_policy"]) == schema["properties"]["fail_policy"]["required"]
assert list(fixture["limits"]) == schema["properties"]["limits"]["required"]
assert list(fixture["publication"]) == schema["properties"]["publication"]["required"]
assert all(isinstance(value, int) and not isinstance(value, bool) and value > 0 for value in fixture["limits"].values())
assert fixture["publication"]["status"] in {"healthy", "degraded"}
assert isinstance(fixture["publication"]["retry_count"], int)
assert isinstance(fixture["publication"]["last_error"], str)
PY

(cd "$root/agent" && GOWORK=off go test ./cmd -run '^TestRuntimeControlHealth_matches_shared_canonical_fixture_bytes$' -count=1 >/dev/null)
(cd "$root/security-engine" && GOWORK=off go test ./engine -run '^TestRuntimeHealth_matches_shared_canonical_fixture_bytes$' -count=1 >/dev/null)
(cd "$root/agent/rasp/python" && python3 -m unittest -q tests.test_runtime_health.TestPythonRuntimeHealth.test_shared_canonical_fixture_matches_bytes >/dev/null)
(cd "$root/agent/rasp/java" && mvn -q -Dtest=CanonicalControlHealthFixtureTest test >/dev/null)

printf 'control-health schema conformance: agent security-engine python java PASS\n'
