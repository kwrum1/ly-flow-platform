#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
module="$root/agent/rasp/java"
iterations=10
if [[ $# -gt 0 ]]; then
  [[ $# -eq 2 && $1 == --iterations && $2 =~ ^[1-9][0-9]*$ ]] || {
    printf 'usage: %s [--iterations COUNT]\n' "$0" >&2
    exit 2
  }
  iterations=$2
fi

tmp=$(mktemp -d)
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

java_version=$(java -version 2>&1 | sed -n '1p')
maven_version=$(mvn -version | sed -n '1p')
[[ $java_version == *'17.0.19'* ]]
[[ $maven_version == *'3.9.9'* ]]

expected_digest=
for ((iteration = 1; iteration <= iterations; iteration++)); do
  log="$tmp/maven-$iteration.log"
  (cd "$module" && mvn -q -Pexperimental-runtime clean verify) >"$log" 2>&1
  jar_path="$module/target/ly-rasp-java-1.0.0-experimental.jar"
  digest=$(sha256sum "$jar_path")
  digest=${digest%% *}
  if [[ -z $expected_digest ]]; then
    expected_digest=$digest
  else
    [[ $digest == "$expected_digest" ]]
  fi
done

jar_path="$module/target/ly-rasp-java-1.0.0-experimental.jar"
jar tf "$jar_path" >"$tmp/jar.list"
! grep -Eq '(^|/)probe/rasp/java(/|$)' "$tmp/jar.list"
! grep -Eq 'com/lyflow/rasp/java/(transformer/|util/ASMHookHelper)' "$tmp/jar.list"
unzip -p "$jar_path" META-INF/MANIFEST.MF >"$tmp/manifest.mf"
grep -Fq 'Premain-Class: com.lyflow.rasp.java.Agent' "$tmp/manifest.mf"
grep -Fq 'Agent-Class: com.lyflow.rasp.java.Agent' "$tmp/manifest.mf"

unit_count=$(python3 - "$module/target/surefire-reports" <<'PY'
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
print(sum(int(ET.parse(path).getroot().attrib["tests"]) for path in Path(sys.argv[1]).glob("TEST-*.xml")))
PY
)
integration_count=$(python3 - "$module/target/failsafe-reports" <<'PY'
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
print(sum(int(ET.parse(path).getroot().attrib["tests"]) for path in Path(sys.argv[1]).glob("TEST-*.xml")))
PY
)
[[ $unit_count -ge 10 && $integration_count -ge 1 ]]
grep -R -Fq 'name="productionSupervisorExhaustsRestartBudgetWithInjectedClockCount10"' "$module/target/surefire-reports"
grep -R -Fq 'name="binaryIntegrityFailureEmitsCanonicalHealth"' "$module/target/surefire-reports"
grep -R -Fq 'name="exporterOutageFallsBackAndReportsDegradedHealth"' "$module/target/surefire-reports"
grep -R -Fq 'name="controlHealthPublicationRetriesAndRecovers"' "$module/target/surefire-reports"

baseline="$tmp/baseline.txt"
monitored="$tmp/monitored.txt"
events="$tmp/events.jsonl"
fallback="$tmp/fallback.jsonl"
(cd "$module" && java -cp target/test-classes com.lyflow.rasp.fixture.FixtureMain) >"$baseline"
(cd "$module" && java \
  -javaagent:"$jar_path"="mode=monitor,policyVersion=14,policyId=todo14,agentId=java-fixture,app=todo14-fixture,packages=com.lyflow.rasp.fixture,evidence=$events,fallback=$fallback" \
  -cp target/test-classes com.lyflow.rasp.fixture.FixtureMain) >"$monitored"
diff -u "$baseline" "$monitored"

python3 - "$events" <<'PY'
import json
import sys
from pathlib import Path
events = [json.loads(line) for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()]
assert {event["event_type"] for event in events} == {
    "rasp.sql", "rasp.command", "rasp.file", "rasp.deserialization"
}
assert all(event["schema_version"] == "lyflow.rasp_bridge_event.v1" for event in events)
assert all(event["severity"] == "low" and event["policy_version"] == 14 for event in events)
PY

[[ ! -e $fallback ]]
[[ $(stat -c %s "$events") -le 1048576 ]]
printf 'java-rasp experimental-profile conformance count=%s unit-tests=%s integration-tests=%s jar-sha256=%s\n' \
  "$iterations" "$unit_count" "$integration_count" "$expected_digest"
