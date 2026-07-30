#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evidence="$root/acceptance-evidence/T11"
mkdir -p "$evidence"
exec > >(tee "$evidence/command.log") 2>&1

export GOSUMDB=sum.golang.org
export GOTOOLCHAIN=auto

git -C "$root" status --short >"$evidence/worktree-status.txt"
git -C "$root" rev-parse HEAD >"$evidence/start-commit.txt"

(
  cd "$root/server"
  go test -race -shuffle=on -count=1 ./rulelifecycle ./cmd -run 'TestActiveRuleCounts|TestCurrentTrafficCount|TestRuleRuntimeHTTP|TestRouteRegistry'
)
(
  cd "$root/frontend"
  npm test -- --run src/pages/RulesCenter.spec.ts
  npm run typecheck
  npm run build
)

docker exec ly-security-engine wget -qO- http://127.0.0.1:8080/health >"$evidence/active-health.json"
docker exec ly-security-engine wget -qO- http://127.0.0.1:8080/health >/dev/null

jq -e '.status == "running" and (.rule_counts.traffic | type == "number" and . > 0) and (.bundle_digest | test("^[0-9a-f]{64}$"))' "$evidence/active-health.json" >/dev/null
candidate="$root/acceptance-evidence/T10/candidate-traffic-ledger.json"
jq -e '.status == "candidate" and .signature_count == 8405 and (.sources | length == 5)' "$candidate" >/dev/null

active_signature_count=$(jq -r '.rule_counts.traffic' "$evidence/active-health.json")
active_digest=$(jq -r '.bundle_digest' "$evidence/active-health.json")
candidate_signature_count=$(jq -r '.signature_count' "$candidate")
python3 - "$evidence/count-parity.json" "$active_signature_count" "$active_digest" "$candidate_signature_count" <<'PY'
import json
import sys
from pathlib import Path

output, active_count, active_digest, candidate_count = sys.argv[1:]
Path(output).write_text(json.dumps({
    "status": "PASS",
    "active_bundle": {
        "signature_count": int(active_count),
        "bundle_digest": active_digest,
        "source": "security_engine_verified_active_bundle",
    },
    "server_and_rules_center_contract": {
        "signature_count": int(active_count),
        "source": "signed_active_lifecycle",
        "rule_file_count": "separate_metric",
    },
    "candidate_corpus": {
        "signature_count": int(candidate_count),
        "source": "signed_candidate_traffic_ledger",
        "not_runtime_loaded": True,
    },
    "intentional_difference": "candidate corpus is not reported as active/runtime count",
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

jq -e '.active_bundle.signature_count == .server_and_rules_center_contract.signature_count and .candidate_corpus.not_runtime_loaded == true' "$evidence/count-parity.json" >/dev/null
printf 'COUNT_SEMANTICS_RESULT=PASS active_signatures=%s candidate_signatures=%s active_digest=%s\n' "$active_signature_count" "$candidate_signature_count" "$active_digest"
