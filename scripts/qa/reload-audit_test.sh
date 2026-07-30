#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evidence=${RELOAD_AUDIT_EVIDENCE_DIR:-$root/acceptance-evidence/T08}
mkdir -p "$evidence"
exec > >(tee "$evidence/command.log") 2>&1

export GOSUMDB=sum.golang.org
export GOTOOLCHAIN=auto
export LYFLOW_RELOAD_AUDIT_RESULT=${LYFLOW_RELOAD_AUDIT_RESULT:-$evidence/reload-events.json}
rm -f "$LYFLOW_RELOAD_AUDIT_RESULT"

git -C "$root" status --short >"$evidence/worktree-status.txt"
git -C "$root" rev-parse HEAD >"$evidence/start-commit.txt"

(
  cd "$root/server"
  go test -race -shuffle=on -count=1 ./rulelifecycle
  go test -race -shuffle=on -count=1 ./cmd \
    -run 'TestCompileDefaultSecurityBundleRestoresStateWhenReloadEventCommitFails|TestRulePlatformInlineSync_realPostgres_is_pinned_immutable_audited_and_activated|TestRuleRuntimeHTTP'
)

jq -e '
  .status == "PASS" and .failed_events == 1 and .successful_events == 1 and .rollback_events == 1 and
  .baseline_version == .final_version and .baseline_digest == .final_digest
' "$LYFLOW_RELOAD_AUDIT_RESULT" >/dev/null
jq '{baseline_version,baseline_digest,candidate_version,final_version,final_digest}' \
  "$LYFLOW_RELOAD_AUDIT_RESULT" >"$evidence/bundle-hashes.json"

printf 'RELOAD_AUDIT_RESULT=PASS failed=1 success=1 rollback=1 exact_restore=true\n'
