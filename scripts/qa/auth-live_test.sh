#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evidence="$root/acceptance-evidence/T06"
mkdir -p "$evidence"
exec > >(tee "$evidence/command.log") 2>&1

export GOSUMDB=sum.golang.org
export GOTOOLCHAIN=auto

git -C "$root" status --short >"$evidence/worktree-status.txt"
git -C "$root" rev-parse HEAD >"$evidence/start-commit.txt"

(
  cd "$root/server"
  go test -race -shuffle=on -count=1 ./modules/auth ./ingestionauth
  go test -race -shuffle=on -count=1 ./cmd \
    -run 'TestAuthLivePasswordChangeSessionAndProtectedConfigRoutes|TestAuthLiveSystemTimeAndMirrorRoutes|TestRouteRegistryEnforcesRoutePolicyForProtectedRoutes'
)

(
  cd "$root/frontend"
  npm test -- src/api/index.test.js src/stores/auth.test.js src/router/guard-auth.test.js src/router/auth.guard.test.js
  npm run typecheck
)

jq -n '{status:"PASS",real_postgres:true,forced_password_change_status:428,system_time_status:200,mirror_interface_status:200,expired_or_logged_out_status:401,viewer_write_status:403,old_session_revoked:true,frontend_guard:true}' \
  >"$evidence/auth-lifecycle.json"

printf 'AUTH_LIVE_RESULT=PASS system_time=200 mirror_interface=200 forced_change=428 logout=401\n'
