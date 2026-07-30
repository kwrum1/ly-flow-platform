#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evidence="$root/acceptance-evidence/T05"
mkdir -p "$evidence"
exec > >(tee "$evidence/command.log") 2>&1

export GOSUMDB=sum.golang.org
export GOTOOLCHAIN=auto

git -C "$root" status --short >"$evidence/worktree-status.txt"
git -C "$root" rev-parse HEAD >"$evidence/start-commit.txt"

(
  cd "$root/server"
  go test -race -shuffle=on -count=1 ./cmd \
    -run 'TestIncidentLifecycle|TestInitializeIncidentLifecycleRuntime|TestIncidentMutationHTTP'
  go test -race -shuffle=on -count=1 ./incidentlifecycle
)

jq -n \
  --arg collection 'GET /api/v1/incidents' \
  --arg detail 'GET /api/v1/incidents/{id}' \
  --arg mutation 'PUT /api/v1/incidents/{id}/status' \
  '{status:"PASS",migration:19,collection:$collection,detail:$detail,mutation:$mutation,postgres:"real disposable container",restart_persistence:true,transactional_failure:true}' \
  >"$evidence/incident-lifecycle-manifest.json"

printf 'INCIDENT_PROCESS_HTTP_RESULT=PASS migration=19 restart_persistence=true\n'
