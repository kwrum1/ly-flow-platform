#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'bash -s' <<'INNER'
find /opt/ly-agent -maxdepth 3 -type f | grep -E 'agent|json|yaml' | head -30
echo IDENTITY
head -20 /opt/ly-agent/etc/agent-identity.yaml 2>/dev/null || true
INNER
REMOTE
