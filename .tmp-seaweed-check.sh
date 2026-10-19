#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'bash -s' <<'INNER'
docker ps --format '{{.Names}} {{.Status}}' | grep -E 'seaweed|ly-server' || true
echo SEAWEED
docker logs --tail 30 lyflow-g5-seaweedfs-1 2>&1 | tail -20 || true
echo SERVER
docker logs --tail 30 lyflow-g5-ly-server-1 2>&1 | tail -20 || true
curl -s -m 5 -o /dev/null -w 'filer=%{http_code}\n' http://127.0.0.1:18888/ || true
curl -sk -m 5 -o /dev/null -w 'health=%{http_code}\n' https://127.0.0.1/api/v1/health || true
INNER
REMOTE
