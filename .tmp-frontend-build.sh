#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
set -e
cd /opt/lyflow/src
docker build --network host -f deploy/docker/pingora-frontend.Dockerfile -t ly-flow/frontend:latest . 2>&1 | tail -3
docker save ly-flow/frontend:latest | gzip -1 | ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'gunzip | docker load' >/dev/null
REMOTE
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE2'
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'bash -s' <<'INNER'
set -e
cd /opt/lyflow/deploy/compose
docker compose --env-file lean.env -f g5-host.yml up -d --force-recreate --no-deps ly-vis 2>&1 | tail -2
sleep 8
curl -sk -m 10 -o /dev/null -w 'health=%{http_code}\n' https://127.0.0.1/ || true
INNER
REMOTE2
