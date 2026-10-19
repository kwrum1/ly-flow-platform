#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
set -e
cd /opt/lyflow/src/server
GOTOOLCHAIN=local /root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.5.linux-amd64/bin/go build -trimpath -o ly-server ./cmd
cd /opt/lyflow/src/agent
GOTOOLCHAIN=local /root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.5.linux-amd64/bin/go build -trimpath -o ly-agent ./cmd
cd /opt/lyflow/src
docker build --no-cache --network host -f deploy/docker/server-lean.Dockerfile -t ly-flow/server:latest . 2>&1 | tail -2
docker save ly-flow/server:latest | gzip -1 | ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'gunzip | docker load' >/dev/null
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null /opt/lyflow/src/deploy/compose/g5-host.yml root@10.1.18.126:/opt/lyflow/deploy/compose/g5-host.yml >/dev/null
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null /opt/lyflow/src/agent/ly-agent root@10.1.18.126:/tmp/ly-agent.new >/dev/null
REMOTE
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE2'
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'bash -s' <<'INNER'
set -e
pkill -x ly-agent 2>/dev/null || true
install -m 0755 /tmp/ly-agent.new /opt/ly-agent/ly-agent
cd /opt/lyflow/deploy/compose
docker compose --env-file lean.env -f g5-host.yml up -d seaweedfs 2>&1 | tail -3
sleep 15
docker compose --env-file lean.env -f g5-host.yml ps seaweedfs
docker compose --env-file lean.env -f g5-host.yml up -d --force-recreate --no-deps ly-server 2>&1 | tail -3
sleep 8
curl -sk -m 10 -o /dev/null -w 'health=%{http_code}\n' https://127.0.0.1/api/v1/health || true
INNER
REMOTE2
