#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null /opt/lyflow/vm/namespace-rollback.py root@10.1.18.126:/opt/ly-agent/etc/namespace-rollback.py >/dev/null
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'python3 /opt/ly-agent/etc/namespace-rollback.py'
bash /opt/lyflow/vm/start-real-agent.sh >/dev/null 2>&1 || true
sleep 4
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'bash -s' <<'INNER'
docker inspect --format '{{json .NetworkSettings.Networks}}' lyflow-response-target
python3 /opt/ly-agent/etc/response-list.py | tail -2
docker rm -f lyflow-response-target >/dev/null 2>&1 || true
INNER
REMOTE
