#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null /opt/lyflow/vm/namespace-create.py root@10.1.18.126:/opt/ly-agent/etc/namespace-create.py >/dev/null
bash /opt/lyflow/vm/start-real-agent.sh >/dev/null 2>&1 || true
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'bash -s' <<'INNER'
python3 /opt/ly-agent/etc/namespace-create.py
sleep 35
docker inspect --format '{{json .NetworkSettings.Networks}}' lyflow-response-target
python3 /opt/ly-agent/etc/response-list.py | tail -2
INNER
REMOTE
