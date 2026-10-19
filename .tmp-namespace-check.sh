#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'bash -s' <<'INNER'
docker inspect --format '{{json .NetworkSettings.Networks}}' lyflow-response-target 2>&1 || true
python3 /opt/ly-agent/etc/response-list.py | tail -3
INNER
REMOTE
