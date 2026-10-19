#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
python3 - <<'PY'
from pathlib import Path
p=Path('/opt/lyflow/vm/run-real-agent.sh')
s=p.read_text().replace('export RESPONSE_ENABLE_NAMESPACE_ISOLATION=false','export RESPONSE_ENABLE_NAMESPACE_ISOLATION=true')
p.write_text(s)
PY
bash /opt/lyflow/vm/start-real-agent.sh >/dev/null 2>&1 || true
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'bash -s' <<'INNER'
set -e
docker rm -f lyflow-response-target >/dev/null 2>&1 || true
docker run -d --name lyflow-response-target --network bridge alpine:3.20 sleep 300 >/dev/null
docker inspect --format '{{json .NetworkSettings.Networks}}' lyflow-response-target
INNER
REMOTE
