#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'bash -s' <<'INNER'
docker rm -f lyflow-response-target >/dev/null 2>&1 || true
docker run -d --name lyflow-response-target --network bridge docker.1ms.run/library/alpine:3.20 sleep 300
docker inspect --format '{{json .NetworkSettings.Networks}}' lyflow-response-target
INNER
REMOTE
