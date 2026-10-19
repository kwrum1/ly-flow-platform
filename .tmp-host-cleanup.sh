#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'bash -s' <<'INNER'
set -e
nohup sh -c 'sleep 120; nft delete table inet lyflow_host_isolation 2>/dev/null || true' >/dev/null 2>&1 &
echo cleanup_timer_started
INNER
REMOTE
