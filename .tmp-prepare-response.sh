#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'bash -s' <<'INNER'
set -e
mkdir -p /tmp/lyflow-response
printf 'quarantine acceptance\n' > /tmp/lyflow-response/sample.txt
id lyflow-response-test >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin lyflow-response-test
pgrep -f 'sleep 300' >/dev/null || (nohup sleep 300 >/dev/null 2>&1 & echo $! >/tmp/lyflow-response-sleep.pid)
sleep 1
printf 'pid=%s\n' "$(cat /tmp/lyflow-response-sleep.pid)"
INNER
REMOTE
