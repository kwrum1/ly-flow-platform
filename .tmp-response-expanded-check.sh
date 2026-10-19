#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'bash -s' <<'INNER'
set +e
echo FILE
ls -l /tmp/lyflow-response/sample.txt 2>&1 || true
ls -l /var/lib/lyflow/quarantine 2>&1 || true
echo PROCESS
cat /tmp/lyflow-response-sleep.pid 2>/dev/null || true
ps -p "$(cat /tmp/lyflow-response-sleep.pid 2>/dev/null)" -o pid,cmd 2>&1 || true
echo ACCOUNT
chage -l lyflow-response-test 2>&1 | head -8
echo ACTIONS
python3 /opt/ly-agent/etc/response-status.py 2>&1 | tail -5
echo AGENTLOG
tail -40 /opt/ly-agent/logs/agent.log 2>/dev/null | tail -25
INNER
REMOTE
