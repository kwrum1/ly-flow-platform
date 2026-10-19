#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
set -e
for f in response-expanded evidence-object-store lateral-integration legacy-retirement; do
  scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "/opt/lyflow/vm/.tmp-$f.txt" "root@10.1.18.126:/opt/lyflow/reports/G5/$f.txt" >/dev/null
done
echo copied
REMOTE
