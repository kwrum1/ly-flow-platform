#!/usr/bin/env bash
set -euo pipefail
ROOT=/opt/lyflow/src
scp "$ROOT/deploy/suricata/lyflow-suricata-test.yaml" root@10.1.18.126:/etc/suricata/lyflow-suricata-test.yaml
scp "$ROOT/deploy/suricata/lyflow-suricata.rules" root@10.1.18.126:/var/lib/suricata/rules/lyflow-suricata.rules
ssh -o BatchMode=yes root@10.1.18.126 'bash -s' <<'REMOTE'
set -e
systemctl stop suricata 2>/dev/null || true
pkill -f 'suricata -c /etc/suricata/lyflow-suricata-test.yaml' 2>/dev/null || true
rm -f /var/log/suricata/eve.json
suricata -T -c /etc/suricata/lyflow-suricata-test.yaml 2>&1 | tail -12
suricata -c /etc/suricata/lyflow-suricata-test.yaml --af-packet=ens160 >/tmp/lyflow-suricata.log 2>&1 &
SURICATA_PID=$!
sleep 4
sleep 3
python3 - <<'PY'
import socket
query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07profile\x04test\x00\x00\x01\x00\x01'
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2)
try:
    sock.sendto(query, ('223.5.5.5', 53))
    sock.recv(512)
except Exception as error:
    print('dns probe:', error)
PY
sleep 3
echo '--- matching eve records ---'
grep -i 'profile.test' /var/log/suricata/eve.json | tail -5 || true
echo '--- alert count ---'
grep -c '"event_type":"alert"' /var/log/suricata/eve.json 2>/dev/null || true
kill "$SURICATA_PID" 2>/dev/null || true
wait "$SURICATA_PID" 2>/dev/null || true
echo '--- suricata log tail ---'
tail -10 /tmp/lyflow-suricata.log
REMOTE

