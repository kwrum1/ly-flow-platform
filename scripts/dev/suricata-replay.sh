#!/usr/bin/env bash
set -euo pipefail
ROOT=/opt/lyflow/src
scp "$ROOT/deploy/suricata/lyflow-suricata-test.yaml" root@10.1.18.126:/etc/suricata/lyflow-suricata-test.yaml
scp "$ROOT/deploy/suricata/lyflow-suricata.rules" root@10.1.18.126:/var/lib/suricata/rules/lyflow-suricata.rules
ssh -o BatchMode=yes root@10.1.18.126 'bash -s' <<'REMOTE'
set -e
apt-get install -y -qq python3-scapy
rm -rf /tmp/lyflow-suri-pcap /tmp/lyflow-dns.pcap
mkdir -p /tmp/lyflow-suri-pcap
python3 - <<'PY'
from scapy.all import DNS, DNSQR, IP, UDP, wrpcap
packet = IP(src="10.1.18.126", dst="223.5.5.5") / UDP(sport=40000, dport=53) / DNS(rd=1, qd=DNSQR(qname="profile.test"))
wrpcap("/tmp/lyflow-dns.pcap", packet)
print("pcap written")
PY
suricata -r /tmp/lyflow-dns.pcap -c /etc/suricata/lyflow-suricata-test.yaml -l /tmp/lyflow-suri-pcap 2>&1 | tail -12
echo '--- eve ---'
cat /tmp/lyflow-suri-pcap/eve.json | tail -10
echo '--- profile.test match ---'
grep -i 'profile.test' /tmp/lyflow-suri-pcap/eve.json | tail -5 || true
REMOTE

