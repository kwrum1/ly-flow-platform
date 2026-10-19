#!/usr/bin/env bash
set -euo pipefail
ROOT=/opt/lyflow/src
scp "$ROOT/deploy/suricata/lyflow-suricata-test.yaml" root@10.1.18.126:/etc/suricata/lyflow-suricata-test.yaml
scp "$ROOT/deploy/suricata/lyflow-suricata.rules" root@10.1.18.126:/var/lib/suricata/rules/lyflow-suricata.rules
ssh -o BatchMode=yes root@10.1.18.126 'bash -s' <<'REMOTE'
set -e
rm -rf /tmp/lyflow-suri-pcap /tmp/lyflow-dns.pcap
mkdir -p /tmp/lyflow-suri-pcap
python3 - <<'PY'
import socket
import struct
import time


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def dns_query(name):
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split("."))
    return (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + labels
        + b"\x00"
        + struct.pack("!HH", 1, 1)
    )


src = socket.inet_aton("10.1.18.126")
dst = socket.inet_aton("223.5.5.5")
payload = dns_query("profile.test")
udp = struct.pack("!HHHH", 40000, 53, 8 + len(payload), 0) + payload
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x1234, 0, 64, 17, 0, src, dst)
ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
eth = bytes.fromhex("00112233445566778899aabb0800")
frame = eth + ip + udp
pcap = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
pcap += struct.pack("<IIII", int(time.time()), 0, len(frame), len(frame)) + frame
with open("/tmp/lyflow-dns.pcap", "wb") as handle:
    handle.write(pcap)
print("pcap written")
PY
suricata -r /tmp/lyflow-dns.pcap -c /etc/suricata/lyflow-suricata-test.yaml -l /tmp/lyflow-suri-pcap 2>&1 | tail -12
echo '--- eve ---'
tail -10 /tmp/lyflow-suri-pcap/eve.json
echo '--- profile.test match ---'
grep -i 'profile.test' /tmp/lyflow-suri-pcap/eve.json | tail -5 || true
REMOTE
