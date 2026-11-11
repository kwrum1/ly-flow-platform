#!/usr/bin/env python3
"""Build a pcap containing a real HTTP attack request over a full TCP handshake.

The payloads are copied verbatim from this deployment's own alert history
(`ET WEB_SERVER /etc/passwd Detected in URI`, sid 2049400), so the replay proves
the deployed profile still catches the attack that matters, and still ignores the
same payload when it is not addressed to a protected asset.

A complete three-way handshake is emitted because Suricata only reassembles an
HTTP transaction on an established stream.
"""
import struct
import sys

WIN = 65535
MSS = 1460


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_bytes(value):
    return bytes(int(part) for part in value.split("."))


class Flow:
    """One client/server TCP conversation with a real handshake."""

    FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

    def __init__(self, client, server, client_port, server_port, request, base):
        self.client, self.server = client, server
        self.cport, self.sport = client_port, server_port
        self.base = base
        self.cseq = base
        self.sseq = base + 500_000
        self.packets = []
        self.request = request

    def _segment(self, src, dst, sport, dport, seq, ack, flags, payload=b"", options=b""):
        src_b, dst_b = ip_bytes(src), ip_bytes(dst)
        data_offset = (5 + len(options) // 4) << 12
        tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack,
                          data_offset | flags, WIN, 0, 0) + options + payload
        pseudo = src_b + dst_b + struct.pack("!BBH", 0, 6, len(tcp))
        tcp_sum = checksum(pseudo + tcp)
        tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack,
                          data_offset | flags, WIN, tcp_sum, 0) + options + payload
        total_len = 20 + len(tcp)
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len,
                             seq & 0xFFFF, 0x4000, 64, 6, 0, src_b, dst_b)
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        eth = (b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00")
        self.packets.append(eth + header + tcp)

    def build(self):
        syn_opts = b"\x02\x04" + struct.pack("!H", MSS)          # MSS option
        syn_opts += b"\x01\x01\x04\x02"                          # NOP NOP SACK-permitted

        # handshake
        self._segment(self.client, self.server, self.cport, self.sport,
                      self.cseq, 0, self.SYN, options=syn_opts)
        self.cseq += 1
        self._segment(self.server, self.client, self.sport, self.cport,
                      self.sseq, self.cseq, self.SYN | self.ACK, options=syn_opts)
        self.sseq += 1
        self._segment(self.client, self.server, self.cport, self.sport,
                      self.cseq, self.sseq, self.ACK)

        # request
        self._segment(self.client, self.server, self.cport, self.sport,
                      self.cseq, self.sseq, self.PSH | self.ACK, self.request)
        self.cseq += len(self.request)

        # response
        body = b"<html><body>ok</body></html>"
        response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
                    + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        self._segment(self.server, self.client, self.sport, self.cport,
                      self.sseq, self.cseq, self.PSH | self.ACK, response)
        self.sseq += len(response)

        # teardown
        self._segment(self.server, self.client, self.sport, self.cport,
                      self.sseq, self.cseq, self.FIN | self.ACK)
        self.sseq += 1
        self._segment(self.client, self.server, self.cport, self.sport,
                      self.cseq, self.sseq, self.FIN | self.ACK)
        self.cseq += 1
        self._segment(self.server, self.client, self.sport, self.cport,
                      self.sseq, self.cseq, self.ACK)
        return self.packets


def write_pcap(path, packets):
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            handle.write(struct.pack("<IIII", 1760000000 + index, index * 1000,
                                     len(packet), len(packet)))
            handle.write(packet)


# Verbatim from the alert history: a scanner walking sru.edu.cn site directories.
REAL_URI = "/chat/imController/showOrDownByurl.do?dbPath=../../../../../etc/passwd"


def request(host):
    return (
        f"GET {REAL_URI} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode()


def main():
    target = sys.argv[1]
    sessions = [
        # 1. The real incident: internal scanner -> protected web tier (must alert).
        Flow("10.1.1.181", "10.1.18.253", 40272, 80, request("jjc.sru.edu.cn"), 1_000_000),
        # 2. Same payload -> protected public NAT (must alert).
        Flow("10.1.1.181", "113.194.3.11", 40273, 80, request("gjc.sru.edu.cn"), 2_000_000),
        # 3. Same payload between two non-protected internal hosts (must NOT alert).
        Flow("10.1.1.181", "10.1.2.52", 40274, 80, request("lab.internal"), 3_000_000),
        # 4. Same payload to an unrelated internal workstation (must NOT alert).
        Flow("10.1.1.181", "10.20.215.161", 40275, 80, request("ws.internal"), 4_000_000),
    ]
    packets = []
    for session in sessions:
        packets.extend(session.build())
    write_pcap(target, packets)
    print(f"wrote {target} with {len(packets)} packets across {len(sessions)} sessions")


if __name__ == "__main__":
    main()
