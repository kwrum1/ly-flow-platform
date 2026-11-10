#!/usr/bin/env python3
"""Generate a minimal Ethernet/IPv4/UDP pcap for Suricata direction testing.

The packets are synthetic and inert: they exist only so the same capture can be
replayed against two Suricata profiles that differ solely in HOME_NET/EXTERNAL_NET.
"""
import struct
import sys


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


def build_udp(src, dst, sport, dport, payload, ident):
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    src_b, dst_b = ip_bytes(src), ip_bytes(dst)
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, 17, udp_len)
    udp_sum = checksum(pseudo + udp)
    if udp_sum == 0:
        udp_sum = 0xFFFF
    udp = struct.pack("!HHHH", sport, dport, udp_len, udp_sum) + payload
    total_len = 20 + len(udp)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ident, 0, 64, 17, 0, src_b, dst_b,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    return eth + header + udp


def write_pcap(path, packets):
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            handle.write(struct.pack("<IIII", 1760000000 + index, 0, len(packet), len(packet)))
            handle.write(packet)


def main():
    target = sys.argv[1]
    packets = [
        # internal -> internal on an inbound-only port (the 10.1.1.181 -> 10.1.18.253:161 pattern)
        build_udp("10.1.1.181", "10.1.18.253", 52449, 161, b"public", 1),
        # external -> internal on the same inbound-only port (a genuine inbound hit)
        build_udp("203.0.113.9", "10.1.18.253", 40001, 161, b"public", 2),
        # internal -> external on an outbound-only port (a genuine egress hit)
        build_udp("10.1.1.181", "203.0.113.80", 40002, 5353, b"dirprobe", 3),
        # internal -> internal on the outbound-only port (must not match outbound-only)
        build_udp("10.1.1.181", "10.1.18.253", 40003, 5353, b"dirprobe", 4),
        # any -> any stays direction-agnostic and must keep firing everywhere
        build_udp("10.1.1.181", "10.1.18.253", 40004, 9999, b"neutral", 5),
    ]
    write_pcap(target, packets)
    print(f"wrote {target} with {len(packets)} packets")


if __name__ == "__main__":
    main()
