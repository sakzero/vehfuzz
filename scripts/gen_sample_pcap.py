#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
import time
from pathlib import Path


def _sum16(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return s


def _checksum16(data: bytes) -> int:
    s = _sum16(data)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a tiny classic pcap (Ethernet linktype) for offline fuzzing demos.")
    ap.add_argument("--out", default="fuzz/vehfuzz/samples/sample_eth.pcap")
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Little-endian, microseconds, Ethernet (DLT_EN10MB=1)
    gh = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)

    # Minimal Ethernet + IPv4 + UDP packet (padded to 60 bytes).
    payload = b"vehfuzz-demo"
    src_ip = bytes([192, 0, 2, 1])
    dst_ip = bytes([192, 0, 2, 2])

    udp_hdr = struct.pack(">HHHH", 12345, 30511, 8 + len(payload), 0)
    pseudo = src_ip + dst_ip + b"\x00" + bytes([17]) + struct.pack(">H", len(udp_hdr) + len(payload))
    udp_chk = _checksum16(pseudo + udp_hdr + payload)
    if udp_chk == 0:
        udp_chk = 0xFFFF
    udp_hdr = struct.pack(">HHHH", 12345, 30511, 8 + len(payload), udp_chk)

    ip_total_len = 20 + len(udp_hdr) + len(payload)
    ip_hdr_wo = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,  # version=4, ihl=5
        0x00,  # tos
        ip_total_len,
        0x1234,  # identification
        0x0000,  # flags/fragment
        64,  # ttl
        17,  # udp
        0,  # checksum placeholder
        src_ip,
        dst_ip,
    )
    ip_chk = _checksum16(ip_hdr_wo)
    ip_hdr = ip_hdr_wo[:10] + struct.pack(">H", ip_chk) + ip_hdr_wo[12:]

    eth = (
        bytes.fromhex("001122334455")  # dst
        + bytes.fromhex("66778899aabb")  # src
        + bytes.fromhex("0800")  # ethertype IPv4
        + ip_hdr
        + udp_hdr
        + payload
    )
    if len(eth) < 60:
        eth = eth.ljust(60, b"\x00")

    ts = time.time()
    ts_sec = int(ts)
    ts_us = int((ts - ts_sec) * 1_000_000)
    ph = struct.pack("<IIII", ts_sec, ts_us, len(eth), len(eth))

    out.write_bytes(gh + ph + eth)
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
