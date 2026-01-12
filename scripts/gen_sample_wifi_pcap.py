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


def _ipv4_header_checksum(hdr: bytes) -> int:
    return _checksum16(hdr)


def _udp_checksum(src_ip: bytes, dst_ip: bytes, udp_hdr: bytes, payload: bytes) -> int:
    pseudo = src_ip + dst_ip + b"\x00" + bytes([17]) + struct.pack(">H", len(udp_hdr) + len(payload))
    c = _checksum16(pseudo + udp_hdr + payload)
    return 0xFFFF if c == 0 else c


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate a tiny classic pcap (802.11 Radiotap linktype) for offline Wi-Fi fuzzing demos."
    )
    ap.add_argument("--out", default="fuzz/vehfuzz/samples/sample_wifi_radiotap.pcap")
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Little-endian, microseconds, DLT_IEEE802_11_RADIO=127 (Radiotap)
    gh = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 127)

    # Radiotap header (8 bytes, no fields).
    rtap = struct.pack("<BBHI", 0, 0, 8, 0)

    # 802.11 data frame header (24 bytes, cleartext).
    # Frame Control: version=0, type=2 (data), subtype=0, flags=0 => 0x0008
    fc = (0x0008).to_bytes(2, "little")
    dur = (0).to_bytes(2, "little")
    addr1 = bytes.fromhex("001122334455")
    addr2 = bytes.fromhex("66778899aabb")
    addr3 = bytes.fromhex("0c0d0e0f1011")
    seq = (0).to_bytes(2, "little")
    dot11 = fc + dur + addr1 + addr2 + addr3 + seq

    # LLC/SNAP + EtherType IPv4
    llc = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"

    # IPv4 + UDP payload
    payload = b"vehfuzz-wifi"
    src_ip = bytes([192, 0, 2, 10])
    dst_ip = bytes([192, 0, 2, 20])

    udp_hdr_wo = struct.pack(">HHHH", 12345, 30511, 8 + len(payload), 0)
    udp_chk = _udp_checksum(src_ip, dst_ip, udp_hdr_wo, payload)
    udp_hdr = struct.pack(">HHHH", 12345, 30511, 8 + len(payload), udp_chk)

    ip_total_len = 20 + len(udp_hdr) + len(payload)
    ip_hdr_wo = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0x00,
        ip_total_len,
        0x4242,
        0x0000,
        64,
        17,
        0,
        src_ip,
        dst_ip,
    )
    ip_chk = _ipv4_header_checksum(ip_hdr_wo)
    ip_hdr = ip_hdr_wo[:10] + struct.pack(">H", ip_chk) + ip_hdr_wo[12:]

    pkt = rtap + dot11 + llc + ip_hdr + udp_hdr + payload

    ts = time.time()
    ts_sec = int(ts)
    ts_us = int((ts - ts_sec) * 1_000_000)
    ph = struct.pack("<IIII", ts_sec, ts_us, len(pkt), len(pkt))

    out.write_bytes(gh + ph + pkt)
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

