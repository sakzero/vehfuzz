#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
import time
from pathlib import Path

_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_EPB = 0x00000006


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


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * ((4 - (len(data) % 4)) % 4)


def _block(block_type: int, body: bytes, *, endianness: str = "<") -> bytes:
    if endianness not in ("<", ">"):
        raise ValueError("endianness must be '<' or '>'")
    total_len = 12 + len(body)
    if total_len % 4 != 0:
        raise ValueError("pcapng block must be 32-bit aligned")
    return struct.pack(f"{endianness}II", block_type, total_len) + body + struct.pack(f"{endianness}I", total_len)


def _build_demo_ethernet_ipv4_udp() -> bytes:
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
    return eth


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a tiny pcapng (Ethernet linktype) for offline fuzzing demos.")
    ap.add_argument("--out", default="fuzz/vehfuzz/samples/sample_eth.pcapng")
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    endianness = "<"

    # Section Header Block (SHB)
    shb_body = (
        struct.pack(f"{endianness}I", 0x1A2B3C4D)  # byte-order magic
        + struct.pack(f"{endianness}HH", 1, 0)  # version 1.0
        + struct.pack(f"{endianness}q", -1)  # section length: unknown
        + struct.pack(f"{endianness}HH", 0, 0)  # end-of-options
    )
    shb = _block(_PCAPNG_SHB, _pad4(shb_body), endianness=endianness)

    # Interface Description Block (IDB)
    linktype = 1  # DLT_EN10MB (Ethernet)
    snaplen = 65535
    # if_tsresol (code=9, len=1) => base-10, exponent=6 => microseconds
    idb_opts = struct.pack(f"{endianness}HH", 9, 1) + b"\x06" + b"\x00" * 3 + struct.pack(f"{endianness}HH", 0, 0)
    idb_body = struct.pack(f"{endianness}HHI", linktype, 0, snaplen) + idb_opts
    idb = _block(_PCAPNG_IDB, _pad4(idb_body), endianness=endianness)

    # Enhanced Packet Block (EPB)
    pkt = _build_demo_ethernet_ipv4_udp()
    ts64 = int(time.time() * 1_000_000)
    ts_high = (ts64 >> 32) & 0xFFFFFFFF
    ts_low = ts64 & 0xFFFFFFFF
    cap_len = len(pkt)
    pkt_len = len(pkt)
    epb_body = (
        struct.pack(f"{endianness}IIIII", 0, ts_high, ts_low, cap_len, pkt_len)
        + _pad4(pkt)
        + struct.pack(f"{endianness}HH", 0, 0)  # end-of-options
    )
    epb = _block(_PCAPNG_EPB, _pad4(epb_body), endianness=endianness)

    out.write_bytes(shb + idb + epb)
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

