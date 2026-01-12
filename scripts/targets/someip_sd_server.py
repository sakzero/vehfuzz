#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import struct


def _parse_someip_header(data: bytes) -> dict | None:
    if len(data) < 16:
        return None
    try:
        service_id, method_id, length, client_id, session_id, proto_ver, iface_ver, msg_type, ret_code = struct.unpack(
            ">HHIHHBBBB", data[:16]
        )
    except struct.error:
        return None
    return {
        "service_id": service_id,
        "method_id": method_id,
        "length": length,
        "client_id": client_id,
        "session_id": session_id,
        "proto_ver": proto_ver,
        "iface_ver": iface_ver,
        "msg_type": msg_type,
        "ret_code": ret_code,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Minimal SOME/IP-SD UDP server target (vehfuzz)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=30490)
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    print(f"someip_sd_server listening on {args.host}:{args.port}")

    while True:
        data, addr = sock.recvfrom(65535)
        hdr = _parse_someip_header(data)
        if hdr is None:
            continue
        payload = data[16:]

        # Best-effort parse SD header (flags + reserved + entries_len + ...).
        if len(payload) < 12:
            continue
        flags = payload[0]
        entries_len = struct.unpack(">I", payload[4:8])[0]
        if 8 + entries_len + 4 > len(payload):
            # malformed, drop
            continue

        # Reply with a generic SOME/IP response echoing SD payload.
        resp_type = 0x80
        resp_code = 0x00
        resp_length = (len(payload) + 8) & 0xFFFFFFFF
        out_hdr = struct.pack(
            ">HHIHHBBBB",
            int(hdr["service_id"]) & 0xFFFF,
            int(hdr["method_id"]) & 0xFFFF,
            resp_length,
            int(hdr["client_id"]) & 0xFFFF,
            int(hdr["session_id"]) & 0xFFFF,
            int(hdr["proto_ver"]) & 0xFF,
            int(hdr["iface_ver"]) & 0xFF,
            resp_type,
            resp_code,
        )
        sock.sendto(out_hdr + payload, addr)


if __name__ == "__main__":
    raise SystemExit(main())

