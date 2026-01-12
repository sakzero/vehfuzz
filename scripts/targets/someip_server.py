#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import struct


def main() -> int:
    ap = argparse.ArgumentParser(description="Minimal SOME/IP UDP server target (vehfuzz)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=30509)
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    print(f"someip_server listening on {args.host}:{args.port}")

    while True:
        data, addr = sock.recvfrom(65535)
        if len(data) < 16:
            continue
        try:
            service_id, method_id, length, client_id, session_id, proto_ver, iface_ver, msg_type, ret_code = struct.unpack(
                ">HHIHHBBBB", data[:16]
            )
        except struct.error:
            continue

        payload = data[16:]
        # SOME/IP length includes 8 bytes (client_id..return_code)
        expected_payload_len = int(length) - 8 if int(length) >= 8 else 0
        if expected_payload_len < 0:
            expected_payload_len = 0
        if expected_payload_len != len(payload):
            # Best-effort: accept and respond anyway.
            pass

        resp_type = 0x80  # response
        resp_code = 0x00
        resp_length = (len(payload) + 8) & 0xFFFFFFFF
        header = struct.pack(
            ">HHIHHBBBB",
            service_id,
            method_id,
            resp_length,
            client_id,
            session_id,
            proto_ver,
            iface_ver,
            resp_type,
            resp_code,
        )
        sock.sendto(header + payload, addr)


if __name__ == "__main__":
    raise SystemExit(main())

