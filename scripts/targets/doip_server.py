#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import struct
import threading
from dataclasses import dataclass


def _build_header(version: int, payload_type: int, payload_len: int) -> bytes:
    version &= 0xFF
    inv = version ^ 0xFF
    return struct.pack(">BBHI", version, inv, payload_type & 0xFFFF, payload_len & 0xFFFFFFFF)


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def _build_uds_response(req: bytes) -> bytes:
    if not req:
        return b""
    sid = req[0]
    sub = req[1] if len(req) > 1 else 0x00
    if sid == 0x10:
        return bytes([0x50, sub, 0x00, 0x32, 0x01, 0xF4])
    if sid == 0x3E:
        return bytes([0x7E, sub])
    if sid == 0x22 and len(req) >= 3:
        did = req[1:3]
        return bytes([0x62]) + did + b"\x12\x34\x56\x78"
    if sid == 0x27:
        if sub % 2 == 1:
            return bytes([0x67, sub]) + b"\xAA\xBB\xCC\xDD"
        return bytes([0x67, sub])
    return bytes([0x7F, sid, 0x11])


@dataclass
class _Session:
    activated: bool = False
    tester_addr: int = 0x0E00
    ecu_addr: int = 0x0E01


def _handle_client(conn: socket.socket, addr: tuple[str, int], version: int, require_activation: bool) -> None:
    sess = _Session()
    try:
        while True:
            hdr = _recv_exact(conn, 8)
            v, inv, ptype, plen = struct.unpack(">BBHI", hdr)
            if (v ^ inv) & 0xFF != 0xFF:
                _ = _recv_exact(conn, plen)
                continue
            payload = _recv_exact(conn, plen) if plen else b""

            if ptype == 0x0005:  # Routing Activation Request
                if len(payload) >= 2:
                    sess.tester_addr = int.from_bytes(payload[0:2], "big")
                sess.activated = True
                # Routing Activation Response (minimal)
                resp_code = 0x10  # success (best-effort)
                resp_payload = struct.pack(">HHBBI", sess.tester_addr, sess.ecu_addr, resp_code, 0x00, 0x00000000)
                conn.sendall(_build_header(version, 0x0006, len(resp_payload)) + resp_payload)
                continue

            if ptype == 0x8001:  # Diagnostic message
                if require_activation and not sess.activated:
                    # Negative ACK
                    if len(payload) >= 4:
                        src, dst = struct.unpack(">HH", payload[:4])
                    else:
                        src, dst = sess.tester_addr, sess.ecu_addr
                    nack_payload = struct.pack(">HHB", src, dst, 0x01)
                    conn.sendall(_build_header(version, 0x8003, len(nack_payload)) + nack_payload)
                    continue

                if len(payload) < 4:
                    continue
                src, dst = struct.unpack(">HH", payload[:4])
                uds = payload[4:]
                resp_uds = _build_uds_response(uds)

                # Positive ACK
                ack_payload = struct.pack(">HHB", src, dst, 0x00)
                conn.sendall(_build_header(version, 0x8002, len(ack_payload)) + ack_payload)

                # Diagnostic response (swap src/dst)
                diag_payload = struct.pack(">HH", dst, src) + resp_uds
                conn.sendall(_build_header(version, 0x8001, len(diag_payload)) + diag_payload)
                continue

    except Exception:
        return
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Minimal DoIP server target (vehfuzz)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=13400)
    ap.add_argument("--version", type=lambda s: int(s, 0), default=0x02)
    ap.add_argument("--no-activation", action="store_true", help="Do not require routing activation")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(5)
    print(f"doip_server listening on {args.host}:{args.port}")

    while True:
        conn, addr = srv.accept()
        t = threading.Thread(
            target=_handle_client,
            args=(conn, addr, int(args.version) & 0xFF, not args.no_activation),
            daemon=True,
        )
        t.start()


if __name__ == "__main__":
    raise SystemExit(main())

