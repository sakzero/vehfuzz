#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket


def main() -> int:
    ap = argparse.ArgumentParser(description="NMEA UDP sink (vehfuzz simulation target)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=30511)
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    print(f"nmea_udp_sink listening on {args.host}:{args.port}")

    while True:
        data, addr = sock.recvfrom(65535)
        print(data.decode("ascii", errors="replace").rstrip())


if __name__ == "__main__":
    raise SystemExit(main())

