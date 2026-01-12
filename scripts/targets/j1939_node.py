#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time


def _parse_j1939_id(can_id: int) -> dict:
    can_id &= 0x1FFFFFFF
    prio = (can_id >> 26) & 0x7
    dp = (can_id >> 24) & 0x1
    pf = (can_id >> 16) & 0xFF
    ps = (can_id >> 8) & 0xFF
    sa = can_id & 0xFF
    if pf < 240:
        pgn = (dp << 16) | (pf << 8)
        da = ps
    else:
        pgn = (dp << 16) | (pf << 8) | ps
        da = None
    return {"priority": prio, "data_page": dp, "pf": pf, "ps": ps, "sa": sa, "pgn": pgn, "da": da}


def _build_j1939_id(*, priority: int, data_page: int, pf: int, ps: int, sa: int) -> int:
    return (
        ((priority & 0x7) << 26)
        | ((data_page & 0x1) << 24)
        | ((pf & 0xFF) << 16)
        | ((ps & 0xFF) << 8)
        | (sa & 0xFF)
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Minimal J1939 node target (vehfuzz)")
    ap.add_argument("--channel", default="vcan0")
    ap.add_argument("--interface", default="socketcan")
    ap.add_argument("--sa", type=lambda s: int(s, 0), default=0x80, help="Source address of this node")
    ap.add_argument("--respond", action="store_true", help="Respond to Request (PGN 0x00EA00)")
    args = ap.parse_args()

    try:
        import can  # type: ignore
    except Exception as e:  # pragma: no cover
        raise SystemExit(f"python-can is required: {e}")

    bus = can.interface.Bus(channel=str(args.channel), interface=str(args.interface), fd=False)
    print(f"j1939_node listening on {args.interface}:{args.channel} sa=0x{int(args.sa)&0xFF:02x}")

    while True:
        msg = bus.recv(timeout=1.0)
        if msg is None:
            continue
        if not getattr(msg, "is_extended_id", False):
            continue
        info = _parse_j1939_id(int(msg.arbitration_id))
        data = bytes(getattr(msg, "data", b""))
        da_str = f"0x{int(info['da']):02x}" if info["da"] is not None else "ff"
        print(
            f"rx prio={info['priority']} pgn=0x{info['pgn']:06x} sa=0x{info['sa']:02x} "
            f"da={da_str} data={data.hex()}"
        )

        if not args.respond:
            continue

        # Respond to J1939 Request (PGN 0x00EA00) with a simple single-frame payload.
        if info["pgn"] != 0x00EA00 or len(data) < 3:
            continue
        req_pgn = int(data[0]) | (int(data[1]) << 8) | (int(data[2]) << 16)
        dp = (req_pgn >> 16) & 0x1
        pf = (req_pgn >> 8) & 0xFF
        if pf < 240:
            ps = info["sa"]  # unicast back
        else:
            ps = req_pgn & 0xFF

        resp_id = _build_j1939_id(priority=info["priority"], data_page=dp, pf=pf, ps=ps, sa=int(args.sa))
        resp_payload = bytes([0xAA, 0x55]) + data[:6].ljust(6, b"\xFF")
        out = can.Message(
            arbitration_id=resp_id,
            is_extended_id=True,
            data=resp_payload[:8],
        )
        bus.send(out)
        time.sleep(0.001)


if __name__ == "__main__":
    raise SystemExit(main())
