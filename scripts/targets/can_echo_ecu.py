#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time


def main() -> int:
    ap = argparse.ArgumentParser(description="SocketCAN echo ECU (vehfuzz simulation target)")
    ap.add_argument("--channel", default="vcan0")
    ap.add_argument("--interface", default="socketcan")
    ap.add_argument("--rx-id", type=lambda s: int(s, 0), default=None, help="Only echo this CAN ID (default: any)")
    ap.add_argument("--tx-offset", type=lambda s: int(s, 0), default=0x8, help="Response ID = rx_id + offset")
    ap.add_argument("--delay-ms", type=int, default=0, help="Artificial response delay")
    args = ap.parse_args()

    try:
        import can  # type: ignore
    except Exception as e:
        raise SystemExit("python-can is required for can_echo_ecu.py") from e

    bus = can.interface.Bus(channel=args.channel, interface=args.interface)
    print(f"can_echo_ecu listening on {args.channel} ({args.interface})")

    while True:
        msg = bus.recv(timeout=1.0)
        if msg is None:
            continue
        if args.rx_id is not None and int(msg.arbitration_id) != int(args.rx_id):
            continue
        if args.delay_ms > 0:
            time.sleep(args.delay_ms / 1000.0)
        resp_id = int(msg.arbitration_id) + int(args.tx_offset)
        resp = can.Message(arbitration_id=resp_id, data=msg.data, is_extended_id=msg.is_extended_id)
        bus.send(resp)


if __name__ == "__main__":
    raise SystemExit(main())

