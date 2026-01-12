#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path


def _bootstrap_src_path() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(repo_root / "fuzz" / "vehfuzz" / "src"))


def _hex_int(s: str) -> int:
    return int(s, 0)


def _build_uds_response(req: bytes) -> bytes:
    if not req:
        return b""
    sid = req[0]
    sub = req[1] if len(req) > 1 else 0x00

    # Minimal demo ECU: supports a handful of UDS services.
    if sid == 0x10:  # DiagnosticSessionControl
        return bytes([0x50, sub, 0x00, 0x32, 0x01, 0xF4])  # includes dummy P2/P2*
    if sid == 0x3E:  # TesterPresent
        return bytes([0x7E, sub])
    if sid == 0x22 and len(req) >= 3:  # ReadDataByIdentifier
        did = req[1:3]
        value = b"\x12\x34\x56\x78"
        return bytes([0x62]) + did + value
    if sid == 0x27:  # SecurityAccess (demo only; not real algorithm)
        if sub % 2 == 1:  # requestSeed
            seed = b"\xAA\xBB\xCC\xDD"
            return bytes([0x67, sub]) + seed
        # sendKey: accept any key in demo
        return bytes([0x67, sub])

    # NegativeResponse: 0x11 = ServiceNotSupported
    return bytes([0x7F, sid, 0x11])


def main() -> int:
    _bootstrap_src_path()

    try:
        import can  # type: ignore
    except Exception as e:
        raise SystemExit("python-can is required") from e

    from vehfuzz.core.isotp import (
        IsoTpReassembly,
        build_cf,
        build_fc,
        build_ff,
        build_sf,
        parse_isotp_frame,
        reassemble_feed,
        stmin_to_seconds,
    )

    ap = argparse.ArgumentParser(description="UDS ECU target over ISO-TP/SocketCAN (vehfuzz)")
    ap.add_argument("--channel", default="vcan0")
    ap.add_argument("--interface", default="socketcan")
    ap.add_argument("--req-id", type=_hex_int, default=0x7E0, help="Tester->ECU CAN ID")
    ap.add_argument("--resp-id", type=_hex_int, default=0x7E8, help="ECU->Tester CAN ID")
    ap.add_argument("--pad-byte", type=_hex_int, default=0x00)
    ap.add_argument("--fc-timeout-s", type=float, default=0.5)
    ap.add_argument("--tx-timeout-s", type=float, default=2.0)
    args = ap.parse_args()

    bus = can.interface.Bus(channel=args.channel, interface=args.interface)
    print(f"uds_isotp_ecu: listen req_id={hex(args.req_id)} resp_id={hex(args.resp_id)} on {args.channel}")

    rx_state = IsoTpReassembly()

    def send_can(can_id: int, data: bytes) -> None:
        msg = can.Message(arbitration_id=int(can_id), data=data[:8], is_extended_id=(can_id > 0x7FF))
        bus.send(msg)

    def wait_fc(timeout_s: float) -> object | None:
        end = time.time() + timeout_s
        while True:
            remaining = end - time.time()
            if remaining <= 0:
                return None
            rx = bus.recv(timeout=remaining)
            if rx is None:
                continue
            if int(rx.arbitration_id) != int(args.req_id):
                continue
            try:
                parsed = parse_isotp_frame(bytes(rx.data))
            except ValueError:
                continue
            if parsed.frame_type == "fc":
                return parsed

    def send_isotp(payload: bytes) -> None:
        if len(payload) <= 7:
            send_can(args.resp_id, build_sf(payload, pad_byte=args.pad_byte))
            return

        total_len = len(payload)
        send_can(args.resp_id, build_ff(payload, total_len=total_len, pad_byte=args.pad_byte))

        fc = wait_fc(args.fc_timeout_s)
        if fc is None:
            return
        if (fc.fc_status or 0) != 0:
            return

        bs = int(fc.block_size or 0)
        stmin = int(fc.stmin or 0)
        st_delay = stmin_to_seconds(stmin)

        sent_in_block = 0
        seq = 1
        offset = 6
        start = time.time()
        while offset < total_len:
            if time.time() - start > args.tx_timeout_s:
                return
            chunk = payload[offset : offset + 7]
            offset += len(chunk)
            send_can(args.resp_id, build_cf(seq, chunk, pad_byte=args.pad_byte))
            seq = (seq + 1) & 0xF
            if st_delay > 0:
                time.sleep(st_delay)
            if bs != 0:
                sent_in_block += 1
                if sent_in_block >= bs and offset < total_len:
                    sent_in_block = 0
                    fc = wait_fc(args.fc_timeout_s)
                    if fc is None or (fc.fc_status or 0) != 0:
                        return
                    bs = int(fc.block_size or 0)
                    stmin = int(fc.stmin or 0)
                    st_delay = stmin_to_seconds(stmin)

    while True:
        rx = bus.recv(timeout=1.0)
        if rx is None:
            continue
        if int(rx.arbitration_id) != int(args.req_id):
            continue

        data = bytes(rx.data)
        complete, parsed = reassemble_feed(rx_state, data)

        if parsed.frame_type == "ff":
            # ECU is receiver of request -> send FC CTS on resp-id
            send_can(args.resp_id, build_fc(status=0x0, block_size=0, stmin=0, pad_byte=args.pad_byte))

        if complete is None:
            continue

        resp = _build_uds_response(complete)
        if not resp:
            continue
        send_isotp(resp)


if __name__ == "__main__":
    raise SystemExit(main())

