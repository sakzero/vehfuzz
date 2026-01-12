#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a tiny classic pcap (Bluetooth HCI H4 linktype) for offline demos.")
    ap.add_argument("--out", default="fuzz/vehfuzz/samples/sample_bt_hci_h4.pcap")
    ap.add_argument("--mode", choices=["l2cap", "sdp", "rfcomm"], default="l2cap")
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Little-endian, microseconds, DLT_BLUETOOTH_HCI_H4=187
    gh = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 187)

    # HCI H4 packet: ACL (0x02) + handle/flags + len + L2CAP(len,cid) + payload
    ptype = b"\x02"
    handle_flags = (0x0001).to_bytes(2, "little")

    mode = str(args.mode).lower()
    if mode == "sdp":
        # SDP PDU: id(1) + txn(2) + param_len(2) + params
        params = b"\x35\x03\x19\x11\x01"
        l2_payload = bytes([0x04]) + (0x1234).to_bytes(2, "big") + len(params).to_bytes(2, "big") + params
        cid = (0x0040).to_bytes(2, "little")  # dynamic CID (demo)
    elif mode == "rfcomm":
        # Minimal RFCOMM UIH frame: addr + ctrl + len + info + fcs
        info = b"vehfuzz"
        addr = ((3 << 2) | (1 << 1) | 0x01) & 0xFF  # DLCI=3, C/R=1, EA=1
        ctrl = 0xEF
        ln = ((len(info) & 0x7F) << 1) | 0x01
        fcs = b"\x00"
        l2_payload = bytes([addr, ctrl, ln]) + info + fcs
        cid = (0x0040).to_bytes(2, "little")  # dynamic CID (demo)
    else:
        l2_payload = b"\x01\x00\x01\x00"  # dummy signaling payload
        cid = (0x0001).to_bytes(2, "little")  # L2CAP signaling

    l2_len = len(l2_payload).to_bytes(2, "little")
    acl_payload = l2_len + cid + l2_payload
    acl_len = len(acl_payload).to_bytes(2, "little")
    pkt = ptype + handle_flags + acl_len + acl_payload

    ts = time.time()
    ts_sec = int(ts)
    ts_us = int((ts - ts_sec) * 1_000_000)
    ph = struct.pack("<IIII", ts_sec, ts_us, len(pkt), len(pkt))

    out.write_bytes(gh + ph + pkt)
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
