#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def _default_from_env(name: str, default: str) -> str:
    v = os.environ.get(name)
    return v if v else default


def _env_json(name: str) -> dict:
    raw = os.environ.get(name)
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def main() -> int:
    ap = argparse.ArgumentParser(description="boofuzz DoIP diag fuzzing profile (vehfuzz helper)")
    target_env = _env_json("VEHFUZZ_TARGET_JSON")
    ap.add_argument("--host", default=str(target_env.get("host", "127.0.0.1")))
    ap.add_argument("--port", type=int, default=int(target_env.get("port", 13400)))
    ap.add_argument("--version", type=lambda s: int(s, 0), default=0x02)
    ap.add_argument("--tester", type=lambda s: int(s, 0), default=0x0E00)
    ap.add_argument("--ecu", type=lambda s: int(s, 0), default=0x0E01)
    ap.add_argument("--cases", type=int, default=200)
    ap.add_argument("--recv-timeout", type=float, default=0.5)
    ap.add_argument("--max-uds-len", type=int, default=32)
    ap.add_argument("--no-activation", action="store_true", help="Skip routing activation request")
    args = ap.parse_args()

    try:
        from boofuzz import (  # type: ignore
            BIG_ENDIAN,
            FuzzLoggerCsv,
            Session,
            SocketConnection,
            Target,
            s_block_end,
            s_block_start,
            s_byte,
            s_get,
            s_initialize,
            s_random,
            s_size,
            s_static,
            s_word,
        )
    except Exception as e:  # pragma: no cover
        raise SystemExit(f"boofuzz import failed (install deps / set PYTHONPATH): {e}")

    artifacts_dir = Path(_default_from_env("VEHFUZZ_ARTIFACTS_DIR", ".")).resolve()
    csv_path = Path(_default_from_env("VEHFUZZ_BOOFUZZ_CSV", str(artifacts_dir / "boofuzz.csv"))).resolve()
    db_path = artifacts_dir / "boofuzz.doip.db"

    artifacts_dir.mkdir(parents=True, exist_ok=True)

    version = int(args.version) & 0xFF
    inv = version ^ 0xFF

    if not args.no_activation:
        s_initialize("doip_activation")
        if s_block_start("doip"):
            s_static(bytes([version, inv]))
            s_word(0x0005, endian=BIG_ENDIAN, fuzzable=False)
            s_size("payload", length=4, endian=BIG_ENDIAN, fuzzable=False)
            if s_block_start("payload"):
                s_word(int(args.tester) & 0xFFFF, endian=BIG_ENDIAN, fuzzable=False)
            s_block_end("payload")
        s_block_end("doip")

    s_initialize("doip_diag")
    if s_block_start("doip"):
        s_static(bytes([version, inv]))
        s_word(0x8001, endian=BIG_ENDIAN, fuzzable=False)
        s_size("payload", length=4, endian=BIG_ENDIAN, fuzzable=False)
        if s_block_start("payload"):
            s_word(int(args.tester) & 0xFFFF, endian=BIG_ENDIAN, fuzzable=False)
            s_word(int(args.ecu) & 0xFFFF, endian=BIG_ENDIAN, fuzzable=False)
            s_byte(0x10, name="uds_sid")
            s_byte(0x01, name="uds_sub")
            s_random(b"", min_length=0, max_length=max(0, int(args.max_uds_len)), num_mutations=50, name="uds_data")
        s_block_end("payload")
    s_block_end("doip")

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        fuzz_loggers = [FuzzLoggerCsv(file_handle=f)]
        session = Session(
            target=Target(
                connection=SocketConnection(
                    host=str(args.host),
                    port=int(args.port),
                    proto="tcp",
                    recv_timeout=float(args.recv_timeout),
                )
            ),
            web_port=None,
            console_gui=False,
            receive_data_after_each_request=True,
            receive_data_after_fuzz=True,
            check_data_received_each_request=False,
            reuse_target_connection=False,
            index_start=1,
            index_end=int(args.cases) if int(args.cases) > 0 else None,
            db_filename=str(db_path),
            fuzz_loggers=fuzz_loggers,
        )

        if not args.no_activation:
            session.connect(s_get("doip_activation"), s_get("doip_diag"))
        else:
            session.connect(s_get("doip_diag"))

        session.fuzz()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

