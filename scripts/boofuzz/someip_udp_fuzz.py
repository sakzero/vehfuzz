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
    ap = argparse.ArgumentParser(description="boofuzz SOME/IP UDP fuzzing profile (vehfuzz helper)")
    target_env = _env_json("VEHFUZZ_TARGET_JSON")
    ap.add_argument("--host", default=str(target_env.get("host", "127.0.0.1")))
    ap.add_argument("--port", type=int, default=int(target_env.get("port", 30509)))
    ap.add_argument("--cases", type=int, default=300)
    ap.add_argument("--recv-timeout", type=float, default=0.5)
    ap.add_argument("--max-payload-len", type=int, default=64)
    ap.add_argument("--service-id", type=lambda s: int(s, 0), default=0x1234)
    ap.add_argument("--method-id", type=lambda s: int(s, 0), default=0x0001)
    ap.add_argument("--client-id", type=lambda s: int(s, 0), default=0x0001)
    ap.add_argument("--session-id", type=lambda s: int(s, 0), default=0x0001)
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
            s_word,
        )
    except Exception as e:  # pragma: no cover
        raise SystemExit(f"boofuzz import failed (install deps / set PYTHONPATH): {e}")

    artifacts_dir = Path(_default_from_env("VEHFUZZ_ARTIFACTS_DIR", ".")).resolve()
    csv_path = Path(_default_from_env("VEHFUZZ_BOOFUZZ_CSV", str(artifacts_dir / "boofuzz.csv"))).resolve()
    db_path = artifacts_dir / "boofuzz.someip.db"

    artifacts_dir.mkdir(parents=True, exist_ok=True)

    s_initialize("someip_req")
    if s_block_start("someip"):
        s_word(int(args.service_id) & 0xFFFF, endian=BIG_ENDIAN, fuzzable=False)
        s_word(int(args.method_id) & 0xFFFF, endian=BIG_ENDIAN, fuzzable=False)
        # SOME/IP length includes 8 bytes: client_id..return_code
        s_size("payload", offset=8, length=4, endian=BIG_ENDIAN, fuzzable=False)
        s_word(int(args.client_id) & 0xFFFF, endian=BIG_ENDIAN, fuzzable=False)
        s_word(int(args.session_id) & 0xFFFF, endian=BIG_ENDIAN, fuzzable=False)
        s_byte(0x01, name="proto_ver", fuzzable=False)
        s_byte(0x01, name="iface_ver", fuzzable=False)
        s_byte(0x00, name="msg_type")
        s_byte(0x00, name="ret_code", fuzzable=False)
        if s_block_start("payload"):
            s_random(b"PING", min_length=0, max_length=max(0, int(args.max_payload_len)), num_mutations=100, name="data")
        s_block_end("payload")
    s_block_end("someip")

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        fuzz_loggers = [FuzzLoggerCsv(file_handle=f)]
        session = Session(
            target=Target(
                connection=SocketConnection(
                    host=str(args.host),
                    port=int(args.port),
                    proto="udp",
                    recv_timeout=float(args.recv_timeout),
                    bind=("0.0.0.0", 0),
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

        session.connect(s_get("someip_req"))
        session.fuzz()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

