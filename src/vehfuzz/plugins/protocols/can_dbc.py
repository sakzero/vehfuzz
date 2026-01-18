from __future__ import annotations

import hashlib
import random
from pathlib import Path
from typing import Any

from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.config import resolve_path
from vehfuzz.core.plugins import Message, Protocol, register_protocol


_DBC_CACHE: dict[str, Any] = {}


def _load_dbc(path: Path) -> Any:
    key = str(path.resolve())
    if key in _DBC_CACHE:
        return _DBC_CACHE[key]

    try:
        import cantools  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError("cantools is required for can_dbc protocol (pip install cantools)") from e

    db = cantools.database.load_file(str(path))
    _DBC_CACHE[key] = db
    return db


def _pick_message(db: Any, *, frame_id: int | None = None, name: str | None = None) -> Any:
    if name:
        try:
            return db.get_message_by_name(name)
        except Exception:
            for m in getattr(db, "messages", []):
                if getattr(m, "name", None) == name:
                    return m
            raise

    if frame_id is None:
        raise ValueError("can_dbc requires either protocol_config.message_name or a CAN frame_id")

    try:
        return db.get_message_by_frame_id(int(frame_id))
    except Exception:
        for m in getattr(db, "messages", []):
            if int(getattr(m, "frame_id", -1)) == int(frame_id):
                return m
        raise


def _stable_rng(mutated: bytes, seed_salt: str) -> random.Random:
    h = hashlib.sha256()
    h.update(seed_salt.encode("utf-8"))
    h.update(b"\0")
    h.update(mutated)
    seed = int.from_bytes(h.digest()[:8], "big", signed=False)
    return random.Random(seed)


class _CanDbcProtocol(Protocol):
    """
    Use a DBC file to perform signal-level mutation and encoding.

    This keeps the core engine byte-mutation pipeline unchanged: the mutated bytes are used as deterministic entropy
    to choose and generate signal values, and the final CAN payload is produced by DBC encoding.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

        cfg_dir = Path(str(config.get("__config_dir", "."))).resolve()
        dbc_path_raw = config.get("dbc_path") or config.get("path")
        if not dbc_path_raw or not isinstance(dbc_path_raw, str):
            raise ValueError("can_dbc requires protocol_config.dbc_path")
        dbc_path = resolve_path(cfg_dir, dbc_path_raw)
        if dbc_path is None:
            raise ValueError("can_dbc dbc_path could not be resolved")
        if not dbc_path.exists():
            raise FileNotFoundError(str(dbc_path))
        self._dbc_path = dbc_path
        self._db = _load_dbc(dbc_path)

    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        cfg = self._cfg
        meta_in = dict(seed.meta)

        frame_id = cfg.get("frame_id")
        if frame_id is None:
            frame_id = meta_in.get("can_id")
        frame_id = int(frame_id) if frame_id is not None else None

        msg_name = cfg.get("message_name")
        if msg_name is not None:
            msg_name = str(msg_name)

        message = _pick_message(self._db, frame_id=frame_id, name=msg_name)
        frame_id = int(getattr(message, "frame_id", frame_id or 0))

        # Decode seed if possible; otherwise start from defaults/zeroes.
        signals: dict[str, Any] = {}
        try:
            decoded = message.decode(seed.data)
            if isinstance(decoded, dict):
                signals.update(decoded)
        except Exception:
            pass

        sigs = list(getattr(message, "signals", []))
        if not sigs:
            raise ValueError(f"DBC message has no signals: {getattr(message, 'name', frame_id)}")

        min_signals = int(cfg.get("min_signals", 1))
        max_signals = int(cfg.get("max_signals", min(4, len(sigs))))
        if min_signals < 1:
            min_signals = 1
        if max_signals < min_signals:
            max_signals = min_signals
        max_signals = min(max_signals, len(sigs))

        rng = _stable_rng(mutated, seed_salt=f"{self._dbc_path}:{frame_id}:{getattr(message,'name','')}")
        k = rng.randint(min_signals, max_signals)
        chosen = rng.sample(sigs, k=k)

        mutated_signals: dict[str, Any] = {}
        for s in chosen:
            name = str(getattr(s, "name", ""))
            if not name:
                continue

            minimum = getattr(s, "minimum", None)
            maximum = getattr(s, "maximum", None)
            is_float = bool(getattr(s, "is_float", False))
            length = int(getattr(s, "length", 0) or 0)
            is_signed = bool(getattr(s, "is_signed", False))

            if minimum is not None and maximum is not None and float(maximum) > float(minimum):
                if is_float:
                    value = float(minimum) + rng.random() * (float(maximum) - float(minimum))
                else:
                    lo = int(float(minimum))
                    hi = int(float(maximum))
                    value = rng.randint(min(lo, hi), max(lo, hi))
            else:
                if length <= 0:
                    # Fallback to a small range.
                    value = rng.randint(0, 255)
                elif is_signed:
                    lo = -(1 << (length - 1))
                    hi = (1 << (length - 1)) - 1
                    value = rng.randint(lo, hi)
                else:
                    value = rng.randint(0, (1 << length) - 1)

            signals[name] = value
            mutated_signals[name] = value

        data = bytes(message.encode(signals))

        out_meta = meta_in
        out_meta.update(
            {
                "can_id": frame_id,
                "is_extended": bool(out_meta.get("is_extended", frame_id > 0x7FF)),
                "is_fd": bool(out_meta.get("is_fd", len(data) > 8)),
                "dbc": {
                    "path": str(self._dbc_path),
                    "message": getattr(message, "name", None),
                    "frame_id": frame_id,
                    "mutated_signals": mutated_signals,
                },
            }
        )
        return Message(data=data, meta=out_meta)

    def parse(self, msg: Message) -> ParsedMessage:
        frame_id = msg.meta.get("can_id")
        try:
            frame_id_i = int(frame_id) if frame_id is not None else None
        except Exception:
            frame_id_i = None

        decoded: dict[str, Any] | None = None
        err: str | None = None
        if frame_id_i is not None:
            try:
                message = _pick_message(self._db, frame_id=frame_id_i, name=None)
                decoded = message.decode(bytes(msg.data))
            except Exception as e:  # pragma: no cover
                err = str(e)

        fields: dict[str, Any] = {
            "can_id": frame_id_i,
            "is_fd": bool(msg.meta.get("is_fd", len(msg.data) > 8)),
            "len": len(msg.data),
            "dbc_path": str(self._dbc_path),
        }
        if decoded is not None and isinstance(decoded, dict):
            fields["signals"] = decoded
        if err:
            fields["decode_error"] = err

        flow_key = f"can_dbc:0x{frame_id_i:x}" if frame_id_i is not None else "can_dbc"
        return ParsedMessage(protocol="can_dbc", level="app", ok=True, flow_key=flow_key, fields=fields, payload=ByteRange(0, len(msg.data)))


@register_protocol("can_dbc")
def can_dbc_protocol(config: dict[str, Any]) -> Protocol:
    return _CanDbcProtocol(config)
