from __future__ import annotations

import time
from typing import Any

from vehfuzz.core.isotp import (
    IsoTpReassembly,
    parse_isotp_frame,
    reassemble_feed,
    DEFAULT_REASSEMBLY_TIMEOUT_S,
)
from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.parsers.uds_parser import parse_uds_payload
from vehfuzz.core.plugins import Message, Protocol, register_protocol


# Maximum number of concurrent ISO-TP reassembly states per protocol instance
MAX_ISOTP_STATES = 256


class _CanProtocol(Protocol):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._isotp_states: dict[int, IsoTpReassembly] = {}
        self._last_cleanup: float = 0.0
        self._cleanup_interval: float = float(config.get("cleanup_interval_s", 10.0))
        self._isotp_timeout: float = float(config.get("isotp_timeout_s", DEFAULT_REASSEMBLY_TIMEOUT_S))

    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        can_id = seed.meta.get("can_id", self._cfg.get("can_id", 0x7DF))
        can_id = int(can_id)
        is_fd = bool(seed.meta.get("is_fd", self._cfg.get("is_fd", False)))
        is_extended = bool(seed.meta.get("is_extended", self._cfg.get("is_extended", can_id > 0x7FF)))
        bitrate_switch = bool(seed.meta.get("bitrate_switch", self._cfg.get("bitrate_switch", False)))

        max_len = int(self._cfg.get("max_len", 64 if is_fd else 8))
        if max_len <= 0:
            max_len = 64 if is_fd else 8
        data = mutated[:max_len]

        pad_to = self._cfg.get("pad_to_len")
        if pad_to is not None:
            pad_to = int(pad_to)
            if pad_to > len(data):
                pad_byte = int(self._cfg.get("pad_byte", 0)) & 0xFF
                data = data + bytes([pad_byte]) * (pad_to - len(data))

        meta = dict(seed.meta)
        meta.update(
            {
                "can_id": can_id,
                "is_extended": is_extended,
                "is_fd": is_fd,
                "bitrate_switch": bitrate_switch,
            }
        )
        return Message(data=data, meta=meta)

    def _cleanup_expired_states(self, now: float) -> None:
        """Remove expired ISO-TP reassembly states."""
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now

        expired_keys = [
            k for k, v in self._isotp_states.items()
            if v.is_expired(now)
        ]
        for k in expired_keys:
            del self._isotp_states[k]

        # Also limit total number of states (LRU-like: remove oldest)
        if len(self._isotp_states) > MAX_ISOTP_STATES:
            # Sort by last_activity and remove oldest
            sorted_keys = sorted(
                self._isotp_states.keys(),
                key=lambda k: self._isotp_states[k].last_activity,
            )
            for k in sorted_keys[: len(self._isotp_states) - MAX_ISOTP_STATES]:
                del self._isotp_states[k]

    def parse(self, msg: Message) -> ParsedMessage:
        now = time.time()
        self._cleanup_expired_states(now)

        can_id = msg.meta.get("can_id")
        try:
            can_id_i = int(can_id) if can_id is not None else None
        except (TypeError, ValueError):
            can_id_i = None
        is_fd = bool(msg.meta.get("is_fd", len(msg.data) > 8))

        # Best-effort ISO-TP + UDS parsing when frames look like ISO-TP.
        isotp_fields: dict[str, Any] | None = None
        isotp_error: str | None = None
        inner_uds: dict[str, Any] | None = None
        derived_uds_hex: str | None = None

        if can_id_i is not None and bool(self._cfg.get("parse_isotp", True)):
            try:
                p = parse_isotp_frame(bytes(msg.data))
                isotp_fields = {
                    "frame_type": p.frame_type,
                    "total_len": p.total_len,
                    "declared_len": p.declared_len,
                    "seq": p.seq,
                    "fc_status": p.fc_status,
                    "block_size": p.block_size,
                    "stmin": p.stmin,
                    "truncated": p.truncated,
                }
                if p.error:
                    isotp_error = p.error

                if p.frame_type == "sf":
                    inner_uds = parse_uds_payload(p.payload)
                    derived_uds_hex = p.payload.hex()
                else:
                    state = self._isotp_states.get(can_id_i)
                    if state is None:
                        state = IsoTpReassembly(timeout_s=self._isotp_timeout)
                        self._isotp_states[can_id_i] = state
                    complete, parsed_frame = reassemble_feed(state, bytes(msg.data), now=now)
                    if parsed_frame.error:
                        isotp_error = parsed_frame.error
                    if complete is not None:
                        inner_uds = parse_uds_payload(complete)
                        derived_uds_hex = complete.hex()
                        isotp_fields["reassembly_complete"] = True
            except ValueError as e:
                # ISO-TP parsing error - record it instead of silently ignoring
                isotp_error = str(e)
            except Exception as e:
                # Unexpected error - still record it
                isotp_error = f"unexpected: {type(e).__name__}: {e}"

        return ParsedMessage(
            protocol="can",
            level="l2",
            ok=True,
            flow_key=(f"can:0x{can_id_i:x}" if can_id_i is not None else "can"),
            fields={
                "can_id": can_id_i,
                "is_extended": bool(msg.meta.get("is_extended", (can_id_i or 0) > 0x7FF)),
                "is_fd": is_fd,
                "dlc": int(msg.meta.get("dlc", len(msg.data))),
                "len": len(msg.data),
                "isotp": isotp_fields,
                "isotp_error": isotp_error,
                "inner_uds": inner_uds,
                "inner_uds_hex": derived_uds_hex,
            },
            payload=ByteRange(0, len(msg.data)),
        )


@register_protocol("can")
def can_protocol(config: dict[str, Any]) -> Protocol:
    return _CanProtocol(config)
