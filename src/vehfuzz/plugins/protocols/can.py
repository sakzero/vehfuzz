from __future__ import annotations

from typing import Any

from vehfuzz.core.isotp import IsoTpReassembly, parse_isotp_frame, reassemble_feed
from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.plugins import Message, Protocol, register_protocol
from vehfuzz.plugins.protocols.uds import _parse_uds  # type: ignore


class _CanProtocol(Protocol):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._isotp_states: dict[int, IsoTpReassembly] = {}

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

    def parse(self, msg: Message) -> ParsedMessage:
        can_id = msg.meta.get("can_id")
        try:
            can_id_i = int(can_id) if can_id is not None else None
        except Exception:
            can_id_i = None
        is_fd = bool(msg.meta.get("is_fd", len(msg.data) > 8))

        # Best-effort ISO-TP + UDS parsing when frames look like ISO-TP.
        isotp_fields: dict[str, Any] | None = None
        inner_uds: dict[str, Any] | None = None
        derived_uds_hex: str | None = None
        if can_id_i is not None and bool(self._cfg.get("parse_isotp", True)):
            try:
                p = parse_isotp_frame(bytes(msg.data))
                isotp_fields = {
                    "frame_type": p.frame_type,
                    "total_len": p.total_len,
                    "seq": p.seq,
                    "fc_status": p.fc_status,
                    "block_size": p.block_size,
                    "stmin": p.stmin,
                }
                if p.frame_type == "sf":
                    inner_uds = _parse_uds(p.payload)
                    derived_uds_hex = p.payload.hex()
                else:
                    state = self._isotp_states.setdefault(can_id_i, IsoTpReassembly())
                    complete, _ = reassemble_feed(state, bytes(msg.data))
                    if complete is not None:
                        inner_uds = _parse_uds(complete)
                        derived_uds_hex = complete.hex()
                        isotp_fields["reassembly_complete"] = True
            except Exception:
                pass

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
                "inner_uds": inner_uds,
                "inner_uds_hex": derived_uds_hex,
            },
            payload=ByteRange(0, len(msg.data)),
        )


@register_protocol("can")
def can_protocol(config: dict[str, Any]) -> Protocol:
    return _CanProtocol(config)
