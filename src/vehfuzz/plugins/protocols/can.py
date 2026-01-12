from __future__ import annotations

from typing import Any

from vehfuzz.core.plugins import Message, Protocol, register_protocol


class _CanProtocol(Protocol):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

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


@register_protocol("can")
def can_protocol(config: dict[str, Any]) -> Protocol:
    return _CanProtocol(config)

