from __future__ import annotations

import struct
from typing import Any

from vehfuzz.core.plugins import Message, Protocol, register_protocol


class _DoipProtocol(Protocol):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        version = int(self._cfg.get("version", 0x02)) & 0xFF
        inv = int(self._cfg.get("inverse_version", (version ^ 0xFF))) & 0xFF
        payload_type = int(self._cfg.get("payload_type", 0x8001)) & 0xFFFF
        payload_len = len(mutated) & 0xFFFFFFFF

        header = struct.pack(">BBHI", version, inv, payload_type, payload_len)
        return Message(
            data=header + mutated,
            meta={
                "doip": {
                    "version": version,
                    "inverse_version": inv,
                    "payload_type": payload_type,
                    "payload_len": payload_len,
                }
            },
        )


@register_protocol("doip")
def doip_protocol(config: dict[str, Any]) -> Protocol:
    return _DoipProtocol(config)

