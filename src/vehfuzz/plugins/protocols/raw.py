from __future__ import annotations

from typing import Any

from vehfuzz.core.plugins import Message, Protocol, register_protocol
from vehfuzz.core.parsed import ByteRange, ParsedMessage


class _RawProtocol(Protocol):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        # By default keep seed.meta only as provenance; adapters can ignore.
        meta = dict(seed.meta)
        meta.setdefault("seed_len", len(seed.data))
        meta.setdefault("mutated_len", len(mutated))
        return Message(data=mutated, meta=meta)

    def parse(self, msg: Message) -> ParsedMessage:
        return ParsedMessage(
            protocol="raw",
            level="raw",
            ok=True,
            flow_key="raw",
            fields={"len": len(msg.data)},
            payload=ByteRange(0, len(msg.data)),
        )


@register_protocol("raw")
def raw_protocol(config: dict[str, Any]) -> Protocol:
    return _RawProtocol(config)
