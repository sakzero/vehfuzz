from __future__ import annotations

from typing import Any

from vehfuzz.core.plugins import Message, Protocol, register_protocol


class _UdsProtocol(Protocol):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        max_len = self._cfg.get("max_len")
        if max_len is not None:
            max_len = int(max_len)
            if max_len > 0:
                mutated = mutated[:max_len]

        sid = mutated[0] if mutated else None
        meta = dict(seed.meta)
        meta.update({"uds": {"sid": sid, "len": len(mutated)}})
        return Message(data=mutated, meta=meta)


@register_protocol("uds")
def uds_protocol(config: dict[str, Any]) -> Protocol:
    return _UdsProtocol(config)

