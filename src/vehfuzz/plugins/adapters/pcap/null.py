from __future__ import annotations

from typing import Any

from vehfuzz.core.plugins import Adapter, Message, register_adapter


class _NullAdapter(Adapter):
    def open(self) -> None:
        return None

    def close(self) -> None:
        return None

    def send(self, msg: Message) -> None:
        return None

    def recv(self, timeout_s: float) -> Message | None:
        return None


@register_adapter("null")
def null_adapter(_config: dict[str, Any]) -> Adapter:
    return _NullAdapter()

