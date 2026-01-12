from __future__ import annotations

from typing import Any

from vehfuzz.core.plugins import Message, Protocol, register_protocol


def _nmea_checksum(body: str) -> int:
    c = 0
    for ch in body:
        c ^= ord(ch) & 0xFF
    return c


class _NmeaProtocol(Protocol):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        try:
            s = mutated.decode("ascii", errors="replace")
        except Exception:
            s = repr(mutated)

        s = s.strip("\r\n")
        if not s.startswith("$"):
            s = "$" + s.lstrip("$")

        # Split "$BODY*CS"
        if "*" in s:
            prefix, _cs = s.split("*", 1)
            body = prefix[1:]
        else:
            body = s[1:]

        # Bound body length to avoid runaway growth when using havoc.
        max_body = int(self._cfg.get("max_body_len", 120))
        body = body[:max_body]

        cs = _nmea_checksum(body)
        out = f"${body}*{cs:02X}\r\n".encode("ascii", errors="replace")
        return Message(data=out, meta={"nmea": {"body_len": len(body), "checksum": f"{cs:02X}"}})


@register_protocol("gnss")
@register_protocol("nmea")
def nmea_protocol(config: dict[str, Any]) -> Protocol:
    return _NmeaProtocol(config)
