from __future__ import annotations

from typing import Any

from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.parsers.uds_parser import parse_uds_payload
from vehfuzz.core.plugins import Message, Protocol, register_protocol


# Re-export for backward compatibility (deprecated, use core.parsers.uds_parser)
_parse_uds = parse_uds_payload


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

    def parse(self, msg: Message) -> ParsedMessage:
        fields = parse_uds_payload(bytes(msg.data))
        fields["len"] = len(msg.data)
        flow_key = None
        if isinstance(msg.meta.get("doip"), dict):
            d = msg.meta["doip"]
            src = d.get("src")
            dst = d.get("dst")
            if src is not None and dst is not None:
                flow_key = f"uds:doip:{int(src):04x}->{int(dst):04x}"
        if flow_key is None and isinstance(msg.meta.get("isotp"), dict):
            i = msg.meta["isotp"]
            rx_id = i.get("rx_id")
            tx_id = i.get("tx_id")
            if rx_id is not None and tx_id is not None:
                flow_key = f"uds:isotp:{int(tx_id):x}->{int(rx_id):x}"
        if flow_key is None:
            sid = fields.get("sid")
            flow_key = f"uds:sid=0x{int(sid):02x}" if sid is not None else "uds"
        return ParsedMessage(
            protocol="uds",
            level="app",
            ok=True,
            flow_key=flow_key,
            fields=fields,
            payload=ByteRange(0, len(msg.data)),
        )


@register_protocol("uds")
def uds_protocol(config: dict[str, Any]) -> Protocol:
    return _UdsProtocol(config)
