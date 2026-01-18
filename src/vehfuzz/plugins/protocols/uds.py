from __future__ import annotations

from typing import Any

from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.plugins import Message, Protocol, register_protocol


def _parse_uds(data: bytes) -> dict[str, Any]:
    if not data:
        return {"kind": "empty"}

    sid = int(data[0])
    if sid == 0x7F and len(data) >= 3:
        req_sid = int(data[1])
        nrc = int(data[2])
        return {
            "kind": "negative_response",
            "sid": sid,
            "request_sid": req_sid,
            "nrc": nrc,
        }

    # Positive response SID is request SID + 0x40 in many services.
    is_positive = sid >= 0x40
    req_sid = (sid - 0x40) & 0xFF if is_positive else sid

    out: dict[str, Any] = {
        "kind": "positive_response" if is_positive else "request",
        "sid": sid,
        "request_sid": req_sid,
    }

    # Best-effort service-specific parsing for common services.
    if req_sid == 0x10 and len(data) >= 2:
        out["session_type"] = int(data[1])
    elif req_sid == 0x27 and len(data) >= 2:
        out["security_subfunction"] = int(data[1])
        out["payload_len"] = max(0, len(data) - 2)
    elif req_sid == 0x22 and len(data) >= 3:
        out["did"] = (int(data[1]) << 8) | int(data[2])
    elif req_sid == 0x2E and len(data) >= 3:
        out["did"] = (int(data[1]) << 8) | int(data[2])
        out["payload_len"] = max(0, len(data) - 3)
    elif req_sid == 0x3E and len(data) >= 2:
        out["subfunction"] = int(data[1])
    elif req_sid == 0x19 and len(data) >= 2:
        out["subfunction"] = int(data[1])
    else:
        if len(data) >= 2:
            out["subfunction"] = int(data[1])
    return out


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
        fields = _parse_uds(bytes(msg.data))
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
