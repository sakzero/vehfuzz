from __future__ import annotations

import struct
from typing import Any

from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.parsers.doip_parser import DOIP_PAYLOAD_TYPE_NAMES, parse_doip_header
from vehfuzz.core.parsers.uds_parser import parse_uds_payload
from vehfuzz.core.plugins import Message, Protocol, register_protocol


# Keep local reference for backward compatibility
_DOIP_PAYLOAD_TYPE_NAMES = DOIP_PAYLOAD_TYPE_NAMES


def _parse_doip(data: bytes) -> tuple[dict[str, Any], int | None]:
    """Parse DoIP header and nested UDS payload."""
    fields, payload_off = parse_doip_header(data)

    # Parse nested UDS if present
    uds_payload = fields.pop("uds_payload", None)
    if uds_payload is not None:
        fields["inner_uds"] = parse_uds_payload(uds_payload)

    return fields, payload_off


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

    def parse(self, msg: Message) -> ParsedMessage:
        fields, payload_off = _parse_doip(bytes(msg.data))
        ok = bool(fields.get("ok", True))
        reason = fields.get("reason")
        payload = None
        if payload_off is not None and payload_off <= len(msg.data):
            payload = ByteRange(payload_off, len(msg.data) - payload_off)
        flow_key = None
        ptype = int(fields.get("payload_type", -1))
        if ptype in (0x8001, 0x8002, 0x8003) and fields.get("diag_src") is not None and fields.get("diag_dst") is not None:
            flow_key = f"doip:diag:{int(fields['diag_src']):04x}->{int(fields['diag_dst']):04x}"
        elif ptype in (0x0005, 0x0006) and fields.get("tester_addr") is not None:
            flow_key = f"doip:ra:{int(fields['tester_addr']):04x}"
        elif ptype in (0x0007, 0x0008):
            flow_key = "doip:alive"
        else:
            flow_key = f"doip:ptype=0x{ptype:04x}"
        return ParsedMessage(protocol="doip", level="l4", ok=ok, reason=reason, flow_key=flow_key, fields=fields, payload=payload)


@register_protocol("doip")
def doip_protocol(config: dict[str, Any]) -> Protocol:
    return _DoipProtocol(config)
