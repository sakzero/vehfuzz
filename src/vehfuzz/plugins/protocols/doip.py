from __future__ import annotations

import struct
from typing import Any

from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.plugins import Message, Protocol, register_protocol


_DOIP_PAYLOAD_TYPE_NAMES: dict[int, str] = {
    0x0001: "vehicle_identification_request",
    0x0002: "vehicle_identification_response",
    0x0003: "vehicle_identification_request_eid",
    0x0004: "vehicle_identification_request_vin",
    0x0005: "routing_activation_request",
    0x0006: "routing_activation_response",
    0x0007: "alive_check_request",
    0x0008: "alive_check_response",
    0x4001: "entity_status_request",
    0x4002: "entity_status_response",
    0x8001: "diagnostic_message",
    0x8002: "diagnostic_message_positive_ack",
    0x8003: "diagnostic_message_negative_ack",
}


def _parse_doip(data: bytes) -> tuple[dict[str, Any], int | None]:
    if len(data) < 8:
        return {"ok": False, "reason": "too_short", "len": len(data)}, None
    version, inv, payload_type, payload_len = struct.unpack(">BBHI", data[:8])
    payload_len_i = int(payload_len)
    available = max(0, len(data) - 8)
    fields: dict[str, Any] = {
        "version": int(version),
        "inverse_version": int(inv),
        "payload_type": int(payload_type),
        "payload_type_name": _DOIP_PAYLOAD_TYPE_NAMES.get(int(payload_type), "unknown"),
        "payload_len": payload_len_i,
        "inverse_ok": ((version ^ inv) & 0xFF) == 0xFF,
        "payload_len_available": available,
        "payload_len_matches": payload_len_i <= available,
    }

    payload = data[8 : 8 + min(payload_len_i, available)]

    # Routing Activation Request (0x0005): tester addr + activation_type + reserved + oem.
    if int(payload_type) == 0x0005 and len(payload) >= 8:
        tester_addr = int.from_bytes(payload[0:2], "big")
        activation_type = int(payload[2])
        fields.update({"tester_addr": tester_addr, "activation_type": activation_type, "oem_len": max(0, len(payload) - 8)})

    # Routing Activation Response (0x0006): best-effort parse.
    if int(payload_type) == 0x0006 and len(payload) >= 5:
        tester_addr = int.from_bytes(payload[0:2], "big")
        # Many stacks put response_code at byte 4; keep best-effort.
        response_code = int(payload[4])
        fields.update({"tester_addr": tester_addr, "activation_response_code": response_code})

    # Alive Check Response (0x0008): logical address.
    if int(payload_type) == 0x0008 and len(payload) >= 2:
        logical_addr = int.from_bytes(payload[0:2], "big")
        fields.update({"logical_addr": logical_addr})

    # Diagnostic Message (0x8001): src/dst + UDS payload.
    if int(payload_type) == 0x8001 and len(payload) >= 4:
        src = int.from_bytes(payload[0:2], "big")
        dst = int.from_bytes(payload[2:4], "big")
        uds = payload[4:]
        fields.update({"diag_src": src, "diag_dst": dst, "uds_len": len(uds)})
        try:
            from vehfuzz.plugins.protocols.uds import _parse_uds  # type: ignore

            fields["inner_uds"] = _parse_uds(uds)
        except Exception:
            pass

    # Diagnostic Ack (0x8002/0x8003): src/dst + ack code.
    if int(payload_type) in (0x8002, 0x8003) and len(payload) >= 5:
        src = int.from_bytes(payload[0:2], "big")
        dst = int.from_bytes(payload[2:4], "big")
        ack = int(payload[4])
        fields.update({"diag_src": src, "diag_dst": dst, "ack_code": ack})

    return fields, 8


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
