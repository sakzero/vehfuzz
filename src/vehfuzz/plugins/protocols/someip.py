from __future__ import annotations

import struct
import time
from typing import Any

from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.plugins import Message, Protocol, register_protocol


_SOMEIP_MESSAGE_TYPES: dict[int, str] = {
    0x00: "request",
    0x01: "request_no_return",
    0x02: "notification",
    0x80: "response",
    0x81: "error",
    0x20: "tp_request",  # best-effort names (SOME/IP-TP)
    0x21: "tp_request_no_return",
    0x22: "tp_notification",
    0xA0: "tp_response",
    0xA1: "tp_error",
}

_SOMEIP_RETURN_CODES: dict[int, str] = {
    0x00: "ok",
    0x01: "not_ok",
    0x02: "unknown_service",
    0x03: "unknown_method",
    0x04: "not_ready",
    0x05: "not_reachable",
    0x06: "timeout",
    0x07: "wrong_protocol_version",
    0x08: "wrong_interface_version",
    0x09: "malformed_message",
    0x0A: "wrong_message_type",
}


def _parse_someip(data: bytes) -> tuple[dict[str, Any], int | None]:
    if len(data) < 16:
        return {"ok": False, "reason": "too_short", "len": len(data)}, None
    service_id, method_id, length, client_id, session_id, proto_ver, iface_ver, msg_type, ret_code = struct.unpack(
        ">HHIHHBBBB", data[:16]
    )
    payload_len = max(0, len(data) - 16)
    expected_len = (payload_len + 8) & 0xFFFFFFFF
    return (
        {
            "service_id": service_id,
            "method_id": method_id,
            "length": int(length),
            "client_id": client_id,
            "session_id": session_id,
            "protocol_version": proto_ver,
            "interface_version": iface_ver,
            "message_type": msg_type,
            "message_type_name": _SOMEIP_MESSAGE_TYPES.get(msg_type, "unknown"),
            "return_code": ret_code,
            "return_code_name": _SOMEIP_RETURN_CODES.get(ret_code, "unknown"),
            "payload_len": payload_len,
            "length_matches": int(length) == expected_len,
        },
        16,
    )


class _SomeIpProtocol(Protocol):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        # Map (client_id, session_id) -> last request info.
        self._pending: dict[tuple[int, int], dict[str, Any]] = {}

    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        service_id = int(self._cfg.get("service_id", 0x1234)) & 0xFFFF
        method_id = int(self._cfg.get("method_id", 0x0001)) & 0xFFFF
        client_id = int(self._cfg.get("client_id", 0x0001)) & 0xFFFF
        session_id = int(self._cfg.get("session_id", 0x0001)) & 0xFFFF
        proto_ver = int(self._cfg.get("protocol_version", 1)) & 0xFF
        iface_ver = int(self._cfg.get("interface_version", 1)) & 0xFF
        msg_type = int(self._cfg.get("message_type", 0x00)) & 0xFF
        ret_code = int(self._cfg.get("return_code", 0x00)) & 0xFF

        # SOME/IP length includes 8 bytes: client_id..return_code + payload.
        length = (len(mutated) + 8) & 0xFFFFFFFF

        header = struct.pack(
            ">HHIHHBBBB",
            service_id,
            method_id,
            length,
            client_id,
            session_id,
            proto_ver,
            iface_ver,
            msg_type,
            ret_code,
        )
        msg = header + mutated
        return Message(
            data=msg,
            meta={
                "someip": {
                    "service_id": service_id,
                    "method_id": method_id,
                    "client_id": client_id,
                    "session_id": session_id,
                    "protocol_version": proto_ver,
                    "interface_version": iface_ver,
                    "message_type": msg_type,
                    "return_code": ret_code,
                    "payload_len": len(mutated),
                }
            },
        )

    def parse(self, msg: Message) -> ParsedMessage:
        fields, payload_off = _parse_someip(bytes(msg.data))
        ok = bool(fields.get("ok", True))
        reason = fields.get("reason")
        payload = None
        if payload_off is not None and payload_off <= len(msg.data):
            payload = ByteRange(payload_off, len(msg.data) - payload_off)
        flow_key = None
        try:
            if ok:
                flow_key = (
                    f"someip:{int(fields['service_id']):04x}:{int(fields['method_id']):04x}:"
                    f"{int(fields['client_id']):04x}:{int(fields['session_id']):04x}"
                )
        except Exception:
            flow_key = None

        # Best-effort method-call correlation (request -> response/error).
        if ok:
            msg_type = int(fields.get("message_type", -1))
            client_id = int(fields.get("client_id", 0))
            session_id = int(fields.get("session_id", 0))
            key = (client_id, session_id)

            if msg_type in (0x00, 0x01, 0x02, 0x20, 0x21, 0x22):
                self._pending[key] = {
                    "service_id": int(fields.get("service_id", 0)),
                    "method_id": int(fields.get("method_id", 0)),
                    "ts": time.time(),
                    "message_type": msg_type,
                }
            elif msg_type in (0x80, 0x81, 0xA0, 0xA1):
                req = self._pending.get(key)
                if req is not None:
                    fields["correlates_to"] = req
                    # Keep small cache to avoid unbounded growth.
                    if len(self._pending) > 1000:
                        self._pending.clear()
                    else:
                        del self._pending[key]

        return ParsedMessage(protocol="someip", level="app", ok=ok, reason=reason, flow_key=flow_key, fields=fields, payload=payload)


@register_protocol("someip")
def someip_protocol(config: dict[str, Any]) -> Protocol:
    return _SomeIpProtocol(config)
