from __future__ import annotations

import struct
from typing import Any

from vehfuzz.core.plugins import Message, Protocol, register_protocol


class _SomeIpProtocol(Protocol):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

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


@register_protocol("someip")
def someip_protocol(config: dict[str, Any]) -> Protocol:
    return _SomeIpProtocol(config)

