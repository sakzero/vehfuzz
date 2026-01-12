from __future__ import annotations

import struct
from typing import Any

from vehfuzz.core.plugins import Message, Protocol, register_protocol


def _sd_flags(*, reboot: bool, unicast: bool, raw_flags: int | None = None) -> int:
    if raw_flags is not None:
        return int(raw_flags) & 0xFF
    flags = 0
    if reboot:
        flags |= 0x80
    if unicast:
        flags |= 0x40
    return flags & 0xFF


class _SomeIpSdProtocol(Protocol):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        cfg = self._cfg

        service_id = int(cfg.get("service_id", 0xFFFF)) & 0xFFFF
        method_id = int(cfg.get("method_id", 0x8100)) & 0xFFFF
        client_id = int(cfg.get("client_id", 0x0000)) & 0xFFFF
        session_id = int(cfg.get("session_id", 0x0001)) & 0xFFFF
        proto_ver = int(cfg.get("protocol_version", 1)) & 0xFF
        iface_ver = int(cfg.get("interface_version", 1)) & 0xFF
        msg_type = int(cfg.get("message_type", 0x02)) & 0xFF  # notification
        ret_code = int(cfg.get("return_code", 0x00)) & 0xFF

        max_entries_len = int(cfg.get("max_entries_len", 256))
        if max_entries_len < 0:
            max_entries_len = 0
        entries = mutated[:max_entries_len]
        options = b""

        reboot = bool(cfg.get("reboot", False))
        unicast = bool(cfg.get("unicast", True))
        flags = _sd_flags(reboot=reboot, unicast=unicast, raw_flags=cfg.get("flags"))

        sd_payload = (
            struct.pack(">B3sI", flags, b"\x00\x00\x00", len(entries))
            + entries
            + struct.pack(">I", len(options))
            + options
        )

        # SOME/IP length includes 8 bytes: client_id..return_code + payload.
        length = (len(sd_payload) + 8) & 0xFFFFFFFF
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
        return Message(
            data=header + sd_payload,
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
                    "payload_len": len(sd_payload),
                },
                "someip_sd": {
                    "flags": flags,
                    "entries_len": len(entries),
                    "options_len": len(options),
                },
            },
        )


@register_protocol("someip_sd")
def someip_sd_protocol(config: dict[str, Any]) -> Protocol:
    return _SomeIpSdProtocol(config)

