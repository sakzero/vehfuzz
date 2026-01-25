from __future__ import annotations

import struct
from typing import Any

from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.plugins import Message, Protocol, register_protocol


# Configurable limits for parsing
DEFAULT_MAX_ENTRIES = 100
DEFAULT_MAX_OPTIONS = 100


def _sd_flags(*, reboot: bool, unicast: bool, raw_flags: int | None = None) -> int:
    if raw_flags is not None:
        return int(raw_flags) & 0xFF
    flags = 0
    if reboot:
        flags |= 0x80
    if unicast:
        flags |= 0x40
    return flags & 0xFF


def _sd_option_type_name(opt_type: int) -> str:
    opt_type &= 0xFF
    return {
        0x01: "configuration",
        0x02: "load_balancing",
        0x04: "ipv4_endpoint",
        0x06: "ipv6_endpoint",
        0x14: "ipv4_multicast",
        0x16: "ipv6_multicast",
        0x24: "ipv4_sd_endpoint",
        0x26: "ipv6_sd_endpoint",
    }.get(opt_type, "unknown")


def _fill_sd_option_fields(out: dict[str, Any], opt_type: int, data: bytes) -> None:
    opt_type &= 0xFF
    if opt_type in (0x04, 0x14, 0x24) and len(data) >= 8:
        ip = ".".join(str(b) for b in data[0:4])
        l4_proto = int(data[5])
        port = int.from_bytes(data[6:8], "big")
        out.update(
            {
                "ip": ip,
                "l4_proto": l4_proto,
                "l4_proto_name": {0x06: "tcp", 0x11: "udp"}.get(l4_proto, "unknown"),
                "port": port,
            }
        )
        return

    if opt_type in (0x06, 0x16, 0x26) and len(data) >= 20:
        ip6 = ":".join(f"{int.from_bytes(data[i:i+2],'big'):x}" for i in range(0, 16, 2))
        l4_proto = int(data[17])
        port = int.from_bytes(data[18:20], "big")
        out.update(
            {
                "ip": ip6,
                "l4_proto": l4_proto,
                "l4_proto_name": {0x06: "tcp", 0x11: "udp"}.get(l4_proto, "unknown"),
                "port": port,
            }
        )
        return

    if opt_type == 0x01:
        # Configuration option: often key=value strings; keep bytes and best-effort ascii.
        out["text"] = data.decode("ascii", errors="replace")
        return

    if opt_type == 0x02 and len(data) >= 5:
        # Load balancing: priority(2) weight(2) reserved(1) - best effort
        out["priority"] = int.from_bytes(data[0:2], "big")
        out["weight"] = int.from_bytes(data[2:4], "big")
        return


class _SomeIpSdProtocol(Protocol):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._max_entries = int(config.get("max_entries", DEFAULT_MAX_ENTRIES))
        self._max_options = int(config.get("max_options", DEFAULT_MAX_OPTIONS))

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

    def parse(self, msg: Message) -> ParsedMessage:
        data = bytes(msg.data)
        if len(data) < 16 + 1 + 3 + 4 + 4:
            return ParsedMessage(protocol="someip_sd", level="raw", ok=False, reason="too_short", fields={"len": len(data)})

        someip = {}
        try:
            service_id, method_id, length, client_id, session_id, proto_ver, iface_ver, msg_type, ret_code = struct.unpack(
                ">HHIHHBBBB", data[:16]
            )
            someip = {
                "service_id": service_id,
                "method_id": method_id,
                "length": int(length),
                "client_id": client_id,
                "session_id": session_id,
                "protocol_version": proto_ver,
                "interface_version": iface_ver,
                "message_type": msg_type,
                "return_code": ret_code,
            }
        except Exception as e:
            return ParsedMessage(protocol="someip_sd", level="raw", ok=False, reason=f"someip_header_parse_error:{e}", fields={"len": len(data)})

        payload = data[16:]
        flags = int(payload[0])
        entries_len_decl = int.from_bytes(payload[4:8], "big")
        entries_off = 8
        entries_len = max(0, min(entries_len_decl, len(payload) - entries_off))

        options_len_off = entries_off + entries_len
        options_len_decl: int | None = None
        if options_len_off + 4 <= len(payload):
            options_len_decl = int.from_bytes(payload[options_len_off : options_len_off + 4], "big")

        options_off = options_len_off + 4
        options_len = 0
        if options_len_decl is not None and options_off <= len(payload):
            options_len = max(0, min(int(options_len_decl), len(payload) - options_off))

        entries_bytes = payload[entries_off : entries_off + entries_len]
        options_bytes = payload[options_off : options_off + options_len] if options_len > 0 else b""

        parsed_entries: list[dict[str, Any]] = []
        entry_size = 16
        for i in range(0, len(entries_bytes), entry_size):
            if len(parsed_entries) >= self._max_entries:
                break
            chunk = entries_bytes[i : i + entry_size]
            if len(chunk) < entry_size:
                break
            etype = int(chunk[0])
            idx1 = int(chunk[1])
            idx2 = int(chunk[2])
            num_opts = int(chunk[3])
            num_opts_1 = (num_opts >> 4) & 0xF
            num_opts_2 = num_opts & 0xF
            sid = int.from_bytes(chunk[4:6], "big")
            iid = int.from_bytes(chunk[6:8], "big")
            major = int(chunk[8])
            ttl = int.from_bytes(chunk[9:12], "big")

            entry: dict[str, Any] = {
                "offset": i,
                "type": etype,
                "type_name": {0x00: "FindService", 0x01: "OfferService", 0x06: "SubscribeEventgroup", 0x07: "SubscribeEventgroupAck"}.get(etype, "unknown"),
                "index_1st_options": idx1,
                "index_2nd_options": idx2,
                "num_1st_options": num_opts_1,
                "num_2nd_options": num_opts_2,
                "service_id": sid,
                "instance_id": iid,
                "major_version": major,
                "ttl": ttl,
            }

            # Best-effort: Service entries carry Minor Version (4 bytes); Eventgroup entries carry Eventgroup ID (2 bytes).
            if etype in (0x00, 0x01):  # FindService / OfferService
                entry["minor_version"] = int.from_bytes(chunk[12:16], "big")
            else:
                entry["eventgroup_id"] = int.from_bytes(chunk[12:14], "big")

            parsed_entries.append(entry)

        parsed_options: list[dict[str, Any]] = []
        # Best-effort SOME/IP-SD option parsing: total length = 2 + opt_len.
        o = 0
        while o + 4 <= len(options_bytes) and len(parsed_options) < self._max_options:
            opt_len = int.from_bytes(options_bytes[o : o + 2], "big")
            total = 2 + opt_len
            if total < 4 or o + total > len(options_bytes):
                break
            opt_type = int(options_bytes[o + 2])
            # byte o+3 is reserved
            opt_data = options_bytes[o + 4 : o + total]
            opt: dict[str, Any] = {"offset": o, "type": opt_type, "type_name": _sd_option_type_name(opt_type), "len": opt_len, "data_len": len(opt_data)}
            _fill_sd_option_fields(opt, opt_type, opt_data)
            parsed_options.append(opt)
            o += total

        # Resolve entry -> options with bounds checking
        resolved_entries: list[dict[str, Any]] = []
        for e in parsed_entries:
            idx1 = int(e.get("index_1st_options", 0))
            idx2 = int(e.get("index_2nd_options", 0))
            n1 = int(e.get("num_1st_options", 0))
            n2 = int(e.get("num_2nd_options", 0))

            # Safe bounds checking for option indices
            opts1 = []
            if 0 <= idx1 < len(parsed_options) and idx1 + n1 <= len(parsed_options):
                opts1 = parsed_options[idx1 : idx1 + n1]
            opts2 = []
            if 0 <= idx2 < len(parsed_options) and idx2 + n2 <= len(parsed_options):
                opts2 = parsed_options[idx2 : idx2 + n2]

            resolved_entries.append(
                {
                    "service_id": e.get("service_id"),
                    "instance_id": e.get("instance_id"),
                    "type": e.get("type"),
                    "type_name": e.get("type_name"),
                    "options_1": opts1,
                    "options_2": opts2,
                }
            )

        # Calculate how many entries/options were truncated
        total_entries_possible = len(entries_bytes) // entry_size
        entries_truncated = max(0, total_entries_possible - len(parsed_entries))

        fields = {
            **someip,
            "sd_flags": flags,
            "sd_entries_len": entries_len,
            "sd_entries_len_declared": entries_len_decl,
            "sd_entries_count": len(parsed_entries),
            "sd_entries_truncated": entries_truncated,
            "sd_options_len": options_len,
            "sd_options_len_declared": options_len_decl,
            "sd_options_count": len(parsed_options),
            "sd_entries": parsed_entries,
            "sd_options": parsed_options,
            "sd_entries_resolved": resolved_entries,
            "payload_len": len(payload),
        }
        return ParsedMessage(
            protocol="someip_sd",
            level="app",
            ok=True,
            flow_key="someip_sd",
            fields=fields,
            payload=ByteRange(16 + entries_off, max(0, min(entries_len, len(payload) - entries_off))),
        )


@register_protocol("someip_sd")
def someip_sd_protocol(config: dict[str, Any]) -> Protocol:
    return _SomeIpSdProtocol(config)
