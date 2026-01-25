from __future__ import annotations

from typing import Any

from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.plugins import Message, Protocol, register_protocol
from vehfuzz.plugins.protocols.raw import _RawProtocol


_SDP_PDU_IDS = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

# Safety limits
MAX_RFCOMM_INFO_LEN = 32767  # RFCOMM max info length (15-bit)
MAX_SDP_PARAM_LEN = 65535  # SDP max parameter length (16-bit)


def _crc8_msb(data: bytes, *, poly: int = 0x07, init: int = 0xFF) -> int:
    crc = init & 0xFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ poly) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc & 0xFF


def _rfcomm_fcs(data: bytes) -> int:
    # Best-effort RFCOMM FCS: CRC-8 poly=0x07, init=0xFF, final xor=0xFF.
    return _crc8_msb(data) ^ 0xFF


def _decode_rfcomm_len(buf: bytes, off: int, *, remaining: int | None = None) -> tuple[int, int] | None:
    """Decode RFCOMM length field with boundary validation.

    Args:
        buf: Buffer containing the length field
        off: Offset to start decoding
        remaining: Optional remaining bytes after header (for validation)

    Returns:
        Tuple of (length, bytes_consumed) or None if invalid
    """
    if off >= len(buf):
        return None
    b0 = buf[off]
    if b0 & 0x01:
        length = (b0 >> 1) & 0x7F
        len_bytes = 1
    else:
        if off + 1 >= len(buf):
            return None
        b1 = buf[off + 1]
        if (b1 & 0x01) != 0x01:
            return None
        length = ((b0 >> 1) & 0x7F) | (((b1 >> 1) & 0x7F) << 7)
        len_bytes = 2

    # Validate decoded length against remaining buffer if provided
    if remaining is not None and length > remaining:
        # Length exceeds available data - still return but caller should handle
        pass

    # Sanity check: RFCOMM max info length is 15-bit
    if length > MAX_RFCOMM_INFO_LEN:
        return None

    return int(length), len_bytes


def _encode_rfcomm_len(length: int, *, prefer_two_bytes: bool) -> bytes:
    length = int(length)
    if length < 0:
        length = 0
    if not prefer_two_bytes and length <= 0x7F:
        return bytes([((length & 0x7F) << 1) | 0x01])
    lo = length & 0x7F
    hi = (length >> 7) & 0x7F
    return bytes([(lo << 1) & 0xFE]) + bytes([((hi << 1) & 0xFE) | 0x01])


@register_protocol("bluetooth")
def bluetooth_protocol(config: dict[str, Any]) -> Protocol:
    # Offline/pcap-first: if seed is a Bluetooth HCI H4 PCAP packet, mutate L2CAP payload and fix lengths.
    return _BluetoothHciProtocol(config)


class _BluetoothHciProtocol(_RawProtocol):
    def parse(self, msg: Message) -> ParsedMessage:
        pcap_global = msg.meta.get("pcap_global")
        if not isinstance(pcap_global, dict):
            return ParsedMessage(protocol="bluetooth", level="raw", ok=True, fields={"len": len(msg.data)})

        linktype = int(pcap_global.get("network", pcap_global.get("linktype", -1)))
        if linktype not in (187, 201):
            return ParsedMessage(protocol="bluetooth", level="raw", ok=True, fields={"len": len(msg.data), "linktype": linktype})

        pkt = bytes(msg.data)
        phdr_len = 4 if linktype == 201 else 0
        if linktype == 201 and len(pkt) < 4:
            return ParsedMessage(protocol="bluetooth", level="raw", ok=False, reason="phdr_too_short", fields={"len": len(pkt)})

        h4 = pkt[phdr_len:]
        if not h4:
            return ParsedMessage(protocol="bluetooth", level="raw", ok=False, reason="h4_empty", fields={"len": len(pkt)})

        ptype = int(h4[0])
        fields: dict[str, Any] = {"linktype": linktype, "ptype": ptype, "len": len(pkt)}

        # HCI Command packet (0x01): opcode(2 LE), plen(1), params.
        if ptype == 0x01 and len(h4) >= 1 + 3:
            opcode = int.from_bytes(h4[1:3], "little")
            plen = int(h4[3])
            ogf = (opcode >> 10) & 0x3F
            ocf = opcode & 0x03FF
            fields.update({"layer": "hci_cmd", "opcode": opcode, "ogf": ogf, "ocf": ocf, "param_len": plen})
            return ParsedMessage(protocol="bluetooth", level="app", ok=True, flow_key=f"bt:hci:cmd:0x{opcode:04x}", fields=fields, payload=ByteRange(phdr_len + 1 + 3, max(0, min(plen, len(h4) - 4))))

        # HCI Event packet (0x04): evt(1), plen(1), params.
        if ptype == 0x04 and len(h4) >= 1 + 2:
            evt = int(h4[1])
            plen = int(h4[2])
            fields.update({"layer": "hci_evt", "event_code": evt, "param_len": plen})
            # Common events: Command Complete (0x0E) / Command Status (0x0F)
            if evt == 0x0E and plen >= 3 and len(h4) >= 1 + 2 + plen:
                num = int(h4[3])
                opcode = int.from_bytes(h4[4:6], "little")
                fields.update({"cmd_complete": {"num_hci_cmd_pkts": num, "opcode": opcode}})
            if evt == 0x0F and plen >= 4 and len(h4) >= 1 + 2 + plen:
                status = int(h4[3])
                num = int(h4[4])
                opcode = int.from_bytes(h4[5:7], "little")
                fields.update({"cmd_status": {"status": status, "num_hci_cmd_pkts": num, "opcode": opcode}})
            return ParsedMessage(protocol="bluetooth", level="app", ok=True, flow_key=f"bt:hci:evt:0x{evt:02x}", fields=fields, payload=ByteRange(phdr_len + 1 + 2, max(0, min(plen, len(h4) - 3))))

        # Only parse ACL data for deeper layers.
        if ptype != 0x02 or len(h4) < 1 + 4:
            return ParsedMessage(protocol="bluetooth", level="l2", ok=True, fields=fields)

        acl_hdr = h4[1:5]
        handle_flags = int.from_bytes(acl_hdr[0:2], "little")
        acl_len = int.from_bytes(acl_hdr[2:4], "little")
        payload = h4[5:]
        acl_len = min(int(acl_len), len(payload))
        payload = payload[:acl_len]
        fields.update({"handle_flags": handle_flags, "acl_len": acl_len})

        if len(payload) < 4:
            return ParsedMessage(protocol="bluetooth", level="l2", ok=True, fields=fields)

        l2_len = int.from_bytes(payload[0:2], "little")
        cid = int.from_bytes(payload[2:4], "little")
        l2_payload = payload[4:]
        l2_len = min(int(l2_len), len(l2_payload))

        fields.update({"cid": cid, "l2cap_len": l2_len})

        # L2CAP payload slice within the packet.
        l2_payload_off = phdr_len + 1 + 4 + 4
        payload_br = ByteRange(l2_payload_off, l2_len)
        flow_key = f"bt:l2cap:cid=0x{cid:x}"

        # SDP layer detection (best-effort)
        if l2_len >= 5 and int(l2_payload[0]) in _SDP_PDU_IDS:
            pdu_id = int(l2_payload[0])
            txn = int.from_bytes(l2_payload[1:3], "big")
            param_len_declared = int.from_bytes(l2_payload[3:5], "big")
            param_available = max(0, len(l2_payload) - 5)
            param_len = min(param_len_declared, param_available)
            param_len_mismatch = param_len_declared != param_available
            fields.update({
                "layer": "sdp",
                "sdp_pdu_id": pdu_id,
                "sdp_txn": txn,
                "sdp_param_len": param_len,
                "sdp_param_len_declared": param_len_declared,
                "sdp_param_len_mismatch": param_len_mismatch,
            })
            return ParsedMessage(protocol="bluetooth", level="app", ok=True, flow_key=flow_key, fields=fields, payload=payload_br)

        # RFCOMM UIH detection (best-effort)
        if l2_len >= 4:
            addr = int(l2_payload[0])
            ctrl = int(l2_payload[1])
            base_ctrl = ctrl & 0xEF
            if (addr & 0x01) == 0x01 and base_ctrl == 0xEF:
                # Calculate remaining bytes for validation
                remaining_after_len = max(0, len(l2_payload) - 2)
                dec = _decode_rfcomm_len(l2_payload, 2, remaining=remaining_after_len)
                rf_len = None
                rf_hdr_len = None
                rf_len_mismatch = False
                if dec is not None:
                    rf_len, len_len = dec
                    rf_hdr_len = 2 + len_len
                    # Check if declared length matches available data (minus FCS byte)
                    available_info = max(0, len(l2_payload) - rf_hdr_len - 1)
                    rf_len_mismatch = rf_len != available_info
                dlci = (addr >> 2) & 0x3F
                fields.update(
                    {
                        "layer": "rfcomm",
                        "rfcomm_addr": addr,
                        "rfcomm_ctrl": ctrl,
                        "rfcomm_dlci": dlci,
                        "rfcomm_len": rf_len,
                        "rfcomm_hdr_len": rf_hdr_len,
                        "rfcomm_len_mismatch": rf_len_mismatch,
                    }
                )
                return ParsedMessage(protocol="bluetooth", level="app", ok=True, flow_key=flow_key, fields=fields, payload=payload_br)

        return ParsedMessage(protocol="bluetooth", level="l3", ok=True, flow_key=flow_key, fields=fields, payload=payload_br)

    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        pcap_global = seed.meta.get("pcap_global")
        if not isinstance(pcap_global, dict):
            return super().build_tx(seed, mutated)

        linktype = int(pcap_global.get("network", pcap_global.get("linktype", -1)))
        # Common Wireshark linktypes.
        # - 187: DLT_BLUETOOTH_HCI_H4
        # - 201: DLT_BLUETOOTH_HCI_H4_WITH_PHDR
        if linktype not in (187, 201):
            return super().build_tx(seed, mutated)

        pkt = bytes(seed.data)
        phdr = b""
        h4 = pkt
        if linktype == 201:
            if len(pkt) < 4:
                return super().build_tx(seed, mutated)
            phdr, h4 = pkt[:4], pkt[4:]

        if not h4:
            return super().build_tx(seed, mutated)
        ptype = h4[0]
        # Only ACL data carries L2CAP (ptype=0x02). Others fall back to raw mutation.
        if ptype != 0x02 or len(h4) < 1 + 4:
            preserve_len = bool(self._cfg.get("preserve_packet_len", True))
            out = mutated[: len(pkt)].ljust(len(pkt), b"\x00") if preserve_len else mutated
            return Message(data=out, meta={**seed.meta, "bluetooth": {"ptype": int(ptype), "mode": "raw"}})

        hdr = bytearray(h4[1:5])
        handle_flags = int.from_bytes(hdr[0:2], "little")
        acl_len = int.from_bytes(hdr[2:4], "little")
        payload = h4[5:]
        if acl_len > len(payload):
            acl_len = len(payload)
        payload = payload[:acl_len]
        if len(payload) < 4:
            return super().build_tx(seed, mutated)

        l2_len = int.from_bytes(payload[0:2], "little")
        cid = int.from_bytes(payload[2:4], "little")
        l2_payload = payload[4:]
        if l2_len > len(l2_payload):
            l2_len = len(l2_payload)
        l2_payload = l2_payload[:l2_len]

        layer = str(self._cfg.get("layer", "auto")).lower()
        if layer not in ("auto", "l2cap", "sdp", "rfcomm"):
            layer = "auto"

        new_l2 = None
        layer_meta: dict[str, Any] = {"layer": "l2cap"}

        if layer in ("auto", "sdp"):
            out = self._try_mutate_sdp(l2_payload, mutated)
            if out is not None:
                new_l2, layer_meta = out

        if new_l2 is None and layer in ("auto", "rfcomm"):
            out = self._try_mutate_rfcomm(l2_payload, mutated)
            if out is not None:
                new_l2, layer_meta = out

        if new_l2 is None:
            preserve_len = bool(self._cfg.get("preserve_l2cap_len", True))
            if preserve_len:
                new_l2 = mutated[: len(l2_payload)].ljust(len(l2_payload), b"\x00")
            else:
                max_len = int(self._cfg.get("l2cap_max_len", 512))
                new_l2 = mutated[:max_len]

        new_l2_len = len(new_l2) & 0xFFFF
        new_acl_len = (4 + new_l2_len) & 0xFFFF

        out_payload = (
            int.to_bytes(new_l2_len, 2, "little")
            + int.to_bytes(cid & 0xFFFF, 2, "little")
            + new_l2
        )
        out_h4 = bytes([ptype]) + int.to_bytes(handle_flags & 0xFFFF, 2, "little") + int.to_bytes(new_acl_len, 2, "little") + out_payload
        return Message(
            data=phdr + out_h4,
            meta={
                **seed.meta,
                "bluetooth": {
                    "ptype": int(ptype),
                    "cid": cid,
                    "l2cap_len": new_l2_len,
                    **layer_meta,
                },
            },
        )

    def _try_mutate_sdp(self, l2_payload: bytes, mutated: bytes) -> tuple[bytes, dict[str, Any]] | None:
        if len(l2_payload) < 5:
            return None
        pdu_id = int(l2_payload[0])
        if pdu_id not in _SDP_PDU_IDS:
            return None

        transaction_id = int.from_bytes(l2_payload[1:3], "big")
        param_len_declared = int.from_bytes(l2_payload[3:5], "big")
        params = l2_payload[5:]
        # Validate and clamp param_len
        param_len = min(param_len_declared, len(params), MAX_SDP_PARAM_LEN)
        params = params[:param_len]

        preserve_len = bool(self._cfg.get("preserve_sdp_param_len", True))
        if preserve_len:
            new_params = mutated[: len(params)].ljust(len(params), b"\x00")
        else:
            max_len = int(self._cfg.get("sdp_param_max_len", 512))
            new_params = mutated[:max_len]

        out = bytes([pdu_id]) + transaction_id.to_bytes(2, "big") + len(new_params).to_bytes(2, "big") + new_params
        return out, {"layer": "sdp", "sdp_pdu_id": pdu_id, "sdp_txn": transaction_id, "sdp_param_len": len(new_params)}

    def _try_mutate_rfcomm(self, l2_payload: bytes, mutated: bytes) -> tuple[bytes, dict[str, Any]] | None:
        if len(l2_payload) < 4:
            return None
        addr = int(l2_payload[0])
        ctrl = int(l2_payload[1])
        if (addr & 0x01) != 0x01:
            return None

        base_ctrl = ctrl & 0xEF  # clear P/F bit
        is_uih = base_ctrl == 0xEF
        if not is_uih:
            return None

        dec = _decode_rfcomm_len(l2_payload, 2)
        if dec is None:
            return None
        _orig_len, len_len = dec
        hdr_len = 2 + len_len

        # Boundary check: need at least header + 1 byte for FCS
        if hdr_len + 1 > len(l2_payload):
            return None

        # Safe extraction of info field (between header and FCS)
        # Handle edge case where hdr_len == len(l2_payload) - 1 (empty info)
        if hdr_len >= len(l2_payload):
            orig_info = b""
            orig_fcs = 0
        else:
            orig_info = l2_payload[hdr_len:-1] if hdr_len < len(l2_payload) - 1 else b""
            orig_fcs = int(l2_payload[-1])

        preserve_len = bool(self._cfg.get("preserve_rfcomm_info_len", True))
        if preserve_len:
            new_info = mutated[: len(orig_info)].ljust(len(orig_info), b"\x00")
        else:
            max_len = int(self._cfg.get("rfcomm_info_max_len", 512))
            # Clamp to RFCOMM max
            max_len = min(max_len, MAX_RFCOMM_INFO_LEN)
            new_info = mutated[:max_len]

        prefer_two = len_len == 2
        new_len_bytes = _encode_rfcomm_len(len(new_info), prefer_two_bytes=prefer_two)
        header = bytes([addr, ctrl]) + new_len_bytes

        fix_fcs = bool(self._cfg.get("rfcomm_fix_fcs", False))
        if fix_fcs:
            fcs_input = header[:2] if is_uih else header
            new_fcs = _rfcomm_fcs(fcs_input)
        else:
            new_fcs = orig_fcs

        out = header + new_info + bytes([new_fcs & 0xFF])
        dlci = (addr >> 2) & 0x3F
        return out, {"layer": "rfcomm", "rfcomm_dlci": dlci, "rfcomm_info_len": len(new_info)}
