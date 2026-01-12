from __future__ import annotations

from typing import Any

from vehfuzz.core.plugins import Message, Protocol, register_protocol
from vehfuzz.plugins.protocols.raw import _RawProtocol


_SDP_PDU_IDS = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}


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


def _decode_rfcomm_len(buf: bytes, off: int) -> tuple[int, int] | None:
    if off >= len(buf):
        return None
    b0 = buf[off]
    if b0 & 0x01:
        return (b0 >> 1) & 0x7F, 1
    if off + 1 >= len(buf):
        return None
    b1 = buf[off + 1]
    if (b1 & 0x01) != 0x01:
        return None
    length = ((b0 >> 1) & 0x7F) | (((b1 >> 1) & 0x7F) << 7)
    return int(length), 2


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
        param_len = int.from_bytes(l2_payload[3:5], "big")
        params = l2_payload[5:]
        if param_len > len(params):
            param_len = len(params)
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
        if len(l2_payload) < hdr_len + 1:
            return None

        orig_info = l2_payload[hdr_len:-1]
        orig_fcs = int(l2_payload[-1])

        preserve_len = bool(self._cfg.get("preserve_rfcomm_info_len", True))
        if preserve_len:
            new_info = mutated[: len(orig_info)].ljust(len(orig_info), b"\x00")
        else:
            max_len = int(self._cfg.get("rfcomm_info_max_len", 512))
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
