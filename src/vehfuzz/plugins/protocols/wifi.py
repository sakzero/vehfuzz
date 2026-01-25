from __future__ import annotations

import struct
from typing import Any

from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.plugins import Message, Protocol, register_protocol
from vehfuzz.plugins.protocols.raw import _RawProtocol


def _validate_wifi_config(cfg: dict[str, Any]) -> None:
    decrypt = cfg.get("decrypt")
    if decrypt is None:
        return
    if not isinstance(decrypt, dict) or not decrypt:
        raise ValueError("wifi protocol_config.decrypt must be a non-empty mapping when provided")

    tk_hex = decrypt.get("ccmp_tk_hex")
    if not isinstance(tk_hex, str) or not tk_hex:
        raise ValueError("wifi protocol_config.decrypt.ccmp_tk_hex is required (16-byte hex key)")
    try:
        tk = bytes.fromhex(tk_hex)
    except Exception as e:
        raise ValueError("wifi protocol_config.decrypt.ccmp_tk_hex must be valid hex") from e
    if len(tk) != 16:
        raise ValueError("wifi protocol_config.decrypt.ccmp_tk_hex must be 16 bytes (32 hex chars)")

    try:
        from Cryptodome.Cipher import AES  # noqa: F401
    except Exception as e:
        raise RuntimeError("Wi-Fi CCMP decryption requires `pycryptodomex` (pip install pycryptodomex)") from e


def _sum16(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return s


def _checksum16(data: bytes) -> int:
    s = _sum16(data)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _ipv4_header_checksum(hdr: bytes) -> int:
    if len(hdr) % 2 == 1:
        hdr += b"\x00"
    return _checksum16(hdr)


def _udp_checksum(src_ip: bytes, dst_ip: bytes, udp_hdr: bytes, payload: bytes) -> int:
    pseudo = src_ip + dst_ip + b"\x00" + bytes([17]) + struct.pack(">H", len(udp_hdr) + len(payload))
    c = _checksum16(pseudo + udp_hdr + payload)
    return 0xFFFF if c == 0 else c


def _tcp_checksum(src_ip: bytes, dst_ip: bytes, tcp_hdr: bytes, payload: bytes) -> int:
    pseudo = src_ip + dst_ip + b"\x00" + bytes([6]) + struct.pack(">H", len(tcp_hdr) + len(payload))
    c = _checksum16(pseudo + tcp_hdr + payload)
    return 0xFFFF if c == 0 else c


@register_protocol("wifi")
def wifi_protocol(config: dict[str, Any]) -> Protocol:
    # Offline/pcap-first: when seed is a PCAP Ethernet+IPv4 packet, mutate L4 payload and recompute checksums.
    _validate_wifi_config(config)
    return _WifiTcpIpProtocol(config)


class _WifiTcpIpProtocol(_RawProtocol):
    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        # Only apply when the seed comes from pcap and the linktype looks like Ethernet.
        pcap_global = seed.meta.get("pcap_global")
        if not isinstance(pcap_global, dict):
            return super().build_tx(seed, mutated)

        linktype = int(pcap_global.get("network", pcap_global.get("linktype", 1)))
        pkt = bytes(seed.data)

        # DLT_EN10MB (Ethernet)
        if linktype == 1:
            out = self._mutate_ethernet_ipv4(pkt, mutated)
            if out is not None:
                data, meta = out
                return Message(data=data, meta={**seed.meta, "wifi": meta})
            return super().build_tx(seed, mutated)

        # DLT_IEEE802_11 (105) / DLT_IEEE802_11_RADIO (127)
        if linktype in (105, 127):
            out = self._mutate_80211_ipv4(pkt, mutated, has_radiotap=(linktype == 127))
            if out is not None:
                data, meta = out
                return Message(data=data, meta={**seed.meta, "wifi": meta})
            return super().build_tx(seed, mutated)

        return super().build_tx(seed, mutated)

    def parse(self, msg: Message) -> ParsedMessage:
        pcap_global = msg.meta.get("pcap_global")
        if not isinstance(pcap_global, dict):
            return ParsedMessage(protocol="wifi", level="raw", ok=True, fields={"len": len(msg.data)})

        linktype = int(pcap_global.get("network", pcap_global.get("linktype", 1)))
        pkt = bytes(msg.data)

        if linktype == 1:
            return _parse_ethernet_ipv4(pkt)
        if linktype in (105, 127):
            return _parse_80211_ipv4(pkt, has_radiotap=(linktype == 127), cfg=self._cfg)
        return ParsedMessage(protocol="wifi", level="raw", ok=True, fields={"linktype": linktype, "len": len(pkt)})

    def _preserve_packet_len(self, *, out: bytes, original_len: int) -> bytes:
        if not bool(self._cfg.get("preserve_packet_len", True)):
            return out
        if len(out) < original_len:
            return out.ljust(original_len, b"\x00")
        if len(out) > original_len:
            return out[:original_len]
        return out

    def _mutate_ethernet_ipv4(self, pkt: bytes, mutated: bytes) -> tuple[bytes, dict[str, Any]] | None:
        if len(pkt) < 14:
            return None
        eth = pkt[:14]
        ethertype = struct.unpack(">H", eth[12:14])[0]
        if ethertype != 0x0800:
            return None
        ip_bytes = pkt[14:]
        out = self._mutate_ipv4_packet(ip_bytes, mutated)
        if out is None:
            return None
        ip_out, meta = out
        data = eth + ip_out
        return self._preserve_packet_len(out=data, original_len=len(pkt)), meta

    def _mutate_80211_ipv4(self, pkt: bytes, mutated: bytes, *, has_radiotap: bool) -> tuple[bytes, dict[str, Any]] | None:
        if has_radiotap:
            if len(pkt) < 8:
                return None
            # Radiotap is little-endian.
            rtap_len = int.from_bytes(pkt[2:4], "little")
            if rtap_len < 8 or rtap_len > len(pkt):
                return None
            rtap = pkt[:rtap_len]
            frame = pkt[rtap_len:]
        else:
            rtap = b""
            frame = pkt

        hdr_len = _ieee80211_data_header_len(frame)
        if hdr_len is None or len(frame) < hdr_len + 8 + 20:
            return None

        # Only handle cleartext data frames (no Protected Frame bit).
        fc = int.from_bytes(frame[0:2], "little")
        if fc & 0x4000:
            return None

        llc = frame[hdr_len : hdr_len + 8]
        if llc[:3] != b"\xaa\xaa\x03" or llc[3:6] != b"\x00\x00\x00":
            return None
        ethertype = struct.unpack(">H", llc[6:8])[0]
        if ethertype != 0x0800:
            return None

        ip_bytes = frame[hdr_len + 8 :]
        out = self._mutate_ipv4_packet(ip_bytes, mutated)
        if out is None:
            return None
        ip_out, meta = out

        new_frame = frame[: hdr_len + 8] + ip_out
        out_pkt = rtap + new_frame
        out_pkt = self._preserve_packet_len(out=out_pkt, original_len=len(pkt))
        meta = {**meta, "linktype": ("radiotap" if has_radiotap else "802.11")}
        return out_pkt, meta

    def _mutate_ipv4_packet(self, ip_bytes: bytes, mutated: bytes) -> tuple[bytes, dict[str, Any]] | None:
        ip = bytearray(ip_bytes)
        if len(ip) < 20:
            return None

        ver_ihl = ip[0]
        version = (ver_ihl >> 4) & 0xF
        ihl = ver_ihl & 0xF
        if version != 4:
            return None
        ip_hlen = ihl * 4
        if ip_hlen < 20 or len(ip) < ip_hlen:
            return None

        ip_total_len = struct.unpack(">H", bytes(ip[2:4]))[0]
        if ip_total_len < ip_hlen:
            return None

        # Track length mismatch for diagnostics
        length_mismatch = False
        if ip_total_len > len(ip):
            length_mismatch = True
            ip_total_len = len(ip)

        proto = int(ip[9])
        src_ip = bytes(ip[12:16])
        dst_ip = bytes(ip[16:20])

        l4 = bytearray(ip[ip_hlen:ip_total_len])
        if proto == 17:
            if len(l4) < 8:
                return None
            udp_hdr = bytearray(l4[:8])
            orig_payload = bytes(l4[8:])

            preserve_len = bool(self._cfg.get("preserve_payload_len", True))
            if preserve_len:
                new_payload = mutated[: len(orig_payload)].ljust(len(orig_payload), b"\x00")
            else:
                max_len = int(self._cfg.get("payload_max_len", 512))
                new_payload = mutated[:max_len]

            udp_len = 8 + len(new_payload)
            # Check for length overflow
            if udp_len > 0xFFFF:
                return None
            udp_hdr[4:6] = struct.pack(">H", udp_len)
            udp_hdr[6:8] = b"\x00\x00"
            udp_chk = _udp_checksum(src_ip, dst_ip, bytes(udp_hdr), new_payload)
            udp_hdr[6:8] = struct.pack(">H", udp_chk)

            total_len = ip_hlen + udp_len
            # Check for IP total length overflow
            if total_len > 0xFFFF:
                return None
            ip[2:4] = struct.pack(">H", total_len)
            ip[10:12] = b"\x00\x00"
            ip_chk = _ipv4_header_checksum(bytes(ip[:ip_hlen]))
            ip[10:12] = struct.pack(">H", ip_chk)

            out = bytes(ip[:ip_hlen]) + bytes(udp_hdr) + new_payload
            return out, {"l4": "udp", "payload_len": len(new_payload), "length_mismatch": length_mismatch}

        if proto == 6:
            if len(l4) < 20:
                return None
            data_offset = (l4[12] >> 4) & 0xF
            tcp_hlen = data_offset * 4
            if tcp_hlen < 20 or len(l4) < tcp_hlen:
                return None

            tcp_hdr = bytearray(l4[:tcp_hlen])
            orig_payload = bytes(l4[tcp_hlen:])

            preserve_len = bool(self._cfg.get("preserve_payload_len", True))
            if preserve_len:
                new_payload = mutated[: len(orig_payload)].ljust(len(orig_payload), b"\x00")
            else:
                max_len = int(self._cfg.get("payload_max_len", 1024))
                new_payload = mutated[:max_len]

            tcp_hdr[16:18] = b"\x00\x00"
            tcp_chk = _tcp_checksum(src_ip, dst_ip, bytes(tcp_hdr), new_payload)
            tcp_hdr[16:18] = struct.pack(">H", tcp_chk)

            total_len = ip_hlen + tcp_hlen + len(new_payload)
            # Check for IP total length overflow
            if total_len > 0xFFFF:
                return None
            ip[2:4] = struct.pack(">H", total_len)
            ip[10:12] = b"\x00\x00"
            ip_chk = _ipv4_header_checksum(bytes(ip[:ip_hlen]))
            ip[10:12] = struct.pack(">H", ip_chk)

            out = bytes(ip[:ip_hlen]) + bytes(tcp_hdr) + new_payload
            return out, {"l4": "tcp", "payload_len": len(new_payload), "length_mismatch": length_mismatch}

        return None


def _ieee80211_data_header_len(frame: bytes) -> int | None:
    if len(frame) < 24:
        return None
    fc = int.from_bytes(frame[0:2], "little")
    ftype = (fc >> 2) & 0x3
    if ftype != 2:
        return None
    subtype = (fc >> 4) & 0xF
    to_ds = (fc >> 8) & 0x1
    from_ds = (fc >> 9) & 0x1

    hdr = 24
    if to_ds and from_ds:
        hdr += 6  # Address4

    # QoS data subtypes are 8-15.
    if subtype >= 8:
        hdr += 2  # QoS Control
        if fc & 0x8000:
            hdr += 4  # HT Control

    return hdr if len(frame) >= hdr else None


def _parse_80211_data_header(frame: bytes, hdr_len: int) -> dict[str, Any]:
    fc = int.from_bytes(frame[0:2], "little")
    to_ds = (fc >> 8) & 0x1
    from_ds = (fc >> 9) & 0x1
    addr1 = frame[4:10] if len(frame) >= 10 else b""
    addr2 = frame[10:16] if len(frame) >= 16 else b""
    addr3 = frame[16:22] if len(frame) >= 22 else b""
    seq_ctrl = int.from_bytes(frame[22:24], "little") if len(frame) >= 24 else 0
    seq = (seq_ctrl >> 4) & 0xFFF
    frag = seq_ctrl & 0xF

    # Address4 only present when ToDS & FromDS.
    addr4 = b""
    if to_ds and from_ds and len(frame) >= 30:
        addr4 = frame[24:30]

    qos_tid = None
    subtype = (fc >> 4) & 0xF
    if subtype >= 8 and hdr_len >= 26 and len(frame) >= 26:
        # QoS control is after Address4 if present, otherwise at offset 24.
        qos_off = 30 if (to_ds and from_ds) else 24
        if len(frame) >= qos_off + 2:
            qos_ctrl = int.from_bytes(frame[qos_off : qos_off + 2], "little")
            qos_tid = qos_ctrl & 0xF

    return {
        "to_ds": int(to_ds),
        "from_ds": int(from_ds),
        "addr1": addr1.hex(":"),
        "addr2": addr2.hex(":"),
        "addr3": addr3.hex(":"),
        "addr4": addr4.hex(":") if addr4 else None,
        "seq": seq,
        "frag": frag,
        "qos_tid": qos_tid,
    }


def _parse_80211_nondata(frame: bytes, *, rtap_len: int, has_radiotap: bool) -> ParsedMessage:
    if len(frame) < 2:
        return ParsedMessage(protocol="wifi", level="l2", ok=False, reason="80211_too_short", fields={"radiotap": has_radiotap, "len": len(frame)})
    fc = int.from_bytes(frame[0:2], "little")
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    fields: dict[str, Any] = {"radiotap": has_radiotap, "type": int(ftype), "subtype": int(subtype), "len": len(frame)}

    # Mgmt frames have 24-byte header.
    if ftype == 0 and len(frame) >= 24:
        fields.update(
            {
                "addr1": frame[4:10].hex(":"),
                "addr2": frame[10:16].hex(":"),
                "addr3": frame[16:22].hex(":"),
            }
        )
        # Tagged parameters start after fixed params; try SSID for common mgmt frames.
        if subtype in (8, 5):  # Beacon / Probe Response
            off = 24 + 12
        elif subtype in (4, 0):  # Probe Request / Assoc Request
            off = 24
        else:
            off = None
        if off is not None and off <= len(frame):
            ssid = _parse_ssid_tag(frame[off:])
            if ssid is not None:
                fields["ssid"] = ssid

    return ParsedMessage(protocol="wifi", level="l2", ok=True, fields=fields)


def _parse_ssid_tag(buf: bytes) -> str | None:
    i = 0
    while i + 2 <= len(buf):
        eid = int(buf[i])
        ln = int(buf[i + 1])
        i += 2
        if i + ln > len(buf):
            break
        val = buf[i : i + ln]
        if eid == 0:
            return val.decode("utf-8", errors="replace")
        i += ln
    return None


def _decrypt_capability(cfg: dict[str, Any]) -> dict[str, Any]:
    d = cfg.get("decrypt") if isinstance(cfg.get("decrypt"), dict) else {}
    return {
        "configured": bool(d),
        "ccmp_tk_hex": bool(isinstance(d.get("ccmp_tk_hex"), str) and d.get("ccmp_tk_hex")),
    }


def _try_ccmp_decrypt(frame: bytes, *, hdr_len: int, hdr: dict[str, Any], cfg: dict[str, Any]) -> tuple[bytes | None, str | None]:
    """
    Attempt CCMP decryption.

    Returns:
        Tuple of (decrypted_payload_or_none, error_reason_or_none)
    """
    d = cfg.get("decrypt") if isinstance(cfg.get("decrypt"), dict) else None
    if not d:
        return None, "no_decrypt_config"
    tk_hex = d.get("ccmp_tk_hex")
    if not isinstance(tk_hex, str) or not tk_hex:
        return None, "no_ccmp_tk"

    try:
        tk = bytes.fromhex(tk_hex)
    except ValueError as e:
        return None, f"invalid_tk_hex: {e}"

    if len(tk) != 16:
        return None, f"tk_wrong_length: {len(tk)}"

    try:
        from Cryptodome.Cipher import AES  # type: ignore
    except ImportError:
        return None, "pycryptodomex_not_installed"

    # CCMP header is 8 bytes immediately after 802.11 header; MIC is last 8 bytes.
    if len(frame) < hdr_len + 8 + 8:
        return None, "frame_too_short_for_ccmp"
    ccmp_hdr = frame[hdr_len : hdr_len + 8]
    enc = frame[hdr_len + 8 :]
    if len(enc) < 8:
        return None, "encrypted_payload_too_short"
    ciphertext, mic = enc[:-8], enc[-8:]

    pn0, pn1 = ccmp_hdr[0], ccmp_hdr[1]
    pn2, pn3, pn4, pn5 = ccmp_hdr[4], ccmp_hdr[5], ccmp_hdr[6], ccmp_hdr[7]
    pn = bytes([pn5, pn4, pn3, pn2, pn1, pn0])

    prio = int(hdr.get("qos_tid") or 0) & 0xFF
    try:
        addr2 = bytes.fromhex(str(hdr.get("addr2", "")).replace(":", ""))
    except (ValueError, AttributeError):
        addr2 = b""
    if len(addr2) != 6:
        addr2 = b"\x00" * 6

    nonce = bytes([prio]) + addr2 + pn
    aad = _ccmp_build_aad(frame[:hdr_len])
    try:
        cipher = AES.new(tk, AES.MODE_CCM, nonce=nonce, mac_len=8)
        cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, mic), None
    except ValueError as e:
        # MIC verification failed or other CCM error
        return None, f"ccm_decrypt_failed: {e}"
    except Exception as e:
        return None, f"decrypt_error: {type(e).__name__}: {e}"


def _ccmp_build_aad(hdr: bytes) -> bytes:
    # Best-effort AAD for CCMP.
    if len(hdr) < 24:
        return b""
    fc = bytearray(hdr[0:2])
    fc[0] &= 0x8F
    fc[1] &= 0xC7
    aad = bytearray()
    aad.extend(fc)
    aad.extend(hdr[2:4])      # duration
    aad.extend(hdr[4:22])     # addr1-3
    seq = bytearray(hdr[22:24])
    seq[0] &= 0x0F
    seq[1] = 0
    aad.extend(seq)
    if len(hdr) >= 30:
        aad.extend(hdr[24:30])  # addr4
    if len(hdr) >= 26:
        aad.extend(hdr[-2:])    # qos control (best-effort)
    return bytes(aad)


def _parse_ethernet_ipv4(pkt: bytes) -> ParsedMessage:
    if len(pkt) < 14:
        return ParsedMessage(protocol="wifi", level="raw", ok=False, reason="ethernet_too_short", fields={"len": len(pkt)})
    ethertype = struct.unpack(">H", pkt[12:14])[0]
    if ethertype != 0x0800:
        return ParsedMessage(protocol="wifi", level="l2", ok=True, fields={"link": "ethernet", "ethertype": ethertype, "len": len(pkt)})

    ip_off = 14
    out = _parse_ipv4(pkt[ip_off:])
    out.fields["link"] = "ethernet"
    if out.payload is not None:
        out = ParsedMessage(
            protocol=out.protocol,
            level=out.level,
            ok=out.ok,
            encrypted=out.encrypted,
            reason=out.reason,
            flow_key=out.flow_key,
            fields=out.fields,
            payload=ByteRange(ip_off + out.payload.offset, out.payload.length),
        )
    return out


def _parse_80211_ipv4(pkt: bytes, *, has_radiotap: bool, cfg: dict[str, Any]) -> ParsedMessage:
    rtap_len = 0
    frame = pkt
    if has_radiotap:
        if len(pkt) < 8:
            return ParsedMessage(protocol="wifi", level="raw", ok=False, reason="radiotap_too_short", fields={"len": len(pkt)})
        rtap_len = int.from_bytes(pkt[2:4], "little")
        if rtap_len < 8 or rtap_len > len(pkt):
            return ParsedMessage(protocol="wifi", level="raw", ok=False, reason="radiotap_len_invalid", fields={"len": len(pkt), "rtap_len": rtap_len})
        frame = pkt[rtap_len:]

    hdr_len = _ieee80211_data_header_len(frame)
    if hdr_len is None:
        return _parse_80211_nondata(frame, rtap_len=rtap_len, has_radiotap=has_radiotap)
    if len(frame) < hdr_len:
        return ParsedMessage(protocol="wifi", level="l2", ok=False, reason="80211_hdr_invalid", fields={"len": len(pkt), "radiotap": has_radiotap})

    fc = int.from_bytes(frame[0:2], "little")
    protected = bool(fc & 0x4000)
    hdr = _parse_80211_data_header(frame, hdr_len)
    if protected:
        pt, decrypt_error = _try_ccmp_decrypt(frame, hdr_len=hdr_len, hdr=hdr, cfg=cfg)
        if pt is None:
            return ParsedMessage(
                protocol="wifi",
                level="l2",
                ok=True,
                encrypted=True,
                reason="protected_data_frame",
                fields={
                    "radiotap": has_radiotap,
                    "hdr_len": hdr_len,
                    "len": len(pkt),
                    **hdr,
                    "decrypt": _decrypt_capability(cfg),
                    "decrypt_error": decrypt_error,
                },
            )
        # Decrypted payload includes LLC+payload.
        if len(pt) < 8:
            return ParsedMessage(protocol="wifi", level="l2", ok=True, encrypted=False, reason="decrypted_no_llc", fields={"radiotap": has_radiotap, **hdr, "len": len(pkt), "decrypted": True})
        llc = pt[:8]
        if llc[:3] != b"\xaa\xaa\x03" or llc[3:6] != b"\x00\x00\x00":
            return ParsedMessage(protocol="wifi", level="l2", ok=True, encrypted=False, reason="decrypted_unknown_llc", fields={"radiotap": has_radiotap, **hdr, "len": len(pkt), "decrypted": True})
        ethertype = struct.unpack(">H", llc[6:8])[0]
        if ethertype != 0x0800:
            return ParsedMessage(protocol="wifi", level="l2", ok=True, encrypted=False, fields={"radiotap": has_radiotap, **hdr, "ethertype": ethertype, "len": len(pkt), "decrypted": True})

        ip_off = rtap_len + hdr_len + 8
        out = _parse_ipv4(pt[8:])
        out.fields["link"] = "802.11_radiotap" if has_radiotap else "802.11"
        out.fields["decrypted"] = True
        out.fields.update(hdr)
        if out.payload is not None:
            out = ParsedMessage(
                protocol=out.protocol,
                level=out.level,
                ok=out.ok,
                encrypted=out.encrypted,
                reason=out.reason,
                flow_key=out.flow_key,
                fields=out.fields,
                payload=ByteRange(ip_off + out.payload.offset, out.payload.length),
            )
        return out

    llc = frame[hdr_len : hdr_len + 8]
    if llc[:3] != b"\xaa\xaa\x03" or llc[3:6] != b"\x00\x00\x00":
        return ParsedMessage(protocol="wifi", level="l2", ok=True, fields={"radiotap": has_radiotap, "hdr_len": hdr_len, "len": len(pkt), **hdr, "llc": "unknown"})
    ethertype = struct.unpack(">H", llc[6:8])[0]
    if ethertype != 0x0800:
        return ParsedMessage(protocol="wifi", level="l2", ok=True, fields={"radiotap": has_radiotap, "hdr_len": hdr_len, "ethertype": ethertype, "len": len(pkt), **hdr})

    ip_off = rtap_len + hdr_len + 8
    out = _parse_ipv4(frame[hdr_len + 8 :])
    out.fields["link"] = "802.11_radiotap" if has_radiotap else "802.11"
    out.fields.update(hdr)
    if out.payload is not None:
        out = ParsedMessage(
            protocol=out.protocol,
            level=out.level,
            ok=out.ok,
            encrypted=out.encrypted,
            reason=out.reason,
            flow_key=out.flow_key,
            fields=out.fields,
            payload=ByteRange(ip_off + out.payload.offset, out.payload.length),
        )
    return out


def _parse_ipv4(ip_bytes: bytes) -> ParsedMessage:
    if len(ip_bytes) < 20:
        return ParsedMessage(protocol="wifi", level="l3", ok=False, reason="ipv4_too_short", fields={"len": len(ip_bytes)})

    ver_ihl = ip_bytes[0]
    version = (ver_ihl >> 4) & 0xF
    ihl = ver_ihl & 0xF
    if version != 4:
        return ParsedMessage(protocol="wifi", level="l3", ok=False, reason="not_ipv4", fields={"version": version})
    ip_hlen = ihl * 4
    if ip_hlen < 20 or len(ip_bytes) < ip_hlen:
        return ParsedMessage(protocol="wifi", level="l3", ok=False, reason="ipv4_ihl_invalid", fields={"ihl": ihl, "len": len(ip_bytes)})

    total_len = struct.unpack(">H", ip_bytes[2:4])[0]
    if total_len < ip_hlen:
        return ParsedMessage(protocol="wifi", level="l3", ok=False, reason="ipv4_total_len_invalid", fields={"total_len": total_len, "ip_hlen": ip_hlen})
    total_len = min(int(total_len), len(ip_bytes))

    proto = int(ip_bytes[9])
    src_ip = ".".join(str(b) for b in ip_bytes[12:16])
    dst_ip = ".".join(str(b) for b in ip_bytes[16:20])

    l4_off = ip_hlen
    l4 = ip_bytes[l4_off:total_len]
    fields: dict[str, Any] = {"src_ip": src_ip, "dst_ip": dst_ip, "ip_proto": proto, "ip_total_len": int(total_len), "ip_hlen": int(ip_hlen)}

    if proto == 17 and len(l4) >= 8:
        src_port, dst_port, udp_len = struct.unpack(">HHH", l4[:6])
        fields.update({"l4": "udp", "src_port": src_port, "dst_port": dst_port, "udp_len": udp_len})
        flow_key = f"ipv4:udp:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        payload_off = l4_off + 8
        payload_len = max(0, min(len(ip_bytes), total_len) - payload_off)
        return ParsedMessage(protocol="wifi", level="l4", ok=True, flow_key=flow_key, fields=fields, payload=ByteRange(payload_off, payload_len))

    if proto == 6 and len(l4) >= 20:
        src_port, dst_port = struct.unpack(">HH", l4[:4])
        data_offset = (l4[12] >> 4) & 0xF
        tcp_hlen = data_offset * 4
        if tcp_hlen < 20 or len(l4) < tcp_hlen:
            return ParsedMessage(protocol="wifi", level="l4", ok=False, reason="tcp_hlen_invalid", flow_key=f"ipv4:tcp:{src_ip}:{src_port}->{dst_ip}:{dst_port}", fields={**fields, "src_port": src_port, "dst_port": dst_port, "tcp_hlen": tcp_hlen})
        fields.update({"l4": "tcp", "src_port": src_port, "dst_port": dst_port, "tcp_hlen": tcp_hlen})
        flow_key = f"ipv4:tcp:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        payload_off = l4_off + tcp_hlen
        payload_len = max(0, min(len(ip_bytes), total_len) - payload_off)
        return ParsedMessage(protocol="wifi", level="l4", ok=True, flow_key=flow_key, fields=fields, payload=ByteRange(payload_off, payload_len))

    return ParsedMessage(protocol="wifi", level="l3", ok=True, fields=fields)
