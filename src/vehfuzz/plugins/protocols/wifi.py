from __future__ import annotations

import struct
from typing import Any

from vehfuzz.core.plugins import Message, Protocol, register_protocol
from vehfuzz.plugins.protocols.raw import _RawProtocol


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
        if ip_total_len > len(ip):
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
            udp_hdr[4:6] = struct.pack(">H", udp_len & 0xFFFF)
            udp_hdr[6:8] = b"\x00\x00"
            udp_chk = _udp_checksum(src_ip, dst_ip, bytes(udp_hdr), new_payload)
            udp_hdr[6:8] = struct.pack(">H", udp_chk)

            total_len = ip_hlen + udp_len
            ip[2:4] = struct.pack(">H", total_len & 0xFFFF)
            ip[10:12] = b"\x00\x00"
            ip_chk = _ipv4_header_checksum(bytes(ip[:ip_hlen]))
            ip[10:12] = struct.pack(">H", ip_chk)

            out = bytes(ip[:ip_hlen]) + bytes(udp_hdr) + new_payload
            return out, {"l4": "udp", "payload_len": len(new_payload)}

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
            ip[2:4] = struct.pack(">H", total_len & 0xFFFF)
            ip[10:12] = b"\x00\x00"
            ip_chk = _ipv4_header_checksum(bytes(ip[:ip_hlen]))
            ip[10:12] = struct.pack(">H", ip_chk)

            out = bytes(ip[:ip_hlen]) + bytes(tcp_hdr) + new_payload
            return out, {"l4": "tcp", "payload_len": len(new_payload)}

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
