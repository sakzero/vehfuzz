from __future__ import annotations

import struct
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from vehfuzz.core.plugins import Message


class OfflineSink(ABC):
    @abstractmethod
    def emit(self, msg: Message) -> None: ...

    @abstractmethod
    def close(self) -> None: ...


class HexSink(OfflineSink):
    def __init__(self, path: Path) -> None:
        self._fp = path.open("w", encoding="utf-8", newline="\n")

    def emit(self, msg: Message) -> None:
        self._fp.write(msg.data.hex() + "\n")

    def close(self) -> None:
        self._fp.close()


class TextSink(OfflineSink):
    def __init__(self, path: Path) -> None:
        self._fp = path.open("w", encoding="utf-8", newline="\n")

    def emit(self, msg: Message) -> None:
        try:
            text = msg.data.decode("ascii", errors="replace")
        except (UnicodeDecodeError, AttributeError):
            text = repr(msg.data)
        self._fp.write(text)
        if not text.endswith("\n"):
            self._fp.write("\n")

    def close(self) -> None:
        self._fp.close()


class CandumpSink(OfflineSink):
    def __init__(self, path: Path, iface: str = "vcan0") -> None:
        self._fp = path.open("w", encoding="utf-8", newline="\n")
        self._iface = iface

    def emit(self, msg: Message) -> None:
        ts = time.time()
        can_id = int(msg.meta.get("can_id", 0))
        is_fd = bool(msg.meta.get("is_fd", False))
        sep = "##" if is_fd else "#"
        self._fp.write(f"({ts:.6f}) {self._iface} {can_id:x}{sep}{msg.data.hex()}\n")

    def close(self) -> None:
        self._fp.close()


class PcapSink(OfflineSink):
    def __init__(self, path: Path, pcap_global: dict[str, Any]) -> None:
        self._fp = path.open("wb")
        self._gh = pcap_global

        endianness = str(pcap_global.get("endianness", "<"))
        ts_resolution = str(pcap_global.get("ts_resolution", "us"))
        if endianness not in ("<", ">"):
            raise ValueError("pcap endianness must be '<' or '>'")
        if ts_resolution not in ("us", "ns"):
            raise ValueError("pcap ts_resolution must be 'us' or 'ns'")

        if endianness == "<" and ts_resolution == "us":
            magic = b"\xd4\xc3\xb2\xa1"
        elif endianness == ">" and ts_resolution == "us":
            magic = b"\xa1\xb2\xc3\xd4"
        elif endianness == "<" and ts_resolution == "ns":
            magic = b"\x4d\x3c\xb2\xa1"
        else:
            magic = b"\xa1\xb2\x3c\x4d"

        ver_major = int(pcap_global.get("version_major", 2))
        ver_minor = int(pcap_global.get("version_minor", 4))
        snaplen = int(pcap_global.get("snaplen", 65535))
        linktype = int(pcap_global.get("linktype", pcap_global.get("network", 1)))

        self._fp.write(magic)
        self._fp.write(struct.pack(f"{endianness}HHIIII", ver_major, ver_minor, 0, 0, snaplen, linktype))
        self._endianness = endianness
        self._ts_resolution = ts_resolution

    def emit(self, msg: Message) -> None:
        p = msg.meta.get("pcap") or {}
        ts_sec = int(p.get("ts_sec", int(time.time())))
        ts_sub = int(p.get("ts_sub", 0))
        incl_len = len(msg.data)
        orig_len = int(p.get("orig_len", incl_len))

        self._fp.write(struct.pack(f"{self._endianness}IIII", ts_sec, ts_sub, incl_len, orig_len))
        self._fp.write(msg.data)

    def close(self) -> None:
        self._fp.close()


def create_offline_sink(seed_type: str, *, artifacts_dir: Path, seeds: list[Message]) -> tuple[OfflineSink, str]:
    seed_type = seed_type.lower()
    if seed_type in ("hex", "inline_hex"):
        return HexSink(artifacts_dir / "mutated.hex"), "mutated.hex"
    if seed_type == "nmea":
        return TextSink(artifacts_dir / "mutated.nmea"), "mutated.nmea"
    if seed_type == "candump":
        iface = str(seeds[0].meta.get("iface", "vcan0")) if seeds else "vcan0"
        return CandumpSink(artifacts_dir / "mutated.candump.log", iface=iface), "mutated.candump.log"
    if seed_type in ("pcap", "pcapng"):
        if not seeds:
            raise ValueError("pcap offline sink requires at least one seed packet")
        gh = seeds[0].meta.get("pcap_global")
        if not isinstance(gh, dict):
            raise ValueError("pcap seeds missing pcap_global meta")
        return PcapSink(artifacts_dir / "mutated.pcap", gh), "mutated.pcap"

    # Fallback
    return HexSink(artifacts_dir / "mutated.hex"), "mutated.hex"
