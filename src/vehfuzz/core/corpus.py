from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from vehfuzz.core.config import resolve_path
from vehfuzz.core.plugins import Message


@dataclass(frozen=True)
class PcapGlobalHeader:
    endianness: str  # "<" little, ">" big
    ts_resolution: str  # "us" | "ns"
    version_major: int
    version_minor: int
    snaplen: int
    network: int


def _iter_non_empty_lines(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            yield line


def load_seed_messages(config_dir: Path, seed_cfg: dict[str, Any]) -> list[Message]:
    seed_type = str(seed_cfg.get("type", "hex")).lower()
    path = resolve_path(config_dir, seed_cfg.get("path"))

    if seed_type == "inline_hex":
        values = seed_cfg.get("values")
        if not isinstance(values, list) or not values:
            raise ValueError("seed.inline_hex requires seed.values list")
        seeds: list[Message] = []
        for idx, item in enumerate(values):
            if not isinstance(item, str):
                raise ValueError("seed.values must be strings")
            seeds.append(Message(data=_parse_hex_line(item), meta={"seed_index": idx}))
        return seeds

    if path is None:
        raise ValueError("seed.path is required")

    if seed_type == "hex":
        return _load_hex_lines(path)
    if seed_type == "nmea":
        return _load_nmea_lines(path)
    if seed_type == "candump":
        return _load_candump(path)
    if seed_type in ("canalyzat0r_export", "canalyzat0r"):
        return _load_canalyzat0r_export(path)
    if seed_type == "pcap":
        return _load_pcap_any(path)
    if seed_type == "pcapng":
        return _load_pcapng(path)

    raise ValueError(f"Unsupported seed.type: {seed_type}")


def _parse_hex_line(line: str) -> bytes:
    # Allow "aa bb cc" or "aabbcc" or "0x.." tokens.
    cleaned = (
        line.replace("0x", "")
        .replace("0X", "")
        .replace(" ", "")
        .replace("\t", "")
        .replace(":", "")
        .replace("-", "")
    )
    if len(cleaned) % 2 != 0:
        raise ValueError(f"Invalid hex line length: {line!r}")
    return bytes.fromhex(cleaned)


def _load_hex_lines(path: Path) -> list[Message]:
    seeds: list[Message] = []
    for idx, line in enumerate(_iter_non_empty_lines(path)):
        seeds.append(Message(data=_parse_hex_line(line), meta={"seed_index": idx, "source": str(path)}))
    if not seeds:
        raise ValueError(f"No seeds found in hex file: {path}")
    return seeds


def _load_nmea_lines(path: Path) -> list[Message]:
    seeds: list[Message] = []
    for idx, line in enumerate(_iter_non_empty_lines(path)):
        if not line.startswith("$"):
            # Still allow arbitrary lines.
            pass
        seeds.append(
            Message(
                data=(line.rstrip("\r\n") + "\r\n").encode("ascii", errors="replace"),
                meta={"seed_index": idx, "source": str(path)},
            )
        )
    if not seeds:
        raise ValueError(f"No seeds found in NMEA file: {path}")
    return seeds


_CANDUMP_RE = re.compile(r"\((?P<ts>[0-9]+\.[0-9]+)\)\s+(?P<iface>\S+)\s+(?P<iddata>\S+)")


def _load_candump(path: Path) -> list[Message]:
    seeds: list[Message] = []

    for idx, line in enumerate(_iter_non_empty_lines(path)):
        can_id: int | None = None
        data: bytes | None = None
        is_fd = False

        m = _CANDUMP_RE.search(line)
        if m:
            iface = m.group("iface")
            iddata = m.group("iddata")
            if "##" in iddata:
                is_fd = True
                can_id_hex, data_hex = iddata.split("##", 1)
            elif "#" in iddata:
                can_id_hex, data_hex = iddata.split("#", 1)
            else:
                can_id_hex, data_hex = iddata, ""

            can_id = int(can_id_hex, 16)
            data = bytes.fromhex(data_hex) if data_hex else b""
            seeds.append(
                Message(
                    data=data,
                    meta={
                        "seed_index": idx,
                        "source": str(path),
                        "iface": iface,
                        "can_id": can_id,
                        "is_fd": is_fd,
                        "is_extended": can_id > 0x7FF,
                    },
                )
            )
            continue

        # candump -L / other text formats: "can0 123 [8] 11 22 .."
        tokens = line.split()
        if len(tokens) >= 3 and tokens[1].lower() != "rx" and tokens[1].lower() != "tx":
            iface = tokens[0]
            try:
                can_id = int(tokens[1], 16)
            except ValueError:
                can_id = None
            if can_id is not None:
                # Find [dlc] token.
                data_tokens = [t for t in tokens[2:] if not t.startswith("[") and not t.endswith("]")]
                hex_bytes: list[str] = []
                for t in data_tokens:
                    if re.fullmatch(r"[0-9a-fA-F]{2}", t):
                        hex_bytes.append(t)
                data = bytes.fromhex("".join(hex_bytes)) if hex_bytes else b""
                seeds.append(
                    Message(
                        data=data,
                        meta={
                            "seed_index": idx,
                            "source": str(path),
                            "iface": iface,
                            "can_id": can_id,
                            "is_fd": False,
                            "is_extended": can_id > 0x7FF,
                        },
                    )
                )
                continue

        raise ValueError(f"Unrecognized candump line: {line!r}")

    if not seeds:
        raise ValueError(f"No seeds found in candump file: {path}")
    return seeds


_CANALYZAT0R_SECTION_MARKER = "\n=============\n"
_CANALYZAT0R_ELEMENT_MARKER = "\n-------------\n"


def _load_canalyzat0r_export(path: Path) -> list[Message]:
    """
    Parse CANalyzat0r "project export" text file and extract Packets as CAN frame seeds.

    The format is documented implicitly in CANalyzat0r `Strings.py`:
      - section marker: "\\n=============\\n"
      - element marker: "\\n-------------\\n"
      - sections: Project / PacketSets / Packets / KnownPackets
    """

    raw = path.read_text(encoding="utf-8", errors="replace")
    text = raw.replace("\r\n", "\n")

    # Parse section by lines to avoid delimiter edge-cases.
    lines = text.split("\n")
    start: int | None = None
    for i, line in enumerate(lines):
        if line.strip() == "Packets:":
            start = i + 1
            break
    if start is None:
        raise ValueError(f"CANalyzat0r export missing 'Packets:' section: {path}")

    # Read until next section marker line.
    end = len(lines)
    for j in range(start, len(lines)):
        if lines[j].strip() == "=============":
            end = j
            break

    body_lines = lines[start:end]

    # Elements are separated by a line containing "-------------".
    blobs: list[str] = []
    buf: list[str] = []
    for line in body_lines:
        if line.strip() == "-------------":
            blob = "\n".join(buf).strip()
            if blob:
                blobs.append(blob)
            buf = []
            continue
        buf.append(line)
    last = "\n".join(buf).strip()
    if last:
        blobs.append(last)

    seeds: list[Message] = []
    for idx, blob in enumerate(blobs):
        try:
            packet = json.loads(blob)
        except Exception as e:
            raise ValueError(f"Invalid CANalyzat0r packet JSON at index {idx} in {path}") from e

        if not isinstance(packet, dict):
            continue

        can_id_str = str(packet.get("CANID", "")).strip()
        data_hex = str(packet.get("data", "")).strip()
        iface = str(packet.get("iface", "")).strip()
        ts = str(packet.get("timestamp", "")).strip()

        # Best-effort normalization.
        if can_id_str.lower().startswith("0x"):
            can_id_str = can_id_str[2:]
        if data_hex.lower().startswith("0x"):
            data_hex = data_hex[2:]

        try:
            can_id = int(can_id_str, 16)
        except Exception as e:
            raise ValueError(f"Invalid CANID in CANalyzat0r packet at index {idx}: {can_id_str!r}") from e

        try:
            data = bytes.fromhex(data_hex) if data_hex else b""
        except Exception as e:
            raise ValueError(f"Invalid data hex in CANalyzat0r packet at index {idx}: {data_hex!r}") from e

        is_extended = can_id > 0x7FF
        is_fd = len(data) > 8
        seeds.append(
            Message(
                data=data,
                meta={
                    "seed_index": len(seeds),
                    "source": str(path),
                    "iface": iface,
                    "timestamp": ts,
                    "can_id": can_id,
                    "is_extended": is_extended,
                    "is_fd": is_fd,
                },
            )
        )

    if not seeds:
        raise ValueError(f"No packet seeds found in CANalyzat0r export: {path}")
    return seeds


def _parse_pcap_global_header(data: bytes) -> PcapGlobalHeader:
    if len(data) < 24:
        raise ValueError("pcap file too small")

    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endianness, ts_res = "<", "us"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endianness, ts_res = ">", "us"
    elif magic == b"\x4d\x3c\xb2\xa1":
        endianness, ts_res = "<", "ns"
    elif magic == b"\xa1\xb2\x3c\x4d":
        endianness, ts_res = ">", "ns"
    else:
        raise ValueError("Unsupported pcap magic")

    _, ver_major, ver_minor, _thiszone, _sigfigs, snaplen, network = struct.unpack(
        f"{endianness}IHHIIII", data[:24]
    )
    return PcapGlobalHeader(
        endianness=endianness,
        ts_resolution=ts_res,
        version_major=ver_major,
        version_minor=ver_minor,
        snaplen=snaplen,
        network=network,
    )


def _load_pcap(path: Path) -> list[Message]:
    seeds: list[Message] = []
    data = path.read_bytes()
    gh = _parse_pcap_global_header(data[:24])

    offset = 24
    pkt_index = 0
    while offset + 16 <= len(data):
        ts_sec, ts_sub, incl_len, orig_len = struct.unpack(
            f"{gh.endianness}IIII", data[offset : offset + 16]
        )
        offset += 16
        if offset + incl_len > len(data):
            break
        pkt = data[offset : offset + incl_len]
        offset += incl_len

        seeds.append(
            Message(
                data=pkt,
                meta={
                    "seed_index": pkt_index,
                    "source": str(path),
                    "pcap_global": {
                        "endianness": gh.endianness,
                        "ts_resolution": gh.ts_resolution,
                        "version_major": gh.version_major,
                        "version_minor": gh.version_minor,
                        "snaplen": gh.snaplen,
                        "linktype": gh.network,
                    },
                    "pcap": {
                        "ts_sec": ts_sec,
                        "ts_sub": ts_sub,
                        "ts_resolution": gh.ts_resolution,
                        "incl_len": incl_len,
                        "orig_len": orig_len,
                        "linktype": gh.network,
                    },
                },
            )
        )
        pkt_index += 1

    if not seeds:
        raise ValueError(f"No packets found in pcap file: {path}")
    return seeds


def _load_pcap_any(path: Path) -> list[Message]:
    data = path.read_bytes()
    # pcapng Section Header Block starts with 0x0A0D0D0A
    if len(data) >= 4 and data[:4] == b"\x0a\x0d\x0d\x0a":
        return _load_pcapng_from_bytes(path=path, data=data)
    return _load_pcap_from_bytes(path=path, data=data)


def _load_pcap_from_bytes(*, path: Path, data: bytes) -> list[Message]:
    seeds: list[Message] = []
    gh = _parse_pcap_global_header(data[:24])

    offset = 24
    pkt_index = 0
    while offset + 16 <= len(data):
        ts_sec, ts_sub, incl_len, orig_len = struct.unpack(
            f"{gh.endianness}IIII", data[offset : offset + 16]
        )
        offset += 16
        if offset + incl_len > len(data):
            break
        pkt = data[offset : offset + incl_len]
        offset += incl_len

        seeds.append(
            Message(
                data=pkt,
                meta={
                    "seed_index": pkt_index,
                    "source": str(path),
                    "pcap_global": {
                        "endianness": gh.endianness,
                        "ts_resolution": gh.ts_resolution,
                        "version_major": gh.version_major,
                        "version_minor": gh.version_minor,
                        "snaplen": gh.snaplen,
                        "linktype": gh.network,
                    },
                    "pcap": {
                        "ts_sec": ts_sec,
                        "ts_sub": ts_sub,
                        "ts_resolution": gh.ts_resolution,
                        "incl_len": incl_len,
                        "orig_len": orig_len,
                        "linktype": gh.network,
                    },
                },
            )
        )
        pkt_index += 1

    if not seeds:
        raise ValueError(f"No packets found in pcap file: {path}")
    return seeds
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_SPB = 0x00000003
_PCAPNG_EPB = 0x00000006


def _load_pcapng(path: Path) -> list[Message]:
    return _load_pcapng_from_bytes(path=path, data=path.read_bytes())


def _load_pcapng_from_bytes(*, path: Path, data: bytes) -> list[Message]:
    if len(data) < 12:
        raise ValueError("pcapng file too small")
    if struct.unpack_from("<I", data, 0)[0] != _PCAPNG_SHB:
        raise ValueError("pcapng missing Section Header Block")

    # Determine byte order from SHB Byte-Order Magic field (offset 8).
    bom = data[8:12]
    if bom == b"\x4d\x3c\x2b\x1a":
        endianness = "<"
    elif bom == b"\x1a\x2b\x3c\x4d":
        endianness = ">"
    else:
        raise ValueError("pcapng unsupported byte-order magic")

    def u32(off: int) -> int:
        return struct.unpack_from(f"{endianness}I", data, off)[0]

    def u16(off: int) -> int:
        return struct.unpack_from(f"{endianness}H", data, off)[0]

    def _read_block(off: int) -> tuple[int, int, bytes, int]:
        if off + 12 > len(data):
            raise ValueError("pcapng truncated block header")
        btype = u32(off)
        blen = u32(off + 4)
        if blen < 12 or blen % 4 != 0:
            raise ValueError(f"pcapng invalid block length: {blen}")
        end_off = off + blen
        if end_off > len(data):
            raise ValueError("pcapng truncated block")
        blen2 = u32(end_off - 4)
        if blen2 != blen:
            raise ValueError("pcapng block length mismatch")
        body = data[off + 8 : end_off - 4]
        return btype, blen, body, end_off

    def _parse_options(opt_data: bytes) -> dict[int, bytes]:
        opts: dict[int, bytes] = {}
        o = 0
        while o + 4 <= len(opt_data):
            code = struct.unpack_from(f"{endianness}H", opt_data, o)[0]
            length = struct.unpack_from(f"{endianness}H", opt_data, o + 2)[0]
            o += 4
            if code == 0 and length == 0:
                break
            val = opt_data[o : o + length]
            o += length
            # 32-bit padding
            o = (o + 3) & ~3
            opts[int(code)] = bytes(val)
        return opts

    # Track interface_id -> (linktype, snaplen, ts_resolution)
    interfaces: dict[int, tuple[int, int, str]] = {}

    seeds: list[Message] = []
    pkt_index = 0
    off = 0
    while off < len(data):
        btype, _blen, body, next_off = _read_block(off)
        off = next_off

        if btype == _PCAPNG_SHB:
            interfaces = {}
            continue

        if btype == _PCAPNG_IDB:
            if len(body) < 8:
                continue
            linktype = int(struct.unpack_from(f"{endianness}H", body, 0)[0])
            snaplen = int(struct.unpack_from(f"{endianness}I", body, 4)[0])
            opts = _parse_options(body[8:])
            ts_res = "us"
            if 9 in opts and opts[9]:
                v = opts[9][0]
                if (v & 0x80) == 0:
                    # base-10 resolution, exponent is v
                    exp = int(v & 0x7F)
                    if exp == 9:
                        ts_res = "ns"
                    elif exp == 6:
                        ts_res = "us"
            iface_id = len(interfaces)
            interfaces[iface_id] = (linktype, snaplen, ts_res)
            continue

        if btype == _PCAPNG_EPB:
            if len(body) < 20:
                continue
            iface_id = int(struct.unpack_from(f"{endianness}I", body, 0)[0])
            ts_high = int(struct.unpack_from(f"{endianness}I", body, 4)[0])
            ts_low = int(struct.unpack_from(f"{endianness}I", body, 8)[0])
            cap_len = int(struct.unpack_from(f"{endianness}I", body, 12)[0])
            pkt_len = int(struct.unpack_from(f"{endianness}I", body, 16)[0])
            pkt_off = 20
            pkt_data = body[pkt_off : pkt_off + cap_len]
            if iface_id not in interfaces:
                # Fallback if IDB missing.
                linktype, snaplen, ts_res = 1, 65535, "us"
            else:
                linktype, snaplen, ts_res = interfaces[iface_id]

            ts64 = (ts_high << 32) | ts_low
            scale = 1_000_000_000 if ts_res == "ns" else 1_000_000
            ts_sec = int(ts64 // scale)
            ts_sub = int(ts64 % scale)

            seeds.append(
                Message(
                    data=bytes(pkt_data),
                    meta={
                        "seed_index": pkt_index,
                        "source": str(path),
                        "pcap_global": {
                            "endianness": "<",
                            "ts_resolution": ts_res,
                            "version_major": 2,
                            "version_minor": 4,
                            "snaplen": snaplen,
                            "linktype": linktype,
                        },
                        "pcap": {
                            "ts_sec": ts_sec,
                            "ts_sub": ts_sub,
                            "ts_resolution": ts_res,
                            "incl_len": cap_len,
                            "orig_len": pkt_len,
                            "linktype": linktype,
                            "pcapng": {"interface_id": iface_id},
                        },
                    },
                )
            )
            pkt_index += 1
            continue

        if btype == _PCAPNG_SPB:
            # Simple Packet Block: 4 bytes packet_len then packet_data.
            if len(body) < 4:
                continue
            pkt_len = int(struct.unpack_from(f"{endianness}I", body, 0)[0])
            pkt_data = body[4 : 4 + pkt_len]
            if interfaces:
                linktype, snaplen, ts_res = interfaces[min(interfaces.keys())]
            else:
                linktype, snaplen, ts_res = 1, 65535, "us"
            seeds.append(
                Message(
                    data=bytes(pkt_data),
                    meta={
                        "seed_index": pkt_index,
                        "source": str(path),
                        "pcap_global": {
                            "endianness": "<",
                            "ts_resolution": ts_res,
                            "version_major": 2,
                            "version_minor": 4,
                            "snaplen": snaplen,
                            "linktype": linktype,
                        },
                        "pcap": {
                            "ts_sec": 0,
                            "ts_sub": 0,
                            "ts_resolution": ts_res,
                            "incl_len": len(pkt_data),
                            "orig_len": pkt_len,
                            "linktype": linktype,
                            "pcapng": {"simple": True},
                        },
                    },
                )
            )
            pkt_index += 1
            continue

    if not seeds:
        raise ValueError(f"No packets found in pcapng file: {path}")
    return seeds
