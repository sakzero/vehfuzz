from __future__ import annotations

import time
from dataclasses import dataclass
from dataclasses import field
from typing import Literal


IsoTpFrameType = Literal["sf", "ff", "cf", "fc"]


@dataclass(frozen=True)
class IsoTpParsed:
    frame_type: IsoTpFrameType
    payload: bytes
    total_len: int | None = None
    seq: int | None = None
    fc_status: int | None = None
    block_size: int | None = None
    stmin: int | None = None


def parse_isotp_frame(data: bytes) -> IsoTpParsed:
    if len(data) < 1:
        raise ValueError("ISO-TP frame requires at least 1 byte")

    pci = data[0]
    ftype = (pci >> 4) & 0xF

    if ftype == 0x0:  # Single Frame
        # Classic: length in low nibble (0..7).
        # ISO-TP 2016 (CAN FD): if low nibble == 0, length is in next byte (1..255).
        length_n = pci & 0xF
        if length_n != 0:
            length = length_n
            if length > max(0, len(data) - 1):
                length = max(0, len(data) - 1)
            return IsoTpParsed(frame_type="sf", payload=data[1 : 1 + length], total_len=length)
        if len(data) < 2:
            raise ValueError("ISO-TP SF extended length requires 2 bytes")
        length = int(data[1])
        if length <= 0:
            raise ValueError("ISO-TP SF extended length must be > 0")
        available = max(0, len(data) - 2)
        length = min(length, available)
        return IsoTpParsed(frame_type="sf", payload=data[2 : 2 + length], total_len=length)

    if ftype == 0x1:  # First Frame
        if len(data) < 2:
            raise ValueError("ISO-TP FF requires 2 bytes")
        length12 = ((pci & 0xF) << 8) | data[1]
        if length12 != 0:
            total_len = int(length12)
            payload = data[2:]
            return IsoTpParsed(frame_type="ff", payload=payload, total_len=total_len)
        # Extended FF length (32-bit) when length12 == 0.
        if len(data) < 6:
            raise ValueError("ISO-TP FF extended length requires 6 bytes")
        total_len = int.from_bytes(data[2:6], "big")
        payload = data[6:]
        return IsoTpParsed(frame_type="ff", payload=payload, total_len=total_len)

    if ftype == 0x2:  # Consecutive Frame
        seq = pci & 0xF
        return IsoTpParsed(frame_type="cf", payload=data[1:], seq=seq)

    if ftype == 0x3:  # Flow Control
        fs = pci & 0xF
        bs = data[1] if len(data) > 1 else 0
        stmin = data[2] if len(data) > 2 else 0
        return IsoTpParsed(frame_type="fc", payload=b"", fc_status=fs, block_size=bs, stmin=stmin)

    raise ValueError(f"Unknown ISO-TP frame type nibble: {ftype}")


def _pad_to_len(data: bytes, *, frame_len: int, pad_byte: int | None) -> bytes:
    if pad_byte is None:
        return data
    frame_len = int(frame_len)
    if frame_len <= 0:
        return data
    if len(data) >= frame_len:
        return data[:frame_len]
    return data + bytes([pad_byte & 0xFF]) * (frame_len - len(data))


def build_sf(payload: bytes, *, frame_len: int = 8, pad_byte: int | None = 0x00) -> bytes:
    payload = bytes(payload)
    if len(payload) <= 7:
        frame = bytes([(0x0 << 4) | (len(payload) & 0xF)]) + payload
        return _pad_to_len(frame, frame_len=frame_len, pad_byte=pad_byte)

    # Extended SF length: PCI low nibble == 0, length byte follows.
    max_payload = max(0, int(frame_len) - 2)
    if len(payload) > 0xFF:
        raise ValueError("SF extended length supports up to 255 bytes in 1 byte length")
    if len(payload) > max_payload:
        raise ValueError("SF payload too long for frame_len")
    frame = bytes([0x00, len(payload) & 0xFF]) + payload
    return _pad_to_len(frame, frame_len=frame_len, pad_byte=pad_byte)


def build_ff(payload: bytes, *, total_len: int, frame_len: int = 8, pad_byte: int | None = 0x00) -> bytes:
    payload = bytes(payload)
    total_len = int(total_len)
    if total_len < 8:
        raise ValueError("FF total_len must be >= 8")
    if total_len <= 4095:
        max_first = max(0, int(frame_len) - 2)
        first = payload[:max_first]
        pci0 = (0x1 << 4) | ((total_len >> 8) & 0xF)
        pci1 = total_len & 0xFF
        frame = bytes([pci0, pci1]) + first
        return _pad_to_len(frame, frame_len=frame_len, pad_byte=pad_byte)

    # Extended FF length (32-bit)
    max_first = max(0, int(frame_len) - 6)
    first = payload[:max_first]
    frame = bytes([0x10, 0x00]) + int(total_len).to_bytes(4, "big") + first
    return _pad_to_len(frame, frame_len=frame_len, pad_byte=pad_byte)


def build_cf(seq: int, chunk: bytes, *, frame_len: int = 8, pad_byte: int | None = 0x00) -> bytes:
    seq = seq & 0xF
    max_chunk = max(0, int(frame_len) - 1)
    frame = bytes([(0x2 << 4) | seq]) + bytes(chunk)[:max_chunk]
    return _pad_to_len(frame, frame_len=frame_len, pad_byte=pad_byte)


def build_fc(
    *,
    status: int = 0x0,
    block_size: int = 0x0,
    stmin: int = 0x0,
    frame_len: int = 8,
    pad_byte: int | None = 0x00,
) -> bytes:
    frame = bytes([(0x3 << 4) | (status & 0xF), block_size & 0xFF, stmin & 0xFF])
    return _pad_to_len(frame, frame_len=frame_len, pad_byte=pad_byte)


def stmin_to_seconds(stmin: int) -> float:
    stmin &= 0xFF
    if stmin <= 0x7F:
        return stmin / 1000.0
    if 0xF1 <= stmin <= 0xF9:
        return (stmin - 0xF0) / 10000.0
    return 0.0


@dataclass
class IsoTpReassembly:
    total_len: int | None = None
    buf: bytearray = field(default_factory=bytearray)
    next_seq: int = 1
    last_activity: float = 0.0

    def reset(self) -> None:
        self.total_len = None
        self.buf = bytearray()
        self.next_seq = 1
        self.last_activity = 0.0


def reassemble_feed(state: IsoTpReassembly, frame_data: bytes) -> tuple[bytes | None, IsoTpParsed]:
    parsed = parse_isotp_frame(frame_data)
    state.last_activity = time.time()

    if parsed.frame_type == "sf":
        state.reset()
        return parsed.payload, parsed

    if parsed.frame_type == "ff":
        state.reset()
        state.total_len = int(parsed.total_len or 0)
        state.buf.extend(parsed.payload)
        state.next_seq = 1
        return None, parsed

    if parsed.frame_type == "cf":
        if state.total_len is None:
            return None, parsed
        if parsed.seq != (state.next_seq & 0xF):
            state.reset()
            return None, parsed
        state.next_seq = (state.next_seq + 1) & 0xF
        state.buf.extend(parsed.payload)
        if len(state.buf) >= state.total_len:
            out = bytes(state.buf[: state.total_len])
            state.reset()
            return out, parsed
        return None, parsed

    # Flow Control is handled by sender/receiver state machines.
    return None, parsed
