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
        length = pci & 0xF
        if length > 7:
            raise ValueError("Invalid ISO-TP SF length")
        return IsoTpParsed(frame_type="sf", payload=data[1 : 1 + length], total_len=length)

    if ftype == 0x1:  # First Frame
        length = ((pci & 0xF) << 8) | data[1]
        return IsoTpParsed(frame_type="ff", payload=data[2:8], total_len=length)

    if ftype == 0x2:  # Consecutive Frame
        seq = pci & 0xF
        return IsoTpParsed(frame_type="cf", payload=data[1:8], seq=seq)

    if ftype == 0x3:  # Flow Control
        fs = pci & 0xF
        bs = data[1] if len(data) > 1 else 0
        stmin = data[2] if len(data) > 2 else 0
        return IsoTpParsed(frame_type="fc", payload=b"", fc_status=fs, block_size=bs, stmin=stmin)

    raise ValueError(f"Unknown ISO-TP frame type nibble: {ftype}")


def _pad_to_8(data: bytes, pad_byte: int | None) -> bytes:
    if pad_byte is None:
        return data
    if len(data) >= 8:
        return data[:8]
    return data + bytes([pad_byte & 0xFF]) * (8 - len(data))


def build_sf(payload: bytes, *, pad_byte: int | None = 0x00) -> bytes:
    if len(payload) > 7:
        raise ValueError("SF payload too long")
    frame = bytes([(0x0 << 4) | (len(payload) & 0xF)]) + payload
    return _pad_to_8(frame, pad_byte)


def build_ff(payload: bytes, *, total_len: int, pad_byte: int | None = 0x00) -> bytes:
    if total_len < 8 or total_len > 4095:
        raise ValueError("FF total_len must be in [8, 4095]")
    first = payload[:6]
    pci0 = (0x1 << 4) | ((total_len >> 8) & 0xF)
    pci1 = total_len & 0xFF
    frame = bytes([pci0, pci1]) + first
    return _pad_to_8(frame, pad_byte)


def build_cf(seq: int, chunk: bytes, *, pad_byte: int | None = 0x00) -> bytes:
    seq = seq & 0xF
    frame = bytes([(0x2 << 4) | seq]) + chunk[:7]
    return _pad_to_8(frame, pad_byte)


def build_fc(
    *,
    status: int = 0x0,
    block_size: int = 0x0,
    stmin: int = 0x0,
    pad_byte: int | None = 0x00,
) -> bytes:
    frame = bytes([(0x3 << 4) | (status & 0xF), block_size & 0xFF, stmin & 0xFF])
    return _pad_to_8(frame, pad_byte)


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
