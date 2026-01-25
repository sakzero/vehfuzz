from __future__ import annotations

import time
from dataclasses import dataclass
from dataclasses import field
from typing import Literal


IsoTpFrameType = Literal["sf", "ff", "cf", "fc"]

# Safety limits to prevent memory exhaustion attacks
MAX_ISOTP_MESSAGE_LEN = 4 * 1024 * 1024  # 4 MB max reassembly size
DEFAULT_REASSEMBLY_TIMEOUT_S = 5.0  # 5 seconds default timeout


@dataclass(frozen=True)
class IsoTpParsed:
    frame_type: IsoTpFrameType
    payload: bytes
    total_len: int | None = None
    declared_len: int | None = None  # Original declared length (before truncation)
    seq: int | None = None
    fc_status: int | None = None
    block_size: int | None = None
    stmin: int | None = None
    truncated: bool = False  # True if payload was truncated due to length mismatch
    error: str | None = None  # Error description if any


def parse_isotp_frame(data: bytes, *, max_len: int = MAX_ISOTP_MESSAGE_LEN) -> IsoTpParsed:
    """
    Parse an ISO-TP frame.

    Args:
        data: Raw frame bytes
        max_len: Maximum allowed message length (for FF total_len validation)

    Returns:
        IsoTpParsed with frame information. Check `error` field for issues.
    """
    if len(data) < 1:
        raise ValueError("ISO-TP frame requires at least 1 byte")

    pci = data[0]
    ftype = (pci >> 4) & 0xF

    if ftype == 0x0:  # Single Frame
        # Classic: length in low nibble (0..7).
        # ISO-TP 2016 (CAN FD): if low nibble == 0, length is in next byte (1..255).
        length_n = pci & 0xF
        if length_n != 0:
            declared_len = length_n
            available = max(0, len(data) - 1)
            truncated = declared_len > available
            actual_len = min(declared_len, available)
            error = f"SF declared {declared_len} bytes but only {available} available" if truncated else None
            return IsoTpParsed(
                frame_type="sf",
                payload=data[1 : 1 + actual_len],
                total_len=actual_len,
                declared_len=declared_len,
                truncated=truncated,
                error=error,
            )
        if len(data) < 2:
            raise ValueError("ISO-TP SF extended length requires 2 bytes")
        declared_len = int(data[1])
        if declared_len <= 0:
            raise ValueError("ISO-TP SF extended length must be > 0")
        available = max(0, len(data) - 2)
        truncated = declared_len > available
        actual_len = min(declared_len, available)
        error = f"SF_EXT declared {declared_len} bytes but only {available} available" if truncated else None
        return IsoTpParsed(
            frame_type="sf",
            payload=data[2 : 2 + actual_len],
            total_len=actual_len,
            declared_len=declared_len,
            truncated=truncated,
            error=error,
        )

    if ftype == 0x1:  # First Frame
        if len(data) < 2:
            raise ValueError("ISO-TP FF requires 2 bytes")
        length12 = ((pci & 0xF) << 8) | data[1]
        if length12 != 0:
            total_len = int(length12)
            # Validate total_len
            error = None
            if total_len < 8:
                error = f"FF total_len {total_len} < 8 (minimum for multi-frame)"
            elif total_len > max_len:
                error = f"FF total_len {total_len} exceeds max_len {max_len}"
            payload = data[2:]
            return IsoTpParsed(
                frame_type="ff",
                payload=payload,
                total_len=total_len,
                declared_len=total_len,
                error=error,
            )
        # Extended FF length (32-bit) when length12 == 0.
        if len(data) < 6:
            raise ValueError("ISO-TP FF extended length requires 6 bytes")
        total_len = int.from_bytes(data[2:6], "big")
        error = None
        if total_len < 4096:
            error = f"FF_EXT total_len {total_len} < 4096 (should use standard FF)"
        elif total_len > max_len:
            error = f"FF_EXT total_len {total_len} exceeds max_len {max_len}"
        payload = data[6:]
        return IsoTpParsed(
            frame_type="ff",
            payload=payload,
            total_len=total_len,
            declared_len=total_len,
            error=error,
        )

    if ftype == 0x2:  # Consecutive Frame
        seq = pci & 0xF
        return IsoTpParsed(frame_type="cf", payload=data[1:], seq=seq)

    if ftype == 0x3:  # Flow Control
        fs = pci & 0xF
        bs = data[1] if len(data) > 1 else 0
        stmin = data[2] if len(data) > 2 else 0
        # Validate flow status
        error = None
        if fs not in (0x0, 0x1, 0x2):  # CTS, Wait, Overflow
            error = f"FC invalid status {fs} (expected 0=CTS, 1=Wait, 2=Overflow)"
        return IsoTpParsed(
            frame_type="fc",
            payload=b"",
            fc_status=fs,
            block_size=bs,
            stmin=stmin,
            error=error,
        )

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
    max_len: int = MAX_ISOTP_MESSAGE_LEN
    timeout_s: float = DEFAULT_REASSEMBLY_TIMEOUT_S

    def reset(self) -> None:
        self.total_len = None
        self.buf = bytearray()
        self.next_seq = 1
        self.last_activity = 0.0

    def is_expired(self, now: float | None = None) -> bool:
        """Check if reassembly has timed out."""
        if self.total_len is None:
            return False
        if now is None:
            now = time.time()
        return (now - self.last_activity) > self.timeout_s


@dataclass(frozen=True)
class ReassemblyResult:
    """Result of reassembly operation."""
    complete: bytes | None  # Complete message if reassembly finished
    parsed: IsoTpParsed  # Parsed frame info
    error: str | None = None  # Error if any (timeout, sequence error, etc.)


def reassemble_feed(
    state: IsoTpReassembly,
    frame_data: bytes,
    *,
    now: float | None = None,
) -> tuple[bytes | None, IsoTpParsed]:
    """
    Feed a frame into the reassembly state machine.

    Args:
        state: Reassembly state
        frame_data: Raw frame bytes
        now: Current time (for testing), defaults to time.time()

    Returns:
        Tuple of (complete_message_or_none, parsed_frame)
    """
    if now is None:
        now = time.time()

    # Check for timeout on existing reassembly
    if state.is_expired(now):
        state.reset()

    parsed = parse_isotp_frame(frame_data, max_len=state.max_len)
    state.last_activity = now

    if parsed.frame_type == "sf":
        state.reset()
        return parsed.payload, parsed

    if parsed.frame_type == "ff":
        state.reset()
        total_len = int(parsed.total_len or 0)
        # Reject if exceeds max_len
        if total_len > state.max_len:
            return None, IsoTpParsed(
                frame_type="ff",
                payload=parsed.payload,
                total_len=total_len,
                declared_len=total_len,
                error=f"FF total_len {total_len} exceeds max_len {state.max_len}, rejecting",
            )
        state.total_len = total_len
        state.buf.extend(parsed.payload)
        state.next_seq = 1
        return None, parsed

    if parsed.frame_type == "cf":
        if state.total_len is None:
            # CF without FF - ignore but report
            return None, IsoTpParsed(
                frame_type="cf",
                payload=parsed.payload,
                seq=parsed.seq,
                error="CF received without prior FF",
            )
        if parsed.seq != (state.next_seq & 0xF):
            expected = state.next_seq & 0xF
            state.reset()
            return None, IsoTpParsed(
                frame_type="cf",
                payload=parsed.payload,
                seq=parsed.seq,
                error=f"CF sequence error: expected {expected}, got {parsed.seq}",
            )
        state.next_seq = (state.next_seq + 1) & 0xF
        state.buf.extend(parsed.payload)
        if len(state.buf) >= state.total_len:
            out = bytes(state.buf[: state.total_len])
            state.reset()
            return out, parsed
        return None, parsed

    # Flow Control is handled by sender/receiver state machines.
    return None, parsed
