from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.plugins import Message, Protocol, register_protocol


# Safety limits for TP state management
MAX_TP_STATES = 256
DEFAULT_TP_TIMEOUT_S = 5.0
MAX_TP_MESSAGE_LEN = 1785  # J1939 max: 255 packets * 7 bytes


# TP.CM Control byte values
TP_CM_RTS = 0x10  # Request To Send
TP_CM_CTS = 0x11  # Clear To Send
TP_CM_EOM_ACK = 0x13  # End of Message Acknowledgment
TP_CM_BAM = 0x20  # Broadcast Announce Message
TP_CM_ABORT = 0xFF  # Connection Abort

TP_CM_CONTROL_NAMES: dict[int, str] = {
    TP_CM_RTS: "RTS",
    TP_CM_CTS: "CTS",
    TP_CM_EOM_ACK: "EOM_ACK",
    TP_CM_BAM: "BAM",
    TP_CM_ABORT: "ABORT",
}


@dataclass(frozen=True)
class J1939Id:
    priority: int
    reserved: int
    data_page: int
    pdu_format: int
    pdu_specific: int
    source_address: int

    @property
    def pgn(self) -> int:
        if self.pdu_format < 240:
            return ((self.data_page & 0x1) << 16) | ((self.pdu_format & 0xFF) << 8)
        return ((self.data_page & 0x1) << 16) | ((self.pdu_format & 0xFF) << 8) | (self.pdu_specific & 0xFF)

    @property
    def destination_address(self) -> int | None:
        if self.pdu_format < 240:
            return self.pdu_specific & 0xFF
        return None

    def to_can_id(self) -> int:
        return (
            ((self.priority & 0x7) << 26)
            | ((self.reserved & 0x1) << 25)
            | ((self.data_page & 0x1) << 24)
            | ((self.pdu_format & 0xFF) << 16)
            | ((self.pdu_specific & 0xFF) << 8)
            | (self.source_address & 0xFF)
        )


def parse_j1939_id(can_id: int) -> J1939Id:
    can_id &= 0x1FFFFFFF
    return J1939Id(
        priority=(can_id >> 26) & 0x7,
        reserved=(can_id >> 25) & 0x1,
        data_page=(can_id >> 24) & 0x1,
        pdu_format=(can_id >> 16) & 0xFF,
        pdu_specific=(can_id >> 8) & 0xFF,
        source_address=can_id & 0xFF,
    )


@dataclass
class _TpReassembly:
    pgn: int
    total_len: int
    total_packets: int
    destination_address: int | None
    next_seq: int = 1
    buf: bytearray = field(default_factory=bytearray)
    last_activity: float = 0.0

    def is_expired(self, now: float, timeout_s: float) -> bool:
        """Check if reassembly has timed out."""
        return (now - self.last_activity) > timeout_s


class _J1939Protocol(Protocol):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        # Keyed by (source_address, destination_address, target_pgn)
        self._tp_states: dict[tuple[int, int | None, int], _TpReassembly] = {}
        self._last_cleanup: float = 0.0
        self._cleanup_interval: float = float(config.get("cleanup_interval_s", 10.0))
        self._tp_timeout: float = float(config.get("tp_timeout_s", DEFAULT_TP_TIMEOUT_S))
        self._max_tp_len: int = int(config.get("max_tp_len", MAX_TP_MESSAGE_LEN))

    def _cleanup_expired_states(self, now: float) -> None:
        """Remove expired TP reassembly states."""
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now

        expired_keys = [
            k for k, v in self._tp_states.items()
            if v.is_expired(now, self._tp_timeout)
        ]
        for k in expired_keys:
            del self._tp_states[k]

        # Also limit total number of states (LRU-like: remove oldest)
        if len(self._tp_states) > MAX_TP_STATES:
            sorted_keys = sorted(
                self._tp_states.keys(),
                key=lambda k: self._tp_states[k].last_activity,
            )
            for k in sorted_keys[: len(self._tp_states) - MAX_TP_STATES]:
                del self._tp_states[k]

    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        cfg = self._cfg
        meta_in = dict(seed.meta)
        jmeta = meta_in.get("j1939") if isinstance(meta_in.get("j1939"), dict) else {}

        priority = int(jmeta.get("priority", cfg.get("priority", 6))) & 0x7
        reserved = int(jmeta.get("reserved", cfg.get("reserved", 0))) & 0x1

        # Prefer explicit PGN from seed/meta/config.
        pgn = jmeta.get("pgn", cfg.get("pgn"))
        if pgn is not None:
            pgn_i = int(pgn) & 0x3FFFF
            data_page = (pgn_i >> 16) & 0x1
            pf = (pgn_i >> 8) & 0xFF
            if pf < 240:
                ps = int(jmeta.get("destination_address", cfg.get("destination_address", 0xFF))) & 0xFF
            else:
                ps = pgn_i & 0xFF
        else:
            data_page = int(jmeta.get("data_page", cfg.get("data_page", 0))) & 0x1
            pf = int(jmeta.get("pdu_format", cfg.get("pdu_format", 0xEF))) & 0xFF
            ps = int(jmeta.get("pdu_specific", cfg.get("pdu_specific", cfg.get("destination_address", 0xFF)))) & 0xFF

        sa = int(jmeta.get("source_address", cfg.get("source_address", 0xFE))) & 0xFF

        j = J1939Id(
            priority=priority,
            reserved=reserved,
            data_page=data_page,
            pdu_format=pf,
            pdu_specific=ps,
            source_address=sa,
        )

        max_len = int(cfg.get("max_len", 8))
        if max_len <= 0:
            max_len = 8
        data = mutated[:max_len]

        pad_to = cfg.get("pad_to_len")
        if pad_to is not None:
            pad_to = int(pad_to)
            if pad_to > len(data):
                pad_byte = int(cfg.get("pad_byte", 0xFF)) & 0xFF
                data = data + bytes([pad_byte]) * (pad_to - len(data))

        can_id = j.to_can_id()
        out_meta = meta_in
        out_meta.update(
            {
                "can_id": can_id,
                "is_extended": True,
                "is_fd": bool(out_meta.get("is_fd", cfg.get("is_fd", False))),
                "j1939": {
                    "priority": j.priority,
                    "reserved": j.reserved,
                    "data_page": j.data_page,
                    "pdu_format": j.pdu_format,
                    "pdu_specific": j.pdu_specific,
                    "source_address": j.source_address,
                    "pgn": j.pgn,
                    "destination_address": j.destination_address,
                },
            }
        )
        return Message(data=data, meta=out_meta)

    def parse(self, msg: Message) -> ParsedMessage:
        now = time.time()
        self._cleanup_expired_states(now)

        can_id = msg.meta.get("can_id")
        try:
            can_id_i = int(can_id) if can_id is not None else None
        except (TypeError, ValueError):
            can_id_i = None
        if can_id_i is None:
            return ParsedMessage(protocol="j1939", level="raw", ok=False, reason="missing_can_id", fields={"len": len(msg.data)})
        j = parse_j1939_id(can_id_i)

        data = bytes(msg.data)
        tp_error: str | None = None

        # J1939 Transport Protocol (TP):
        # - TP.CM: PGN 0x00EC00
        # - TP.DT: PGN 0x00EB00
        if j.pgn == 0x00EC00 and len(data) >= 8:
            control = int(data[0])
            total_len = int.from_bytes(data[1:3], "little")
            total_packets = int(data[3])
            max_packets = int(data[4])
            target_pgn = int.from_bytes(data[5:8], "little") & 0x3FFFF
            da = j.destination_address

            control_name = TP_CM_CONTROL_NAMES.get(control, f"unknown_0x{control:02X}")

            # BAM(0x20) and RTS(0x10) initiate transfer.
            if control in (TP_CM_BAM, TP_CM_RTS):
                if total_len > 0 and total_packets > 0:
                    # Validate total_len
                    if total_len > self._max_tp_len:
                        tp_error = f"TP total_len {total_len} exceeds max {self._max_tp_len}"
                    else:
                        key = (j.source_address, da, target_pgn)
                        self._tp_states[key] = _TpReassembly(
                            pgn=target_pgn,
                            total_len=total_len,
                            total_packets=total_packets,
                            destination_address=da,
                            last_activity=now,
                        )
                else:
                    tp_error = f"TP invalid: total_len={total_len}, total_packets={total_packets}"

            # CTS(0x11) - Clear To Send response
            elif control == TP_CM_CTS:
                # CTS contains: num_packets_to_send, next_packet_number, reserved, target_pgn
                pass  # State machine would handle this

            # Abort(0xFF) - Connection abort
            elif control == TP_CM_ABORT:
                key = (j.source_address, da, target_pgn)
                if key in self._tp_states:
                    del self._tp_states[key]
                    tp_error = "TP connection aborted"

            return ParsedMessage(
                protocol="j1939",
                level="app",
                ok=True,
                flow_key=f"j1939:tp_cm:pgn=0x{target_pgn:x}",
                fields={
                    "can_id": can_id_i,
                    "pgn": j.pgn,
                    "priority": j.priority,
                    "source_address": j.source_address,
                    "destination_address": da,
                    "tp": {
                        "type": "cm",
                        "control": control,
                        "control_name": control_name,
                        "total_len": total_len,
                        "total_packets": total_packets,
                        "max_packets": max_packets,
                        "target_pgn": target_pgn,
                    },
                    "tp_error": tp_error,
                    "len": len(data),
                },
                payload=ByteRange(0, len(data)),
            )

        if j.pgn == 0x00EB00 and len(data) >= 2:
            seq = int(data[0])
            chunk = data[1:8]
            da = j.destination_address

            # Find matching transfer for this SA/DA.
            candidates = [k for k in self._tp_states.keys() if k[0] == j.source_address and k[1] == da]
            if candidates:
                key = candidates[0]
                st = self._tp_states[key]
                st.last_activity = now

                if seq != st.next_seq:
                    tp_error = f"TP sequence error: expected {st.next_seq}, got {seq}"
                    del self._tp_states[key]
                else:
                    st.next_seq += 1
                    st.buf.extend(chunk)
                    if len(st.buf) >= st.total_len or seq >= st.total_packets:
                        payload = bytes(st.buf[: st.total_len])
                        del self._tp_states[key]
                        return ParsedMessage(
                            protocol="j1939",
                            level="app",
                            ok=True,
                            flow_key=f"j1939:tp:pgn=0x{st.pgn:x}",
                            fields={
                                "can_id": can_id_i,
                                "pgn": j.pgn,
                                "priority": j.priority,
                                "source_address": j.source_address,
                                "destination_address": da,
                                "tp": {
                                    "type": "dt",
                                    "seq": seq,
                                    "reassembly_complete": True,
                                    "target_pgn": st.pgn,
                                    "total_len": st.total_len,
                                    "total_packets": st.total_packets,
                                },
                                "tp_payload_hex": payload.hex(),
                                "tp_error": tp_error,
                                "len": len(data),
                            },
                            payload=ByteRange(0, len(data)),
                        )
            else:
                tp_error = "TP.DT received without prior TP.CM"

            return ParsedMessage(
                protocol="j1939",
                level="app",
                ok=True,
                flow_key="j1939:tp_dt",
                fields={
                    "can_id": can_id_i,
                    "pgn": j.pgn,
                    "priority": j.priority,
                    "source_address": j.source_address,
                    "destination_address": da,
                    "tp": {"type": "dt", "seq": seq},
                    "tp_error": tp_error,
                    "len": len(data),
                },
                payload=ByteRange(0, len(data)),
            )

        return ParsedMessage(
            protocol="j1939",
            level="l2",
            ok=True,
            flow_key=f"j1939:pgn=0x{j.pgn:x}",
            fields={
                "can_id": can_id_i,
                "pgn": j.pgn,
                "priority": j.priority,
                "source_address": j.source_address,
                "destination_address": j.destination_address,
                "pdu_format": j.pdu_format,
                "pdu_specific": j.pdu_specific,
                "len": len(msg.data),
            },
            payload=ByteRange(0, len(msg.data)),
        )


@register_protocol("j1939")
def j1939_protocol(config: dict[str, Any]) -> Protocol:
    return _J1939Protocol(config)
