from __future__ import annotations

import time
from typing import Any

from vehfuzz.core.isotp import (
    IsoTpReassembly,
    build_cf,
    build_fc,
    build_ff,
    build_sf,
    parse_isotp_frame,
    reassemble_feed,
    stmin_to_seconds,
)
from vehfuzz.core.plugins import Adapter, Message, register_adapter


class _IsoTpSocketCanAdapter(Adapter):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._bus = None
        self._tx_id = 0
        self._rx_id = 0
        self._is_extended = False
        self._pad = int(config.get("pad_byte", 0x00)) if config.get("pad_byte") is not None else None
        self._fd = bool(config.get("fd", False))
        self._bitrate_switch = bool(config.get("bitrate_switch", False))

    def open(self) -> None:
        try:
            import can  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RuntimeError("python-can is required for isotp adapter") from e

        self._tx_id = int(self._cfg.get("tx_id", 0x7E0))
        self._rx_id = int(self._cfg.get("rx_id", 0x7E8))
        self._is_extended = bool(self._cfg.get("is_extended", self._tx_id > 0x7FF))

        channel = str(self._cfg.get("channel", "vcan0"))
        interface = str(self._cfg.get("interface", "socketcan"))
        self._bus = can.interface.Bus(channel=channel, interface=interface, fd=self._fd)

    def close(self) -> None:
        if self._bus is not None:
            try:
                self._bus.shutdown()
            finally:
                self._bus = None

    def send(self, msg: Message) -> None:
        if self._bus is None:
            raise RuntimeError("isotp adapter not open")

        payload = bytes(msg.data)
        tx_id = int(msg.meta.get("tx_id", self._tx_id))
        rx_id = int(msg.meta.get("rx_id", self._rx_id))

        fc_timeout_s = float(self._cfg.get("fc_timeout_s", 0.5))
        tx_timeout_s = float(self._cfg.get("tx_timeout_s", 2.0))

        start = time.time()
        frame_len = int(self._cfg.get("frame_len", 64 if self._fd else 8))
        if frame_len not in (8, 12, 16, 20, 24, 32, 48, 64):
            frame_len = 64 if self._fd else 8

        if len(payload) <= 7 or (self._fd and len(payload) <= max(0, frame_len - 2)):
            self._send_can(tx_id, build_sf(payload, frame_len=frame_len, pad_byte=self._pad))
            return

        # Multi-frame request: send FF then wait FC then send CF.
        total_len = len(payload)
        self._send_can(tx_id, build_ff(payload, total_len=total_len, frame_len=frame_len, pad_byte=self._pad))

        fc = self._wait_for_fc(rx_id=rx_id, timeout_s=fc_timeout_s)
        if fc is None:
            raise TimeoutError("ISO-TP FC timeout")
        if (fc.fc_status or 0x0) != 0x0:
            raise RuntimeError(f"ISO-TP FC status not CTS: {fc.fc_status}")

        bs = int(fc.block_size or 0)
        stmin = int(fc.stmin or 0)
        st_delay = stmin_to_seconds(stmin)

        sent_in_block = 0
        seq = 1
        # First frame carries payload after PCI bytes.
        if total_len <= 4095:
            offset = max(0, frame_len - 2)
        else:
            offset = max(0, frame_len - 6)
        while offset < total_len:
            if time.time() - start > tx_timeout_s:
                raise TimeoutError("ISO-TP send timeout")

            chunk = payload[offset : offset + 7]
            max_chunk = max(0, frame_len - 1)
            chunk = payload[offset : offset + max_chunk]
            offset += len(chunk)
            self._send_can(tx_id, build_cf(seq, chunk, frame_len=frame_len, pad_byte=self._pad))
            seq = (seq + 1) & 0xF

            if st_delay > 0:
                time.sleep(st_delay)

            if bs != 0:
                sent_in_block += 1
                if sent_in_block >= bs and offset < total_len:
                    sent_in_block = 0
                    fc = self._wait_for_fc(rx_id=rx_id, timeout_s=fc_timeout_s)
                    if fc is None:
                        raise TimeoutError("ISO-TP FC timeout (block)")
                    if (fc.fc_status or 0x0) != 0x0:
                        raise RuntimeError(f"ISO-TP FC status not CTS: {fc.fc_status}")
                    bs = int(fc.block_size or 0)
                    stmin = int(fc.stmin or 0)
                    st_delay = stmin_to_seconds(stmin)

    def recv(self, timeout_s: float) -> Message | None:
        if self._bus is None:
            raise RuntimeError("isotp adapter not open")

        rx_id = int(self._cfg.get("rx_id", self._rx_id))
        tx_id = int(self._cfg.get("tx_id", self._tx_id))

        state = IsoTpReassembly()
        end = time.time() + float(timeout_s)
        while True:
            remaining = end - time.time()
            if remaining <= 0:
                return None
            frame = self._recv_can(timeout_s=remaining)
            if frame is None:
                return None
            if int(frame["can_id"]) != rx_id:
                continue

            data = frame["data"]
            complete, parsed = reassemble_feed(state, data)

            if parsed.frame_type == "ff":
                # Send Flow Control CTS.
                bs = int(self._cfg.get("fc_bs", 0))
                stmin = int(self._cfg.get("fc_stmin", 0))
                frame_len = int(self._cfg.get("frame_len", 64 if self._fd else 8))
                if frame_len not in (8, 12, 16, 20, 24, 32, 48, 64):
                    frame_len = 64 if self._fd else 8
                self._send_can(tx_id, build_fc(status=0x0, block_size=bs, stmin=stmin, frame_len=frame_len, pad_byte=self._pad))

            if complete is not None:
                return Message(
                    data=complete,
                    meta={
                        "isotp": {
                            "rx_id": rx_id,
                            "tx_id": tx_id,
                            "len": len(complete),
                        }
                    },
                )

    def _send_can(self, can_id: int, data: bytes) -> None:
        try:
            import can  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RuntimeError("python-can is required for isotp adapter") from e

        msg = can.Message(
            arbitration_id=int(can_id),
            data=(data[:64] if self._fd else data[:8]),
            is_extended_id=self._is_extended,
            is_fd=self._fd,
            bitrate_switch=self._bitrate_switch,
        )
        self._bus.send(msg)

    def _recv_can(self, timeout_s: float) -> dict[str, Any] | None:
        rx = self._bus.recv(timeout=timeout_s)
        if rx is None:
            return None
        return {
            "can_id": int(rx.arbitration_id),
            "data": bytes(rx.data),
        }

    def _wait_for_fc(self, *, rx_id: int, timeout_s: float) -> Any | None:
        end = time.time() + float(timeout_s)
        while True:
            remaining = end - time.time()
            if remaining <= 0:
                return None
            frame = self._recv_can(timeout_s=remaining)
            if frame is None:
                continue
            if int(frame["can_id"]) != int(rx_id):
                continue
            try:
                parsed = parse_isotp_frame(frame["data"])
            except ValueError:
                continue
            if parsed.frame_type == "fc":
                return parsed


@register_adapter("isotp")
def isotp_adapter(config: dict[str, Any]) -> Adapter:
    return _IsoTpSocketCanAdapter(config)
