from __future__ import annotations

from typing import Any

from vehfuzz.core.plugins import Adapter, Message, register_adapter


class _SocketCanAdapter(Adapter):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._bus = None

    def open(self) -> None:
        try:
            import can  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RuntimeError("python-can is required for socketcan adapter") from e

        channel = str(self._cfg.get("channel", "vcan0"))
        interface = str(self._cfg.get("interface", "socketcan"))
        fd = bool(self._cfg.get("fd", False))
        self._bus = can.interface.Bus(channel=channel, interface=interface, fd=fd)

    def close(self) -> None:
        if self._bus is not None:
            try:
                self._bus.shutdown()
            finally:
                self._bus = None

    def send(self, msg: Message) -> None:
        if self._bus is None:
            raise RuntimeError("socketcan adapter not open")
        try:
            import can  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RuntimeError("python-can is required for socketcan adapter") from e

        can_id = int(msg.meta.get("can_id", 0))
        is_extended = bool(msg.meta.get("is_extended", can_id > 0x7FF))
        is_fd = bool(msg.meta.get("is_fd", False))
        bitrate_switch = bool(msg.meta.get("bitrate_switch", False))
        is_remote_frame = bool(msg.meta.get("is_remote_frame", False))

        frame = can.Message(
            arbitration_id=can_id,
            data=msg.data,
            is_extended_id=is_extended,
            is_fd=is_fd,
            bitrate_switch=bitrate_switch,
            is_remote_frame=is_remote_frame,
        )
        self._bus.send(frame)

    def recv(self, timeout_s: float) -> Message | None:
        if self._bus is None:
            raise RuntimeError("socketcan adapter not open")
        rx = self._bus.recv(timeout=timeout_s)
        if rx is None:
            return None
        return Message(
            data=bytes(rx.data),
            meta={
                "can_id": int(rx.arbitration_id),
                "is_extended": bool(rx.is_extended_id),
                "is_fd": bool(getattr(rx, "is_fd", False)),
                "dlc": int(rx.dlc),
            },
        )


@register_adapter("socketcan")
def socketcan_adapter(config: dict[str, Any]) -> Adapter:
    return _SocketCanAdapter(config)

