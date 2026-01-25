from __future__ import annotations

from typing import Any

from vehfuzz.core.plugins import Adapter, Message, register_adapter


class _SerialAdapter(Adapter):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._ser = None

    def open(self) -> None:
        try:
            import serial  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RuntimeError("pyserial is required for serial adapter") from e

        port = self._cfg.get("port")
        if not port:
            raise ValueError("serial adapter requires port")
        baudrate = int(self._cfg.get("baudrate", 9600))
        timeout_s = float(self._cfg.get("timeout_s", 0.2))
        self._ser = serial.Serial(port=str(port), baudrate=baudrate, timeout=timeout_s)

    def close(self) -> None:
        if self._ser is not None:
            self._ser.close()
            self._ser = None

    def send(self, msg: Message) -> None:
        if self._ser is None:
            raise RuntimeError("serial adapter not open")
        try:
            self._ser.write(msg.data)
        except OSError as e:
            raise RuntimeError(f"serial write failed: {e}") from e

    def recv(self, timeout_s: float) -> Message | None:
        if self._ser is None:
            raise RuntimeError("serial adapter not open")
        # pyserial timeout is set on the Serial object; do a non-blocking-ish read.
        max_bytes = int(self._cfg.get("recv_buf", 4096))
        # Validate buffer size
        max_bytes = max(1, min(max_bytes, 1048576))  # 1 byte to 1 MB
        try:
            data = self._ser.read(max_bytes)
        except OSError as e:
            raise RuntimeError(f"serial read failed: {e}") from e
        if not data:
            return None
        return Message(data=bytes(data), meta={})


@register_adapter("serial")
def serial_adapter(config: dict[str, Any]) -> Adapter:
    return _SerialAdapter(config)

