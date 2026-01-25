from __future__ import annotations

import socket
from typing import Any

from vehfuzz.core.plugins import Adapter, Message, register_adapter


class _UdpAdapter(Adapter):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._sock: socket.socket | None = None

    def open(self) -> None:
        host = str(self._cfg.get("host", "127.0.0.1"))
        port = int(self._cfg.get("port", 0))
        if port <= 0:
            raise ValueError("udp adapter requires port > 0")

        bind_host = self._cfg.get("bind_host")
        bind_port = self._cfg.get("bind_port")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if bind_host is not None or bind_port is not None:
            sock.bind((str(bind_host or "0.0.0.0"), int(bind_port or 0)))
        self._sock = sock
        self._dest = (host, port)

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def send(self, msg: Message) -> None:
        if self._sock is None:
            raise RuntimeError("udp adapter not open")
        self._sock.sendto(msg.data, self._dest)

    def recv(self, timeout_s: float) -> Message | None:
        if self._sock is None:
            raise RuntimeError("udp adapter not open")
        self._sock.settimeout(timeout_s)
        try:
            recv_buf = int(self._cfg.get("recv_buf", 65535))
            # Validate buffer size: 1 byte to 1 MB
            recv_buf = max(1, min(recv_buf, 1048576))
            data, addr = self._sock.recvfrom(recv_buf)
        except TimeoutError:
            return None
        except socket.timeout:
            return None
        return Message(data=data, meta={"src": {"host": addr[0], "port": addr[1]}})


@register_adapter("udp")
def udp_adapter(config: dict[str, Any]) -> Adapter:
    return _UdpAdapter(config)

