from __future__ import annotations

import socket
from typing import Any

from vehfuzz.core.plugins import Adapter, Message, register_adapter


class _TcpAdapter(Adapter):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._sock: socket.socket | None = None

    def open(self) -> None:
        host = str(self._cfg.get("host", "127.0.0.1"))
        port = int(self._cfg.get("port", 0))
        if port <= 0:
            raise ValueError("tcp adapter requires port > 0")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(float(self._cfg.get("connect_timeout_s", 5.0)))
        sock.connect((host, port))
        sock.settimeout(None)
        self._sock = sock

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()
            self._sock = None

    def send(self, msg: Message) -> None:
        if self._sock is None:
            raise RuntimeError("tcp adapter not open")
        self._sock.sendall(msg.data)

    def recv(self, timeout_s: float) -> Message | None:
        if self._sock is None:
            raise RuntimeError("tcp adapter not open")
        self._sock.settimeout(timeout_s)
        try:
            recv_buf = int(self._cfg.get("recv_buf", 65535))
            # Validate buffer size: 1 byte to 1 MB
            recv_buf = max(1, min(recv_buf, 1048576))
            data = self._sock.recv(recv_buf)
        except TimeoutError:
            return None
        except socket.timeout:
            return None
        if not data:
            return None
        return Message(data=data, meta={})


@register_adapter("tcp")
def tcp_adapter(config: dict[str, Any]) -> Adapter:
    return _TcpAdapter(config)

