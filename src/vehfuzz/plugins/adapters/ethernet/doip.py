from __future__ import annotations

import socket
import struct
import time
from typing import Any

from vehfuzz.core.plugins import Adapter, Message, register_adapter


def _build_header(*, version: int, payload_type: int, payload_len: int) -> bytes:
    version &= 0xFF
    inv = version ^ 0xFF
    return struct.pack(">BBHI", version, inv, payload_type & 0xFFFF, payload_len & 0xFFFFFFFF)


def _parse_header(data: bytes) -> tuple[int, int, int, int]:
    if len(data) != 8:
        raise ValueError("DoIP header must be 8 bytes")
    version, inv, ptype, plen = struct.unpack(">BBHI", data)
    return version, inv, ptype, plen


class _DoipAdapter(Adapter):
    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._sock: socket.socket | None = None
        self._tester_addr = int(config.get("tester_addr", 0x0E00)) & 0xFFFF
        self._ecu_addr = int(config.get("ecu_addr", 0x0E01)) & 0xFFFF
        self._version = int(config.get("version", 0x02)) & 0xFF

    def open(self) -> None:
        host = str(self._cfg.get("host", "127.0.0.1"))
        port = int(self._cfg.get("port", 13400))
        timeout = float(self._cfg.get("timeout_s", 2.0))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(timeout)
        sock.connect((host, port))
        self._sock = sock

        if bool(self._cfg.get("routing_activation", True)):
            self._do_routing_activation(timeout_s=timeout)

        # After connect/activation, use non-blocking with per-recv timeouts.
        self._sock.settimeout(None)

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
            raise RuntimeError("doip adapter not open")

        uds = bytes(msg.data)
        src = int(msg.meta.get("tester_addr", self._tester_addr)) & 0xFFFF
        dst = int(msg.meta.get("ecu_addr", self._ecu_addr)) & 0xFFFF

        payload = struct.pack(">HH", src, dst) + uds
        frame = _build_header(version=self._version, payload_type=0x8001, payload_len=len(payload)) + payload
        self._sock.sendall(frame)

    def recv(self, timeout_s: float) -> Message | None:
        if self._sock is None:
            raise RuntimeError("doip adapter not open")

        deadline = time.time() + float(timeout_s)
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return None

            self._sock.settimeout(remaining)
            try:
                header = self._recv_exact(8)
            except socket.timeout:
                return None
            version, inv, ptype, plen = _parse_header(header)
            if (version ^ inv) & 0xFF != 0xFF:
                # Invalid inverse version, drop frame.
                _ = self._recv_exact(plen)
                continue
            payload = self._recv_exact(plen) if plen else b""

            # Skip ACK frames; return diagnostic message.
            if ptype == 0x8001 and len(payload) >= 4:
                src, dst = struct.unpack(">HH", payload[:4])
                uds = payload[4:]
                return Message(data=uds, meta={"doip": {"src": src, "dst": dst, "payload_type": ptype}})

    def _recv_exact(self, n: int) -> bytes:
        if self._sock is None:
            raise RuntimeError("doip adapter not open")
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("DoIP connection closed")
            buf.extend(chunk)
        return bytes(buf)

    def _do_routing_activation(self, *, timeout_s: float) -> None:
        if self._sock is None:
            raise RuntimeError("doip adapter not open")
        activation_type = int(self._cfg.get("activation_type", 0x00)) & 0xFF

        payload = struct.pack(">HBBI", self._tester_addr, activation_type, 0x00, 0x00000000)
        frame = _build_header(version=self._version, payload_type=0x0005, payload_len=len(payload)) + payload
        self._sock.sendall(frame)

        self._sock.settimeout(timeout_s)
        header = self._recv_exact(8)
        version, inv, ptype, plen = _parse_header(header)
        if ptype != 0x0006:
            _ = self._recv_exact(plen)
            raise RuntimeError(f"Unexpected DoIP payload type during activation: 0x{ptype:04x}")
        payload = self._recv_exact(plen) if plen else b""
        # Best-effort parse: response code is typically at byte 4.
        if len(payload) >= 5:
            response_code = payload[4]
            if response_code != 0x10 and response_code != 0x00:
                # 0x10=success in some docs; accept 0x00 too.
                raise RuntimeError(f"Routing activation rejected: 0x{response_code:02x}")


@register_adapter("doip")
def doip_adapter(config: dict[str, Any]) -> Adapter:
    return _DoipAdapter(config)

