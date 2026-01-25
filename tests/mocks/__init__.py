"""
Mock implementations for testing.

These mocks implement the plugin interfaces and can be used for:
- Unit testing without real hardware
- Integration testing
- Recording/replaying message sequences
"""

from __future__ import annotations

from typing import Any

from vehfuzz.core.plugins import Adapter, Protocol, Oracle, Message
from vehfuzz.core.parsed import ParsedMessage, ByteRange


class MockAdapter(Adapter):
    """
    Mock adapter for testing.

    Records all sent messages and allows pre-configuring received messages.

    Usage:
        adapter = MockAdapter()
        adapter.recv_queue.append(Message(data=b"response"))
        adapter.open()
        adapter.send(Message(data=b"request"))
        response = adapter.recv(1.0)
        assert adapter.sent[0].data == b"request"
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._is_open = False
        self.sent: list[Message] = []
        self.recv_queue: list[Message] = []
        self.open_count = 0
        self.close_count = 0

    @property
    def is_open(self) -> bool:
        return self._is_open

    def open(self) -> None:
        self._is_open = True
        self.open_count += 1

    def close(self) -> None:
        self._is_open = False
        self.close_count += 1

    def send(self, msg: Message) -> None:
        if not self._is_open:
            raise RuntimeError("MockAdapter not open")
        self.sent.append(msg)

    def recv(self, timeout_s: float) -> Message | None:
        if not self._is_open:
            raise RuntimeError("MockAdapter not open")
        if self.recv_queue:
            return self.recv_queue.pop(0)
        return None

    def reset(self) -> None:
        """Reset all recorded state."""
        self.sent.clear()
        self.recv_queue.clear()
        self.open_count = 0
        self.close_count = 0


class MockProtocol(Protocol):
    """
    Mock protocol for testing.

    By default, passes through data unchanged. Can be configured to
    transform data or record calls.

    Usage:
        proto = MockProtocol()
        msg = proto.build_tx(seed, b"mutated")
        assert msg.data == b"mutated"
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self.build_tx_calls: list[tuple[Message, bytes]] = []
        self.parse_calls: list[Message] = []
        self._prefix = self._config.get("prefix", b"")
        self._suffix = self._config.get("suffix", b"")

    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        self.build_tx_calls.append((seed, mutated))
        data = self._prefix + mutated + self._suffix
        meta = dict(seed.meta)
        meta["mock_protocol"] = True
        return Message(data=data, meta=meta)

    def parse(self, msg: Message) -> ParsedMessage | None:
        self.parse_calls.append(msg)
        return ParsedMessage(
            protocol="mock",
            level="raw",
            ok=True,
            fields={"len": len(msg.data)},
            payload=ByteRange(0, len(msg.data)),
        )

    def reset(self) -> None:
        """Reset all recorded state."""
        self.build_tx_calls.clear()
        self.parse_calls.clear()


class MockOracle(Oracle):
    """
    Mock oracle for testing.

    Records all events and returns configurable results from finalize().

    Usage:
        oracle = MockOracle()
        oracle.on_tx(case_id=1, msg=msg)
        oracle.on_rx(case_id=1, msg=response)
        result = oracle.finalize()
        assert oracle.tx_events[0] == (1, msg)
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self.tx_events: list[tuple[int, Message]] = []
        self.rx_events: list[tuple[int, Message]] = []
        self.error_events: list[tuple[int, str]] = []
        self._finalize_result: dict[str, Any] = {}

    def on_tx(self, *, case_id: int, msg: Message) -> None:
        self.tx_events.append((case_id, msg))

    def on_rx(self, *, case_id: int, msg: Message) -> None:
        self.rx_events.append((case_id, msg))

    def on_error(self, *, case_id: int, error: str) -> None:
        self.error_events.append((case_id, error))

    def finalize(self) -> dict[str, Any]:
        return {
            "tx_count": len(self.tx_events),
            "rx_count": len(self.rx_events),
            "error_count": len(self.error_events),
            **self._finalize_result,
        }

    def set_finalize_result(self, result: dict[str, Any]) -> None:
        """Configure additional fields to return from finalize()."""
        self._finalize_result = result

    def reset(self) -> None:
        """Reset all recorded state."""
        self.tx_events.clear()
        self.rx_events.clear()
        self.error_events.clear()
        self._finalize_result.clear()


class RecordingAdapter(Adapter):
    """
    Adapter that wraps another adapter and records all traffic.

    Useful for debugging and creating test fixtures.

    Usage:
        real_adapter = create_adapter("tcp", config)
        recording = RecordingAdapter(real_adapter)
        recording.open()
        # ... use normally ...
        recording.save_recording("traffic.json")
    """

    def __init__(self, wrapped: Adapter) -> None:
        self._wrapped = wrapped
        self.recording: list[dict[str, Any]] = []

    @property
    def is_open(self) -> bool:
        return getattr(self._wrapped, "is_open", False)

    def open(self) -> None:
        self._wrapped.open()
        self.recording.append({"event": "open"})

    def close(self) -> None:
        self._wrapped.close()
        self.recording.append({"event": "close"})

    def send(self, msg: Message) -> None:
        self._wrapped.send(msg)
        self.recording.append({
            "event": "send",
            "data": msg.data.hex(),
            "meta": msg.meta,
        })

    def recv(self, timeout_s: float) -> Message | None:
        result = self._wrapped.recv(timeout_s)
        self.recording.append({
            "event": "recv",
            "timeout_s": timeout_s,
            "data": result.data.hex() if result else None,
            "meta": result.meta if result else None,
        })
        return result

    def save_recording(self, path: str) -> None:
        """Save recording to JSON file."""
        import json
        with open(path, "w") as f:
            json.dump(self.recording, f, indent=2)

    def clear_recording(self) -> None:
        """Clear the recording."""
        self.recording.clear()
