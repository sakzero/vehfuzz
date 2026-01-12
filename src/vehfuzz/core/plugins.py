from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar


T = TypeVar("T")


@dataclass(frozen=True)
class Message:
    data: bytes
    meta: dict[str, Any] = field(default_factory=dict)


class Adapter(ABC):
    @abstractmethod
    def open(self) -> None: ...

    @abstractmethod
    def close(self) -> None: ...

    @abstractmethod
    def send(self, msg: Message) -> None: ...

    @abstractmethod
    def recv(self, timeout_s: float) -> Message | None: ...


class Protocol(ABC):
    @abstractmethod
    def build_tx(self, seed: Message, mutated: bytes) -> Message: ...


class Oracle(ABC):
    @abstractmethod
    def on_tx(self, *, case_id: int, msg: Message) -> None: ...

    @abstractmethod
    def on_rx(self, *, case_id: int, msg: Message) -> None: ...

    @abstractmethod
    def on_error(self, *, case_id: int, error: str) -> None: ...

    @abstractmethod
    def finalize(self) -> dict[str, Any]: ...


_ADAPTERS: dict[str, Callable[[dict[str, Any]], Adapter]] = {}
_PROTOCOLS: dict[str, Callable[[dict[str, Any]], Protocol]] = {}
_ORACLES: dict[str, Callable[[dict[str, Any]], Oracle]] = {}


def register_adapter(name: str) -> Callable[[Callable[[dict[str, Any]], Adapter]], Callable[[dict[str, Any]], Adapter]]:
    def _decorator(factory: Callable[[dict[str, Any]], Adapter]) -> Callable[[dict[str, Any]], Adapter]:
        _ADAPTERS[name] = factory
        return factory

    return _decorator


def register_protocol(
    name: str,
) -> Callable[[Callable[[dict[str, Any]], Protocol]], Callable[[dict[str, Any]], Protocol]]:
    def _decorator(factory: Callable[[dict[str, Any]], Protocol]) -> Callable[[dict[str, Any]], Protocol]:
        _PROTOCOLS[name] = factory
        return factory

    return _decorator


def register_oracle(name: str) -> Callable[[Callable[[dict[str, Any]], Oracle]], Callable[[dict[str, Any]], Oracle]]:
    def _decorator(factory: Callable[[dict[str, Any]], Oracle]) -> Callable[[dict[str, Any]], Oracle]:
        _ORACLES[name] = factory
        return factory

    return _decorator


def create_adapter(adapter_type: str, config: dict[str, Any]) -> Adapter:
    if adapter_type not in _ADAPTERS:
        raise KeyError(f"Unknown adapter type: {adapter_type}")
    return _ADAPTERS[adapter_type](config)


def create_protocol(protocol_type: str, config: dict[str, Any]) -> Protocol:
    if protocol_type not in _PROTOCOLS:
        raise KeyError(f"Unknown protocol type: {protocol_type}")
    return _PROTOCOLS[protocol_type](config)


def create_oracle(oracle_type: str, config: dict[str, Any]) -> Oracle:
    if oracle_type not in _ORACLES:
        raise KeyError(f"Unknown oracle type: {oracle_type}")
    return _ORACLES[oracle_type](config)


def load_builtin_plugins() -> None:
    # Import for side-effects (registration).
    from vehfuzz.plugins import adapters as _adapters  # noqa: F401
    from vehfuzz.plugins import oracles as _oracles  # noqa: F401
    from vehfuzz.plugins import protocols as _protocols  # noqa: F401


def list_plugins() -> dict[str, list[str]]:
    return {
        "adapters": sorted(_ADAPTERS.keys()),
        "protocols": sorted(_PROTOCOLS.keys()),
        "oracles": sorted(_ORACLES.keys()),
    }

