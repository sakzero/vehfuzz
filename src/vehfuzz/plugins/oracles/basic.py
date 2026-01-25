from __future__ import annotations

from typing import Any

from vehfuzz.core.plugins import Message, Oracle, register_oracle


class _BasicOracle(Oracle):
    def __init__(self, config: dict[str, Any]) -> None:
        self._tx = 0
        self._rx = 0
        self._errors = 0
        self._anomalies: list[dict[str, Any]] = []
        # Configurable sample limit
        self._max_samples = int(config.get("max_anomaly_samples", 10)) if config else 10

    def on_tx(self, *, case_id: int, msg: Message) -> None:
        self._tx += 1

    def on_rx(self, *, case_id: int, msg: Message) -> None:
        self._rx += 1

    def on_error(self, *, case_id: int, error: str) -> None:
        self._errors += 1
        self._anomalies.append({"case_id": case_id, "type": "error", "error": error})

    def finalize(self) -> dict[str, Any]:
        total_anomalies = len(self._anomalies)
        samples = self._anomalies[:self._max_samples]
        return {
            "type": "basic",
            "tx": self._tx,
            "rx": self._rx,
            "errors": self._errors,
            "anomalies": total_anomalies,
            "anomaly_samples": samples,
            "anomaly_samples_truncated": total_anomalies > len(samples),
        }


@register_oracle("basic")
def basic_oracle(config: dict[str, Any]) -> Oracle:
    return _BasicOracle(config)

