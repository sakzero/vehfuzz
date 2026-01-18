from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


ParseLevel = Literal["raw", "l2", "l3", "l4", "app"]


@dataclass(frozen=True)
class ByteRange:
    offset: int
    length: int

    def to_dict(self) -> dict[str, int]:
        return {"offset": int(self.offset), "length": int(self.length)}


@dataclass(frozen=True)
class ParsedMessage:
    """
    A json-serializable, fuzz-oriented parse result.

    - level: how far we could reliably parse
    - ok: parser ran and produced a meaningful result (even if partial)
    - encrypted: payload is present but not visible (e.g. protected 802.11 data frame)
    - payload: best-effort location of the fuzzable payload (if any)
    """

    protocol: str
    level: ParseLevel = "raw"
    ok: bool = True
    encrypted: bool = False
    reason: str | None = None
    flow_key: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    payload: ByteRange | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "protocol": self.protocol,
            "level": self.level,
            "ok": bool(self.ok),
            "encrypted": bool(self.encrypted),
            "reason": self.reason,
            "flow_key": self.flow_key,
            "fields": self.fields,
        }
        if self.payload is not None:
            out["payload"] = self.payload.to_dict()
        return out
