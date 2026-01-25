# Adding a New Protocol

This guide explains how to add a new protocol handler to vehfuzz.

## Overview

Protocols handle message construction and parsing. They are responsible for:
- Building transmit messages from seeds and mutated data
- Parsing received messages into structured fields

## Step 1: Create the Protocol File

Create a new file in `src/vehfuzz/plugins/protocols/`:

```
src/vehfuzz/plugins/protocols/myproto.py
```

## Step 2: Implement the Protocol Interface

```python
# src/vehfuzz/plugins/protocols/myproto.py

from __future__ import annotations

from typing import Any

from vehfuzz.core.parsed import ByteRange, ParsedMessage
from vehfuzz.core.plugins import Message, Protocol, register_protocol


class _MyProtoProtocol(Protocol):
    """Protocol handler for MyProto."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config

    def build_tx(self, seed: Message, mutated: bytes) -> Message:
        """
        Build a transmit message.

        Args:
            seed: Original seed message (may contain metadata)
            mutated: Mutated payload bytes from the fuzzer

        Returns:
            Complete message ready for transmission
        """
        # Add protocol header/framing
        header = self._build_header(len(mutated))
        data = header + mutated

        # Preserve and extend metadata
        meta = dict(seed.meta)
        meta["myproto"] = {
            "header_len": len(header),
            "payload_len": len(mutated),
        }

        return Message(data=data, meta=meta)

    def _build_header(self, payload_len: int) -> bytes:
        """Build protocol header."""
        # Example: 4-byte header with magic + length
        magic = b"\x4D\x50"  # "MP"
        length = payload_len.to_bytes(2, "big")
        return magic + length

    def parse(self, msg: Message) -> ParsedMessage | None:
        """
        Parse a received message.

        Args:
            msg: Received message

        Returns:
            ParsedMessage with extracted fields, or None if not parseable
        """
        data = bytes(msg.data)

        # Validate minimum length
        if len(data) < 4:
            return ParsedMessage(
                protocol="myproto",
                level="raw",
                ok=False,
                reason="too_short",
                fields={"len": len(data)},
            )

        # Parse header
        magic = data[0:2]
        payload_len = int.from_bytes(data[2:4], "big")

        fields: dict[str, Any] = {
            "magic": magic.hex(),
            "magic_valid": magic == b"\x4D\x50",
            "payload_len": payload_len,
            "actual_len": len(data) - 4,
            "len_matches": payload_len == len(data) - 4,
        }

        # Determine payload location for fuzzing
        payload = ByteRange(offset=4, length=len(data) - 4)

        return ParsedMessage(
            protocol="myproto",
            level="app",
            ok=fields["magic_valid"],
            reason=None if fields["magic_valid"] else "invalid_magic",
            flow_key="myproto",
            fields=fields,
            payload=payload,
        )


@register_protocol("myproto")
def myproto_protocol(config: dict[str, Any]) -> Protocol:
    """Factory function for MyProto protocol."""
    return _MyProtoProtocol(config)
```

## Step 3: Register the Protocol

Update the protocols package `__init__.py`:

```python
# src/vehfuzz/plugins/protocols/__init__.py

from vehfuzz.plugins.protocols import raw
from vehfuzz.plugins.protocols import can
# ... existing imports ...
from vehfuzz.plugins.protocols import myproto  # Add this line
```

## Step 4: Add Shared Parsers (If Needed)

If your protocol needs parsing logic that might be reused by other protocols,
put it in `core/parsers/`:

```python
# src/vehfuzz/core/parsers/myproto_parser.py

from __future__ import annotations

from typing import Any


def parse_myproto_header(data: bytes) -> dict[str, Any]:
    """
    Parse MyProto header.

    This is a pure function with no dependencies on protocol plugins.
    """
    if len(data) < 4:
        return {"ok": False, "reason": "too_short"}

    magic = data[0:2]
    payload_len = int.from_bytes(data[2:4], "big")

    return {
        "ok": True,
        "magic": magic.hex(),
        "magic_valid": magic == b"\x4D\x50",
        "payload_len": payload_len,
        "header_len": 4,
    }
```

Then update `core/parsers/__init__.py`:

```python
from vehfuzz.core.parsers.myproto_parser import parse_myproto_header

__all__ = [
    # ... existing exports ...
    "parse_myproto_header",
]
```

## Step 5: Add Configuration Schema

```python
# src/vehfuzz/core/schemas/__init__.py

class MyProtoProtocolConfig(TypedDict, total=False):
    """Configuration schema for MyProto protocol."""
    max_payload_len: int  # Maximum payload length
    strict_validation: bool  # Fail on invalid magic

# Add to PROTOCOL_SCHEMAS
PROTOCOL_SCHEMAS: dict[str, type[TypedDict]] = {
    # ... existing entries ...
    "myproto": MyProtoProtocolConfig,
}
```

## Step 6: Write Contract Tests

```python
# tests/unit/protocols/test_myproto_contract.py

import pytest
from vehfuzz.core.plugins import Message, create_protocol, load_builtin_plugins
from tests.contracts.test_protocol_contract import ProtocolContractMixin


class TestMyProtoProtocolContract(ProtocolContractMixin):
    """Contract tests for MyProto protocol."""

    @pytest.fixture(scope="class", autouse=True)
    def setup_plugins(self):
        load_builtin_plugins()

    @pytest.fixture
    def protocol_factory(self):
        def _create():
            return create_protocol("myproto", {})
        return _create

    @pytest.fixture
    def sample_seed(self):
        return Message(data=b"", meta={})

    @pytest.fixture
    def sample_mutated(self):
        return b"\x01\x02\x03\x04"
```

## Step 7: Write Unit Tests

```python
# tests/unit/protocols/test_myproto.py

import pytest
from vehfuzz.core.plugins import Message, create_protocol, load_builtin_plugins


class TestMyProtoProtocol:
    @pytest.fixture(scope="class", autouse=True)
    def setup_plugins(self):
        load_builtin_plugins()

    def test_build_tx_adds_header(self):
        proto = create_protocol("myproto", {})
        seed = Message(data=b"", meta={})
        tx = proto.build_tx(seed, b"\x01\x02\x03")

        assert tx.data[:2] == b"\x4D\x50"  # Magic
        assert tx.data[2:4] == b"\x00\x03"  # Length
        assert tx.data[4:] == b"\x01\x02\x03"  # Payload

    def test_parse_valid_message(self):
        proto = create_protocol("myproto", {})
        msg = Message(data=b"\x4D\x50\x00\x03\x01\x02\x03", meta={})
        parsed = proto.parse(msg)

        assert parsed is not None
        assert parsed.ok is True
        assert parsed.fields["magic_valid"] is True
        assert parsed.fields["payload_len"] == 3

    def test_parse_invalid_magic(self):
        proto = create_protocol("myproto", {})
        msg = Message(data=b"\xFF\xFF\x00\x03\x01\x02\x03", meta={})
        parsed = proto.parse(msg)

        assert parsed is not None
        assert parsed.ok is False
        assert parsed.reason == "invalid_magic"

    def test_parse_too_short(self):
        proto = create_protocol("myproto", {})
        msg = Message(data=b"\x4D\x50", meta={})
        parsed = proto.parse(msg)

        assert parsed is not None
        assert parsed.ok is False
        assert parsed.reason == "too_short"
```

## Important: Avoid Protocol Dependencies

**DO NOT** import from other protocol files:

```python
# BAD - creates coupling between protocols
from vehfuzz.plugins.protocols.uds import _parse_uds

# GOOD - use shared parsers
from vehfuzz.core.parsers.uds_parser import parse_uds_payload
```

This ensures protocols can be developed independently.

## ParsedMessage Fields

When creating `ParsedMessage`, use these fields appropriately:

| Field | Type | Description |
|-------|------|-------------|
| `protocol` | str | Protocol name (e.g., "myproto") |
| `level` | str | Parse depth: "raw", "l2", "l3", "l4", "app" |
| `ok` | bool | Whether parsing succeeded |
| `encrypted` | bool | Whether payload is encrypted |
| `reason` | str | Error reason if `ok=False` |
| `flow_key` | str | Key for correlating request/response |
| `fields` | dict | Parsed fields |
| `payload` | ByteRange | Location of fuzzable payload |

## Checklist

- [ ] Implement `build_tx()` method
- [ ] Implement `parse()` method (can return None)
- [ ] Register with `@register_protocol("name")`
- [ ] Use `core/parsers/` for shared parsing logic
- [ ] Do NOT import from other protocols
- [ ] Add configuration schema
- [ ] Pass all contract tests
- [ ] Add unit tests for parsing edge cases
