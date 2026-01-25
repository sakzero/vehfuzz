# Adding a New Adapter

This guide explains how to add a new hardware/network adapter to vehfuzz.

## Overview

Adapters handle the physical or network communication layer. They are responsible for:
- Opening/closing connections
- Sending raw messages
- Receiving responses

## Step 1: Create the Adapter File

Create a new file in `src/vehfuzz/plugins/adapters/`:

```
src/vehfuzz/plugins/adapters/
├── mydevice/
│   ├── __init__.py
│   └── adapter.py
```

## Step 2: Implement the Adapter Interface

```python
# src/vehfuzz/plugins/adapters/mydevice/adapter.py

from __future__ import annotations

from typing import Any

from vehfuzz.core.plugins import Adapter, Message, register_adapter


class _MyDeviceAdapter(Adapter):
    """Adapter for MyDevice hardware."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._cfg = config
        self._connection = None  # Your connection object

    def open(self) -> None:
        """Open connection to the device."""
        # Initialize your connection here
        host = self._cfg.get("host", "127.0.0.1")
        port = int(self._cfg.get("port", 12345))
        # self._connection = ...
        pass

    def close(self) -> None:
        """Close the connection."""
        if self._connection is not None:
            # Clean up your connection
            # self._connection.close()
            self._connection = None

    def send(self, msg: Message) -> None:
        """Send a message."""
        if self._connection is None:
            raise RuntimeError("MyDeviceAdapter not open")
        # Send msg.data through your connection
        # self._connection.send(msg.data)
        pass

    def recv(self, timeout_s: float) -> Message | None:
        """Receive a message with timeout."""
        if self._connection is None:
            raise RuntimeError("MyDeviceAdapter not open")
        # Receive data with timeout
        # data = self._connection.recv(timeout_s)
        # if data:
        #     return Message(data=data, meta={})
        return None


@register_adapter("mydevice")
def mydevice_adapter(config: dict[str, Any]) -> Adapter:
    """Factory function for MyDevice adapter."""
    return _MyDeviceAdapter(config)
```

## Step 3: Register the Adapter

Create `__init__.py` to ensure the adapter is loaded:

```python
# src/vehfuzz/plugins/adapters/mydevice/__init__.py

from vehfuzz.plugins.adapters.mydevice.adapter import mydevice_adapter

__all__ = ["mydevice_adapter"]
```

Update the adapters package `__init__.py`:

```python
# src/vehfuzz/plugins/adapters/__init__.py

from vehfuzz.plugins.adapters import ethernet
from vehfuzz.plugins.adapters import socketcan
from vehfuzz.plugins.adapters import serial
from vehfuzz.plugins.adapters import pcap
from vehfuzz.plugins.adapters import mydevice  # Add this line
```

## Step 4: Add Configuration Schema

Add your adapter's configuration schema:

```python
# src/vehfuzz/core/schemas/__init__.py

class MyDeviceAdapterConfig(TypedDict, total=False):
    """Configuration schema for MyDevice adapter."""
    host: str  # Default: "127.0.0.1"
    port: Required[int]  # Required
    timeout_s: float  # Default: 5.0

# Add to ADAPTER_SCHEMAS
ADAPTER_SCHEMAS: dict[str, type[TypedDict]] = {
    # ... existing entries ...
    "mydevice": MyDeviceAdapterConfig,
}
```

## Step 5: Write Contract Tests

Create contract tests to verify your adapter follows the interface:

```python
# tests/unit/adapters/test_mydevice_contract.py

import pytest
from vehfuzz.core.plugins import create_adapter, load_builtin_plugins
from tests.contracts.test_adapter_contract import AdapterContractMixin


class TestMyDeviceAdapterContract(AdapterContractMixin):
    """Contract tests for MyDevice adapter."""

    @pytest.fixture(scope="class", autouse=True)
    def setup_plugins(self):
        load_builtin_plugins()

    @pytest.fixture
    def adapter_factory(self):
        def _create():
            return create_adapter("mydevice", {
                "host": "127.0.0.1",
                "port": 12345,
            })
        return _create

    @pytest.fixture
    def can_connect(self):
        # Return True if real hardware is available for testing
        return False
```

## Step 6: Write Unit Tests

Add specific unit tests for your adapter's functionality:

```python
# tests/unit/adapters/test_mydevice.py

import pytest
from vehfuzz.core.plugins import Message, create_adapter, load_builtin_plugins


class TestMyDeviceAdapter:
    @pytest.fixture(scope="class", autouse=True)
    def setup_plugins(self):
        load_builtin_plugins()

    def test_config_validation(self):
        """Test that invalid config raises appropriate errors."""
        with pytest.raises(ValueError):
            adapter = create_adapter("mydevice", {"port": -1})
            adapter.open()

    def test_meta_preserved(self):
        """Test that message metadata is handled correctly."""
        # Your specific tests here
        pass
```

## Best Practices

### Error Handling

```python
def send(self, msg: Message) -> None:
    if self._connection is None:
        raise RuntimeError("Adapter not open")
    try:
        self._connection.send(msg.data)
    except ConnectionError as e:
        raise RuntimeError(f"Send failed: {e}") from e
```

### Resource Cleanup

```python
def close(self) -> None:
    """Close should be idempotent and never raise."""
    if self._connection is not None:
        try:
            self._connection.close()
        except Exception:
            pass  # Ignore errors during cleanup
        finally:
            self._connection = None
```

### Timeout Handling

```python
def recv(self, timeout_s: float) -> Message | None:
    if self._connection is None:
        raise RuntimeError("Adapter not open")
    try:
        self._connection.settimeout(timeout_s)
        data = self._connection.recv(4096)
        if not data:
            return None
        return Message(data=data, meta={"source": "mydevice"})
    except TimeoutError:
        return None
```

## Checklist

- [ ] Implement all abstract methods from `Adapter`
- [ ] Register with `@register_adapter("name")`
- [ ] Handle `open()` before `send()`/`recv()` with RuntimeError
- [ ] Make `close()` idempotent (safe to call multiple times)
- [ ] Return `None` from `recv()` on timeout (don't raise)
- [ ] Add configuration schema
- [ ] Pass all contract tests
- [ ] Add unit tests for edge cases
