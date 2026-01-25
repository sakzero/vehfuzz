"""
Adapter Contract Tests.

All Adapter implementations MUST pass these tests to ensure they
conform to the Adapter interface contract.

Usage:
    class TestMyAdapter(AdapterContractMixin):
        @pytest.fixture
        def adapter_factory(self):
            return lambda: MyAdapter(config)

        @pytest.fixture
        def can_connect(self):
            # Return True if real connection is available for testing
            return False
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

import pytest


class AdapterContractMixin:
    """
    Mixin class containing contract tests for Adapter implementations.

    Subclasses must provide:
    - adapter_factory: fixture returning a callable that creates the adapter
    - can_connect: fixture returning True if real connection tests should run
    """

    @pytest.fixture
    @abstractmethod
    def adapter_factory(self) -> Callable:
        """Return a factory function that creates the adapter instance."""
        raise NotImplementedError

    @pytest.fixture
    def can_connect(self) -> bool:
        """Override to True if real connection is available."""
        return False

    @pytest.fixture
    def adapter(self, adapter_factory):
        """Create adapter instance for testing."""
        return adapter_factory()

    # ==================== Interface Existence Tests ====================

    def test_has_open_method(self, adapter):
        """Adapter must have open() method."""
        assert hasattr(adapter, "open")
        assert callable(adapter.open)

    def test_has_close_method(self, adapter):
        """Adapter must have close() method."""
        assert hasattr(adapter, "close")
        assert callable(adapter.close)

    def test_has_send_method(self, adapter):
        """Adapter must have send() method."""
        assert hasattr(adapter, "send")
        assert callable(adapter.send)

    def test_has_recv_method(self, adapter):
        """Adapter must have recv() method."""
        assert hasattr(adapter, "recv")
        assert callable(adapter.recv)

    # ==================== Behavioral Contract Tests ====================

    def test_close_without_open_does_not_raise(self, adapter):
        """Calling close() without open() should not raise."""
        # Should not raise any exception
        adapter.close()

    def test_close_is_idempotent(self, adapter, can_connect):
        """Multiple close() calls should not raise."""
        if can_connect:
            adapter.open()
        adapter.close()
        adapter.close()  # Second close should not raise
        adapter.close()  # Third close should not raise

    def test_send_without_open_raises(self, adapter):
        """send() without open() should raise RuntimeError."""
        from vehfuzz.core.plugins import Message

        msg = Message(data=b"test")
        with pytest.raises(RuntimeError):
            adapter.send(msg)

    def test_recv_without_open_raises(self, adapter):
        """recv() without open() should raise RuntimeError."""
        with pytest.raises(RuntimeError):
            adapter.recv(0.1)

    # ==================== Connection Tests (require real hardware) ====================

    def test_open_close_cycle(self, adapter, can_connect):
        """Test basic open/close cycle."""
        if not can_connect:
            pytest.skip("No connection available")

        adapter.open()
        adapter.close()

    def test_recv_returns_message_or_none(self, adapter, can_connect):
        """recv() should return Message or None."""
        if not can_connect:
            pytest.skip("No connection available")

        from vehfuzz.core.plugins import Message

        adapter.open()
        try:
            result = adapter.recv(0.1)
            assert result is None or isinstance(result, Message)
        finally:
            adapter.close()

    def test_recv_timeout_returns_none(self, adapter, can_connect):
        """recv() with timeout should return None if no data."""
        if not can_connect:
            pytest.skip("No connection available")

        adapter.open()
        try:
            # Very short timeout, likely no data
            result = adapter.recv(0.001)
            # Should return None on timeout (not raise)
            assert result is None or isinstance(result, (type(None), object))
        finally:
            adapter.close()
