"""
Oracle Contract Tests.

All Oracle implementations MUST pass these tests to ensure they
conform to the Oracle interface contract.

Usage:
    class TestMyOracle(OracleContractMixin):
        @pytest.fixture
        def oracle_factory(self):
            return lambda: MyOracle(config)
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, Callable

import pytest


class OracleContractMixin:
    """
    Mixin class containing contract tests for Oracle implementations.

    Subclasses must provide:
    - oracle_factory: fixture returning a callable that creates the oracle
    """

    @pytest.fixture
    @abstractmethod
    def oracle_factory(self) -> Callable:
        """Return a factory function that creates the oracle instance."""
        raise NotImplementedError

    @pytest.fixture
    def oracle(self, oracle_factory):
        """Create oracle instance for testing."""
        return oracle_factory()

    @pytest.fixture
    def sample_message(self):
        """Create a sample message for testing."""
        from vehfuzz.core.plugins import Message
        return Message(data=b"test_data", meta={"test": True})

    # ==================== Interface Existence Tests ====================

    def test_has_on_tx_method(self, oracle):
        """Oracle must have on_tx() method."""
        assert hasattr(oracle, "on_tx")
        assert callable(oracle.on_tx)

    def test_has_on_rx_method(self, oracle):
        """Oracle must have on_rx() method."""
        assert hasattr(oracle, "on_rx")
        assert callable(oracle.on_rx)

    def test_has_on_error_method(self, oracle):
        """Oracle must have on_error() method."""
        assert hasattr(oracle, "on_error")
        assert callable(oracle.on_error)

    def test_has_finalize_method(self, oracle):
        """Oracle must have finalize() method."""
        assert hasattr(oracle, "finalize")
        assert callable(oracle.finalize)

    # ==================== Behavioral Contract Tests ====================

    def test_on_tx_accepts_case_id_and_msg(self, oracle, sample_message):
        """on_tx() must accept case_id and msg kwargs."""
        # Should not raise
        oracle.on_tx(case_id=1, msg=sample_message)

    def test_on_rx_accepts_case_id_and_msg(self, oracle, sample_message):
        """on_rx() must accept case_id and msg kwargs."""
        # Should not raise
        oracle.on_rx(case_id=1, msg=sample_message)

    def test_on_error_accepts_case_id_and_error(self, oracle):
        """on_error() must accept case_id and error kwargs."""
        # Should not raise
        oracle.on_error(case_id=1, error="test error")

    def test_finalize_returns_dict(self, oracle):
        """finalize() must return a dict."""
        result = oracle.finalize()
        assert isinstance(result, dict)

    def test_full_lifecycle(self, oracle, sample_message):
        """Test complete oracle lifecycle."""
        # Simulate a fuzzing session
        oracle.on_tx(case_id=1, msg=sample_message)
        oracle.on_rx(case_id=1, msg=sample_message)
        oracle.on_tx(case_id=2, msg=sample_message)
        oracle.on_error(case_id=2, error="timeout")
        oracle.on_tx(case_id=3, msg=sample_message)
        oracle.on_rx(case_id=3, msg=sample_message)

        result = oracle.finalize()
        assert isinstance(result, dict)

    def test_finalize_can_be_called_without_events(self, oracle):
        """finalize() should work even with no events."""
        result = oracle.finalize()
        assert isinstance(result, dict)

    def test_multiple_tx_same_case_id(self, oracle, sample_message):
        """Oracle should handle multiple TX for same case_id."""
        oracle.on_tx(case_id=1, msg=sample_message)
        oracle.on_tx(case_id=1, msg=sample_message)  # Should not raise

    def test_rx_without_tx(self, oracle, sample_message):
        """Oracle should handle RX without prior TX."""
        # This might be unusual but should not crash
        oracle.on_rx(case_id=999, msg=sample_message)
