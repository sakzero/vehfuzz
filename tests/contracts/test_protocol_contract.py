"""
Protocol Contract Tests.

All Protocol implementations MUST pass these tests to ensure they
conform to the Protocol interface contract.

Usage:
    class TestMyProtocol(ProtocolContractMixin):
        @pytest.fixture
        def protocol_factory(self):
            return lambda: MyProtocol(config)

        @pytest.fixture
        def sample_seed(self):
            return Message(data=b"seed_data", meta={})

        @pytest.fixture
        def sample_mutated(self):
            return b"mutated_data"
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Callable

import pytest


class ProtocolContractMixin:
    """
    Mixin class containing contract tests for Protocol implementations.

    Subclasses must provide:
    - protocol_factory: fixture returning a callable that creates the protocol
    - sample_seed: fixture returning a sample seed Message
    - sample_mutated: fixture returning sample mutated bytes
    """

    @pytest.fixture
    @abstractmethod
    def protocol_factory(self) -> Callable:
        """Return a factory function that creates the protocol instance."""
        raise NotImplementedError

    @pytest.fixture
    @abstractmethod
    def sample_seed(self):
        """Return a sample seed Message for testing."""
        raise NotImplementedError

    @pytest.fixture
    @abstractmethod
    def sample_mutated(self) -> bytes:
        """Return sample mutated bytes for testing."""
        raise NotImplementedError

    @pytest.fixture
    def protocol(self, protocol_factory):
        """Create protocol instance for testing."""
        return protocol_factory()

    # ==================== Interface Existence Tests ====================

    def test_has_build_tx_method(self, protocol):
        """Protocol must have build_tx() method."""
        assert hasattr(protocol, "build_tx")
        assert callable(protocol.build_tx)

    def test_has_parse_method(self, protocol):
        """Protocol must have parse() method."""
        assert hasattr(protocol, "parse")
        assert callable(protocol.parse)

    # ==================== Behavioral Contract Tests ====================

    def test_build_tx_returns_message(self, protocol, sample_seed, sample_mutated):
        """build_tx() must return a Message instance."""
        from vehfuzz.core.plugins import Message

        result = protocol.build_tx(sample_seed, sample_mutated)
        assert isinstance(result, Message)

    def test_build_tx_result_has_data(self, protocol, sample_seed, sample_mutated):
        """build_tx() result must have data attribute."""
        result = protocol.build_tx(sample_seed, sample_mutated)
        assert hasattr(result, "data")
        assert isinstance(result.data, bytes)

    def test_build_tx_result_has_meta(self, protocol, sample_seed, sample_mutated):
        """build_tx() result must have meta attribute."""
        result = protocol.build_tx(sample_seed, sample_mutated)
        assert hasattr(result, "meta")
        assert isinstance(result.meta, dict)

    def test_parse_returns_parsed_message_or_none(self, protocol, sample_seed, sample_mutated):
        """parse() must return ParsedMessage or None."""
        from vehfuzz.core.parsed import ParsedMessage

        tx = protocol.build_tx(sample_seed, sample_mutated)
        result = protocol.parse(tx)
        assert result is None or isinstance(result, ParsedMessage)

    def test_parse_result_has_required_fields(self, protocol, sample_seed, sample_mutated):
        """If parse() returns ParsedMessage, it must have required fields."""
        from vehfuzz.core.parsed import ParsedMessage

        tx = protocol.build_tx(sample_seed, sample_mutated)
        result = protocol.parse(tx)

        if result is not None:
            assert isinstance(result, ParsedMessage)
            assert hasattr(result, "protocol")
            assert hasattr(result, "level")
            assert hasattr(result, "ok")
            assert hasattr(result, "fields")
            assert isinstance(result.protocol, str)
            assert isinstance(result.fields, dict)

    def test_build_tx_with_empty_mutated(self, protocol, sample_seed):
        """build_tx() should handle empty mutated bytes."""
        from vehfuzz.core.plugins import Message

        result = protocol.build_tx(sample_seed, b"")
        assert isinstance(result, Message)

    def test_parse_with_empty_data(self, protocol):
        """parse() should handle empty data gracefully."""
        from vehfuzz.core.plugins import Message
        from vehfuzz.core.parsed import ParsedMessage

        msg = Message(data=b"", meta={})
        # Should not raise, may return None or ParsedMessage
        result = protocol.parse(msg)
        assert result is None or isinstance(result, ParsedMessage)

    def test_build_tx_preserves_seed_immutability(self, protocol, sample_seed, sample_mutated):
        """build_tx() should not modify the seed message."""
        original_data = sample_seed.data
        original_meta = dict(sample_seed.meta)

        protocol.build_tx(sample_seed, sample_mutated)

        assert sample_seed.data == original_data
        assert sample_seed.meta == original_meta
