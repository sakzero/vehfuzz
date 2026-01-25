"""
Contract tests for CAN protocol.
"""

from __future__ import annotations

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3] / "src"))

from vehfuzz.core.plugins import Message, create_protocol, load_builtin_plugins
from tests.contracts.test_protocol_contract import ProtocolContractMixin


class TestCanProtocolContract(ProtocolContractMixin):
    """Contract tests for CAN protocol."""

    @pytest.fixture(scope="class", autouse=True)
    def setup_plugins(self):
        load_builtin_plugins()

    @pytest.fixture
    def protocol_factory(self):
        def _create():
            return create_protocol("can", {"can_id": 0x7DF})
        return _create

    @pytest.fixture
    def sample_seed(self):
        return Message(
            data=b"\x02\x10\x01",
            meta={"can_id": 0x7DF, "is_extended": False, "is_fd": False}
        )

    @pytest.fixture
    def sample_mutated(self):
        return b"\x02\x10\x03"


class TestUdsProtocolContract(ProtocolContractMixin):
    """Contract tests for UDS protocol."""

    @pytest.fixture(scope="class", autouse=True)
    def setup_plugins(self):
        load_builtin_plugins()

    @pytest.fixture
    def protocol_factory(self):
        def _create():
            return create_protocol("uds", {"max_len": 64})
        return _create

    @pytest.fixture
    def sample_seed(self):
        return Message(data=b"\x10\x01", meta={})

    @pytest.fixture
    def sample_mutated(self):
        return b"\x10\x03"


class TestDoipProtocolContract(ProtocolContractMixin):
    """Contract tests for DoIP protocol."""

    @pytest.fixture(scope="class", autouse=True)
    def setup_plugins(self):
        load_builtin_plugins()

    @pytest.fixture
    def protocol_factory(self):
        def _create():
            return create_protocol("doip", {
                "version": 0x02,
                "payload_type": 0x8001,
            })
        return _create

    @pytest.fixture
    def sample_seed(self):
        return Message(data=b"", meta={})

    @pytest.fixture
    def sample_mutated(self):
        # src_addr + dst_addr + UDS payload
        return b"\x0E\x00\x00\x01\x10\x01"


class TestSomeipProtocolContract(ProtocolContractMixin):
    """Contract tests for SOME/IP protocol."""

    @pytest.fixture(scope="class", autouse=True)
    def setup_plugins(self):
        load_builtin_plugins()

    @pytest.fixture
    def protocol_factory(self):
        def _create():
            return create_protocol("someip", {
                "service_id": 0x1234,
                "method_id": 0x0001,
                "client_id": 0x0001,
                "session_id": 0x0001,
            })
        return _create

    @pytest.fixture
    def sample_seed(self):
        return Message(data=b"", meta={})

    @pytest.fixture
    def sample_mutated(self):
        return b"\x01\x02\x03\x04"
