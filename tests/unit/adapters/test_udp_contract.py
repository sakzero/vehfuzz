"""
Contract tests for UDP adapter.
"""

from __future__ import annotations

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3] / "src"))

from vehfuzz.core.plugins import create_adapter, load_builtin_plugins
from tests.contracts.test_adapter_contract import AdapterContractMixin


class TestUdpAdapterContract(AdapterContractMixin):
    """Contract tests for UDP adapter."""

    @pytest.fixture(scope="class", autouse=True)
    def setup_plugins(self):
        load_builtin_plugins()

    @pytest.fixture
    def adapter_factory(self):
        def _create():
            return create_adapter("udp", {
                "host": "127.0.0.1",
                "port": 9999,
            })
        return _create

    @pytest.fixture
    def can_connect(self):
        # UDP is connectionless, but we still need a receiver
        return False
