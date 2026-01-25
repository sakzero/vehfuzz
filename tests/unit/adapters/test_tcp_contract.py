"""
Contract tests for TCP adapter.
"""

from __future__ import annotations

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parents[3] / "src"))

from vehfuzz.core.plugins import create_adapter, load_builtin_plugins
from tests.contracts.test_adapter_contract import AdapterContractMixin


class TestTcpAdapterContract(AdapterContractMixin):
    """Contract tests for TCP adapter."""

    @pytest.fixture(scope="class", autouse=True)
    def setup_plugins(self):
        load_builtin_plugins()

    @pytest.fixture
    def adapter_factory(self):
        def _create():
            return create_adapter("tcp", {
                "host": "127.0.0.1",
                "port": 9999,
                "connect_timeout_s": 1.0,
            })
        return _create

    @pytest.fixture
    def can_connect(self):
        # TCP requires a server to be running
        return False
