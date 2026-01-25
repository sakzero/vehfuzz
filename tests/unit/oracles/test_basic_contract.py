"""
Contract tests for Basic oracle.
"""

from __future__ import annotations

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3] / "src"))

from vehfuzz.core.plugins import create_oracle, load_builtin_plugins
from tests.contracts.test_oracle_contract import OracleContractMixin


class TestBasicOracleContract(OracleContractMixin):
    """Contract tests for Basic oracle."""

    @pytest.fixture(scope="class", autouse=True)
    def setup_plugins(self):
        load_builtin_plugins()

    @pytest.fixture
    def oracle_factory(self):
        def _create():
            return create_oracle("basic", {})
        return _create
