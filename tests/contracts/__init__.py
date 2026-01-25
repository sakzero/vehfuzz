"""
Contract tests package.

This package contains contract test mixins that all plugin implementations
must pass to ensure interface compliance.
"""

from tests.contracts.test_adapter_contract import AdapterContractMixin
from tests.contracts.test_protocol_contract import ProtocolContractMixin
from tests.contracts.test_oracle_contract import OracleContractMixin

__all__ = [
    "AdapterContractMixin",
    "ProtocolContractMixin",
    "OracleContractMixin",
]
