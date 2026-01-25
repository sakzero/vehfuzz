"""
Public parsers module.

This module contains protocol-agnostic parsing functions that can be
shared across multiple protocol implementations without creating
circular dependencies.

Design principle:
- All parsers are pure functions (no state, no side effects)
- Protocol plugins depend on core/parsers, never on each other
- This enables parallel development of different protocols
"""

from vehfuzz.core.parsers.uds_parser import parse_uds_payload
from vehfuzz.core.parsers.doip_parser import parse_doip_header

__all__ = [
    "parse_uds_payload",
    "parse_doip_header",
]
