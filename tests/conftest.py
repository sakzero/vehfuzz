"""
Pytest configuration and shared fixtures.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


# Ensure src is in path
@pytest.fixture(scope="session", autouse=True)
def setup_path():
    project_root = Path(__file__).resolve().parents[0].parent
    src_dir = project_root / "src"
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))


@pytest.fixture(scope="session")
def load_plugins():
    """Load all builtin plugins once per test session."""
    from vehfuzz.core.plugins import load_builtin_plugins
    load_builtin_plugins()


@pytest.fixture
def message_factory():
    """Factory for creating test messages."""
    from vehfuzz.core.plugins import Message

    def _create(data: bytes, **meta) -> Message:
        return Message(data=data, meta=meta)

    return _create
