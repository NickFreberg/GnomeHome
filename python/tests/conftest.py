"""Shared test fixtures.

Every test works inside pytest's ``tmp_path``. Nothing touches the real
config, the real database, or the network.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from helpers import EXAMPLE_PROTECTED, write_config


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    """A config file copied from the example, plus the example protected list next to it."""
    path = write_config(tmp_path)
    if EXAMPLE_PROTECTED.exists():
        shutil.copy(EXAMPLE_PROTECTED, path.parent / "protected_assets.yaml")
    return path
