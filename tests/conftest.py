"""Shared pytest fixtures for the EXPOSE test suite."""
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Absolute path to the repository root."""
    return REPO_ROOT


@pytest.fixture(scope="session")
def schemas_dir(repo_root: Path) -> Path:
    """Absolute path to the JSON Schemas directory."""
    return repo_root / "schemas"


@pytest.fixture(scope="session")
def examples_dir(repo_root: Path) -> Path:
    """Absolute path to the examples directory."""
    return repo_root / "examples"
