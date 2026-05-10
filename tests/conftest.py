"""Shared pytest fixtures for the EXPOSE test suite.

Two fixture families:

- **Path fixtures** (`repo_root`, `schemas_dir`, `examples_dir`) — always
  available; used by schema-sync and similar offline tests.
- **Integration fixtures** (`pg_container`, `nats_container`) — session-scoped
  testcontainers handles for the real Postgres + NATS JetStream services that
  Wave 1 / Wave 3 / Wave 4 integration tests require. Both skip cleanly if
  Docker is not reachable, so unit-only test runs (CI lint job, lint-only
  developer loop) remain unaffected.
"""
from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

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


# === Integration-test infrastructure (testcontainers) =======================
# Both fixtures skip rather than fail if Docker is unavailable. Mark consuming
# tests with `@pytest.mark.integration` so the unit-test loop can `-m "not
# integration"` past them.


def _docker_available() -> bool:
    """Return True iff a `docker` CLI exists on PATH.

    Cheaper than actually probing the socket — testcontainers will surface a
    sharper error message itself if the socket is present but unreachable.
    """
    return shutil.which("docker") is not None


@pytest.fixture(scope="session")
def pg_container() -> Iterator[Any]:
    """Session-scoped Postgres testcontainer for integration tests.

    Yields a ``PostgresContainer`` instance. Consumers call
    ``.get_connection_url()`` and pass it through ``EXPOSE_DB_*`` env vars or
    directly to an async engine factory.

    Skipped if Docker is not available so unit-test runs stay green.
    """
    if not _docker_available():
        pytest.skip("Docker not available; testcontainers Postgres unavailable.")
    from testcontainers.postgres import PostgresContainer  # noqa: PLC0415

    with PostgresContainer("postgres:16-alpine") as container:
        yield container


@pytest.fixture(scope="session")
def nats_container() -> Iterator[Any]:
    """Session-scoped NATS JetStream testcontainer for integration tests.

    JetStream is enabled via the ``-js`` flag (``with_command``). Consumers
    call ``.nats_uri()`` (or equivalent on the testcontainers helper) for the
    connection URL.

    Skipped if Docker is not available, or if the optional
    ``testcontainers[nats]`` extra is not installed.
    """
    if not _docker_available():
        pytest.skip("Docker not available; testcontainers NATS unavailable.")
    try:
        from testcontainers.nats import NatsContainer  # noqa: PLC0415
    except ImportError:
        pytest.skip("testcontainers[nats] extra not installed.")

    container = NatsContainer().with_command("-js")
    container.start()
    try:
        yield container
    finally:
        container.stop()
