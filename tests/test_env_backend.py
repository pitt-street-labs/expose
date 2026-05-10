"""Tests for the environment-variable secrets backend (issue #8).

Coverage:

1. get_secret reads from the derived env var
2. get_secret raises SecretNotFoundError for missing env var
3. set_secret sets the env var
4. delete_secret removes the env var
5. list_keys returns matching vars for a tenant
6. Key convention: uppercased, hyphens replaced with underscores
7. Tenant isolation: tenant A's vars are invisible to tenant B
8. delete is idempotent (removing an absent var is a no-op)
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from uuid import UUID

import pytest

from expose.secrets.backend import SecretNotFoundError
from expose.secrets.env_backend import EnvSecretsBackend, _env_key

TENANT_A = UUID("018f1f00-0000-7000-8000-00000000A001")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000B002")


@pytest.fixture
def backend() -> EnvSecretsBackend:
    """Fresh backend instance per test."""
    return EnvSecretsBackend()


@pytest.fixture(autouse=True)
def _clean_env() -> Iterator[None]:
    """Remove any EXPOSE_SECRET_* vars after each test to prevent bleed."""
    yield
    to_remove = [k for k in os.environ if k.startswith("EXPOSE_SECRET_")]
    for k in to_remove:
        del os.environ[k]


# ------------------------------------------------------------------
# 1. get_secret from env var
# ------------------------------------------------------------------


async def test_get_secret_from_env(backend: EnvSecretsBackend) -> None:
    """get returns the value of the derived environment variable."""
    env_name = _env_key(TENANT_A, "api_key")
    os.environ[env_name] = "sk-from-env"

    result = await backend.get(tenant_id=TENANT_A, key="api_key")
    assert result == "sk-from-env"


# ------------------------------------------------------------------
# 2. get_secret missing → SecretNotFoundError
# ------------------------------------------------------------------


async def test_get_secret_missing(backend: EnvSecretsBackend) -> None:
    """get raises SecretNotFoundError when the env var is not set."""
    with pytest.raises(SecretNotFoundError):
        await backend.get(tenant_id=TENANT_A, key="nonexistent")
    # Also a KeyError per the ABC contract.
    with pytest.raises(KeyError):
        await backend.get(tenant_id=TENANT_A, key="nonexistent")


# ------------------------------------------------------------------
# 3. set_secret sets env var
# ------------------------------------------------------------------


async def test_set_secret(backend: EnvSecretsBackend) -> None:
    """set writes the value into the process environment."""
    await backend.set(tenant_id=TENANT_A, key="api_key", value="sk-set-test")

    env_name = _env_key(TENANT_A, "api_key")
    assert os.environ[env_name] == "sk-set-test"


# ------------------------------------------------------------------
# 4. delete_secret removes env var
# ------------------------------------------------------------------


async def test_delete_secret(backend: EnvSecretsBackend) -> None:
    """delete removes the env var; subsequent get raises."""
    await backend.set(tenant_id=TENANT_A, key="api_key", value="to-delete")
    await backend.delete(tenant_id=TENANT_A, key="api_key")

    env_name = _env_key(TENANT_A, "api_key")
    assert env_name not in os.environ

    with pytest.raises(SecretNotFoundError):
        await backend.get(tenant_id=TENANT_A, key="api_key")


# ------------------------------------------------------------------
# 5. list_keys returns matching vars
# ------------------------------------------------------------------


async def test_list_keys(backend: EnvSecretsBackend) -> None:
    """list_keys scans os.environ for tenant-prefixed vars and returns sorted keys."""
    await backend.set(tenant_id=TENANT_A, key="zebra_key", value="z")
    await backend.set(tenant_id=TENANT_A, key="alpha_key", value="a")
    await backend.set(tenant_id=TENANT_A, key="middle_key", value="m")

    keys = await backend.list_keys(tenant_id=TENANT_A)
    assert list(keys) == ["alpha_key", "middle_key", "zebra_key"]


# ------------------------------------------------------------------
# 6. Key convention — uppercased, hyphens to underscores
# ------------------------------------------------------------------


def test_key_convention() -> None:
    """_env_key uppercases and replaces hyphens with underscores."""
    result = _env_key(TENANT_A, "shodan-api-key")
    # The tenant UUID has hyphens → underscores; the key has hyphens → underscores.
    assert "-" not in result
    assert result == result.upper()
    assert result.startswith("EXPOSE_SECRET_")
    assert "SHODAN_API_KEY" in result


def test_key_convention_roundtrip() -> None:
    """Two distinct logical keys produce distinct env var names."""
    key_a = _env_key(TENANT_A, "alpha")
    key_b = _env_key(TENANT_A, "beta")
    assert key_a != key_b


# ------------------------------------------------------------------
# 7. Tenant isolation
# ------------------------------------------------------------------


async def test_tenant_isolation(backend: EnvSecretsBackend) -> None:
    """Tenant A's secrets are invisible to tenant B."""
    await backend.set(tenant_id=TENANT_A, key="api_key", value="A_VALUE")

    with pytest.raises(SecretNotFoundError):
        await backend.get(tenant_id=TENANT_B, key="api_key")

    # list_keys for B must not include A's keys.
    b_keys = await backend.list_keys(tenant_id=TENANT_B)
    assert list(b_keys) == []

    # Both tenants can hold the same logical key independently.
    await backend.set(tenant_id=TENANT_B, key="api_key", value="B_VALUE")
    assert await backend.get(tenant_id=TENANT_A, key="api_key") == "A_VALUE"
    assert await backend.get(tenant_id=TENANT_B, key="api_key") == "B_VALUE"


# ------------------------------------------------------------------
# 8. delete is idempotent
# ------------------------------------------------------------------


async def test_delete_idempotent(backend: EnvSecretsBackend) -> None:
    """Deleting an absent key is a no-op (not an error)."""
    # Must not raise.
    await backend.delete(tenant_id=TENANT_A, key="never_set")

    # Set, delete, re-delete — all succeed.
    await backend.set(tenant_id=TENANT_A, key="temp", value="x")
    await backend.delete(tenant_id=TENANT_A, key="temp")
    await backend.delete(tenant_id=TENANT_A, key="temp")


# ------------------------------------------------------------------
# 9. repr does not leak values
# ------------------------------------------------------------------


def test_repr_no_leak() -> None:
    """repr shows only the type name; no env var names or values."""
    backend = EnvSecretsBackend()
    assert repr(backend) == "EnvSecretsBackend()"


# ------------------------------------------------------------------
# 10. set overwrites existing value
# ------------------------------------------------------------------


async def test_set_overwrites(backend: EnvSecretsBackend) -> None:
    """A second set overwrites the first value."""
    await backend.set(tenant_id=TENANT_A, key="api_key", value="OLD")
    await backend.set(tenant_id=TENANT_A, key="api_key", value="NEW")
    assert await backend.get(tenant_id=TENANT_A, key="api_key") == "NEW"
