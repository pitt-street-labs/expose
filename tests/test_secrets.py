"""Tests for the per-tenant secrets backend abstraction (W1.F).

Coverage:

1. set/get round-trip returns the value verbatim.
2. get on an absent key raises :class:`SecretNotFoundError` (and
   :exc:`KeyError`).
3. set is overwrite-on-conflict so importers and rotation flows are idempotent.
4. Cross-tenant isolation: tenant A's key is invisible to tenant B (per
   ADR-007 multi-tenancy).
5. ``__repr__`` does not leak tenant IDs, key names, or values — only counts.
6. ``list_keys`` is per-tenant scoped.
7. ``delete`` is idempotent — deleting an absent key is a no-op, not an error.

These tests use the in-memory implementation as the concrete subject. When
production-hardening lands a Vault / KMS backend, the same tests will be
parametrized over both implementations to confirm the contract.
"""

from __future__ import annotations

from uuid import UUID

import pytest

from expose.secrets import InMemoryBackend, SecretNotFoundError

# Synthetic tenant UUIDs reused across the suite. The bit pattern matches
# tests/test_tenant_isolation.py so the two suites can be cross-referenced
# when investigating cross-tenant regressions.
TENANT_A = UUID("018f1f00-0000-7000-8000-00000000A001")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000B002")


@pytest.fixture
def backend() -> InMemoryBackend:
    """Fresh in-memory backend per test (no cross-test bleed)."""
    return InMemoryBackend()


async def test_set_then_get_returns_value(backend: InMemoryBackend) -> None:
    """A value stored under (tenant, key) is returned verbatim by get."""
    await backend.set(tenant_id=TENANT_A, key="collector.shodan-iwide.api_key", value="SHODAN_001")
    got = await backend.get(tenant_id=TENANT_A, key="collector.shodan-iwide.api_key")
    assert got == "SHODAN_001"


async def test_get_missing_raises(backend: InMemoryBackend) -> None:
    """get on an absent key raises SecretNotFoundError (also a KeyError)."""
    with pytest.raises(SecretNotFoundError):
        await backend.get(tenant_id=TENANT_A, key="collector.never-set.api_key")
    # SecretNotFoundError must subclass KeyError so legacy ``except KeyError``
    # paths in being-ported collector code keep working.
    with pytest.raises(KeyError):
        await backend.get(tenant_id=TENANT_A, key="collector.never-set.api_key")


async def test_set_overwrites(backend: InMemoryBackend) -> None:
    """A second set overwrites the first; importer re-runs are idempotent."""
    await backend.set(tenant_id=TENANT_A, key="collector.shodan-iwide.api_key", value="OLD")
    await backend.set(tenant_id=TENANT_A, key="collector.shodan-iwide.api_key", value="NEW")
    assert await backend.get(tenant_id=TENANT_A, key="collector.shodan-iwide.api_key") == "NEW"


async def test_tenant_isolation(backend: InMemoryBackend) -> None:
    """A key set for tenant A is invisible to tenant B (ADR-007)."""
    await backend.set(tenant_id=TENANT_A, key="collector.shodan-iwide.api_key", value="A_KEY")
    # Same key on B is unset — must raise, not return A's value.
    with pytest.raises(SecretNotFoundError):
        await backend.get(tenant_id=TENANT_B, key="collector.shodan-iwide.api_key")
    # B may set its own value under the same logical key; A's value must not
    # be perturbed.
    await backend.set(tenant_id=TENANT_B, key="collector.shodan-iwide.api_key", value="B_KEY")
    assert await backend.get(tenant_id=TENANT_A, key="collector.shodan-iwide.api_key") == "A_KEY"
    assert await backend.get(tenant_id=TENANT_B, key="collector.shodan-iwide.api_key") == "B_KEY"
    # ``list_keys`` is also per-tenant.
    assert await backend.list_keys(tenant_id=TENANT_A) == ["collector.shodan-iwide.api_key"]
    assert await backend.list_keys(tenant_id=TENANT_B) == ["collector.shodan-iwide.api_key"]


async def test_repr_does_not_leak_values(backend: InMemoryBackend) -> None:
    """repr renders only structural counts; never tenant_id / key / value."""
    # ruff S105 false-positive: variable name carries "secret" but the literal
    # is a TEST sentinel, not a real credential. Same for ``secret_key`` below
    # — that's the storage *key* (logical address), not the secret material.
    secret_value = "ULTRA_SECRET_TESTKEY_VALUE_DO_NOT_LEAK"  # noqa: S105
    secret_key = "collector.shodan-iwide.api_key"  # noqa: S105
    await backend.set(tenant_id=TENANT_A, key=secret_key, value=secret_value)
    await backend.set(tenant_id=TENANT_A, key="collector.other.api_key", value="OTHER")
    await backend.set(tenant_id=TENANT_B, key=secret_key, value="B_VALUE")

    rendered = repr(backend)

    # Counts must appear (proves the repr is informative).
    assert "tenants=2" in rendered
    assert "total_keys=3" in rendered

    # Values must NEVER appear.
    assert secret_value not in rendered
    assert "OTHER" not in rendered
    assert "B_VALUE" not in rendered

    # Key names must NOT appear (an attacker grepping logs for "api_key" should
    # find nothing).
    assert secret_key not in rendered
    assert "api_key" not in rendered

    # Tenant UUIDs must NOT appear.
    assert str(TENANT_A) not in rendered
    assert str(TENANT_B) not in rendered


async def test_list_keys_per_tenant(backend: InMemoryBackend) -> None:
    """list_keys returns the keys for the named tenant only — sorted."""
    await backend.set(tenant_id=TENANT_A, key="collector.shodan-iwide.api_key", value="X")
    await backend.set(tenant_id=TENANT_A, key="collector.zoom.api_key", value="Y")
    await backend.set(tenant_id=TENANT_A, key="collector.alpha.api_key", value="Z")
    await backend.set(tenant_id=TENANT_B, key="collector.beta.api_key", value="W")

    a_keys = list(await backend.list_keys(tenant_id=TENANT_A))
    b_keys = list(await backend.list_keys(tenant_id=TENANT_B))

    assert a_keys == [
        "collector.alpha.api_key",
        "collector.shodan-iwide.api_key",
        "collector.zoom.api_key",
    ]
    assert b_keys == ["collector.beta.api_key"]
    assert "collector.beta.api_key" not in a_keys
    assert "collector.shodan-iwide.api_key" not in b_keys


async def test_delete_idempotent(backend: InMemoryBackend) -> None:
    """delete is idempotent: deleting an absent key is a no-op (not an error)."""
    # Deleting before any set succeeds silently.
    await backend.delete(tenant_id=TENANT_A, key="collector.shodan-iwide.api_key")

    # Set, delete, re-delete — all succeed.
    await backend.set(tenant_id=TENANT_A, key="collector.shodan-iwide.api_key", value="X")
    await backend.delete(tenant_id=TENANT_A, key="collector.shodan-iwide.api_key")
    await backend.delete(tenant_id=TENANT_A, key="collector.shodan-iwide.api_key")

    # And the underlying state is gone — get raises after delete.
    with pytest.raises(SecretNotFoundError):
        await backend.get(tenant_id=TENANT_A, key="collector.shodan-iwide.api_key")

    # Cross-tenant: deleting tenant B's nonexistent key does not affect A.
    await backend.set(tenant_id=TENANT_A, key="collector.alpha.api_key", value="A_ALPHA")
    await backend.delete(tenant_id=TENANT_B, key="collector.alpha.api_key")
    assert await backend.get(tenant_id=TENANT_A, key="collector.alpha.api_key") == "A_ALPHA"
