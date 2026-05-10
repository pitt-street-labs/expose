"""Tests for per-tenant collector credential resolution (advances #25).

Coverage:

1. Resolver returns empty dict for collectors with no required keys (ct-crtsh).
2. Resolver returns empty dict for unknown collector_id.
3. Resolver fetches credentials from backend for a collector that needs them.
4. Missing required key raises CredentialResolutionError.
5. Multiple required keys all resolved correctly.
6. Partial resolution (one key found, one missing) raises with missing key listed.
7. CollectorCredentialSpec validates correctly (frozen, extra=forbid).
8. CREDENTIAL_SPECS has entries for all 5 builtin collectors.
9. All builtin collector specs have empty required_keys (credential-free).
10. CredentialResolutionError has descriptive message.
11. Backend key convention encodes collector_id and key_name.
12. Resolver does not cache across calls (fresh fetch each time).

Uses ``InMemoryBackend`` directly — no mocking needed.
"""

from __future__ import annotations

from uuid import UUID

import pytest
from pydantic import ValidationError

from expose.collectors.base import CollectorCredential
from expose.pipeline.credential_resolver import (
    CREDENTIAL_SPECS,
    CollectorCredentialSpec,
    CredentialResolutionError,
    CredentialResolver,
)
from expose.secrets.memory_backend import InMemoryBackend

# Synthetic tenant UUIDs — same bit-pattern as test_secrets.py / test_tenant_isolation.py
TENANT_A = UUID("018f1f00-0000-7000-8000-00000000A001")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000B002")

# The 5 builtin collectors from the CREDENTIAL_SPECS registry.
BUILTIN_COLLECTORS = [
    "ct-crtsh",
    "cloud-ranges",
    "rdap-whois",
    "active-dns-resolve",
    "active-http-fingerprint",
]


@pytest.fixture()
def backend() -> InMemoryBackend:
    """Fresh in-memory backend per test."""
    return InMemoryBackend()


@pytest.fixture()
def resolver(backend: InMemoryBackend) -> CredentialResolver:
    """Resolver wired to the test backend."""
    return CredentialResolver(backend)


# ---- Test 1: Empty dict for credential-free collectors ---------------------


@pytest.mark.parametrize("collector_id", BUILTIN_COLLECTORS)
async def test_resolve_returns_empty_for_credential_free_collectors(
    resolver: CredentialResolver,
    collector_id: str,
) -> None:
    """Collectors with no required_keys resolve to an empty credentials dict."""
    result = await resolver.resolve(TENANT_A, collector_id)
    assert result == {}


# ---- Test 2: Empty dict for unknown collector_id ---------------------------


async def test_resolve_returns_empty_for_unknown_collector(
    resolver: CredentialResolver,
) -> None:
    """An unknown collector_id (not in CREDENTIAL_SPECS) is treated as credential-free."""
    result = await resolver.resolve(TENANT_A, "nonexistent-collector-xyz")
    assert result == {}


# ---- Test 3: Fetches credentials from backend -----------------------------


async def test_resolve_fetches_single_credential(
    backend: InMemoryBackend,
    resolver: CredentialResolver,
) -> None:
    """Resolver fetches a required credential from the secrets backend."""
    # Temporarily register a spec that needs one key.
    CREDENTIAL_SPECS["test-shodan"] = CollectorCredentialSpec(
        collector_id="test-shodan",
        required_keys=["api_key"],
    )
    try:
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.test-shodan.api_key",
            value="SHODAN_KEY_123",
        )
        result = await resolver.resolve(TENANT_A, "test-shodan")
        assert len(result) == 1
        assert "api_key" in result
        assert isinstance(result["api_key"], CollectorCredential)
        assert result["api_key"].name == "api_key"
        assert result["api_key"].secret_value == "SHODAN_KEY_123"  # noqa: S105
    finally:
        del CREDENTIAL_SPECS["test-shodan"]


# ---- Test 4: Missing required key raises ----------------------------------


async def test_resolve_raises_on_missing_required_key(
    resolver: CredentialResolver,
) -> None:
    """Missing required key raises CredentialResolutionError."""
    CREDENTIAL_SPECS["test-missing"] = CollectorCredentialSpec(
        collector_id="test-missing",
        required_keys=["api_key"],
    )
    try:
        with pytest.raises(CredentialResolutionError, match=r"Missing credentials"):
            await resolver.resolve(TENANT_A, "test-missing")
    finally:
        del CREDENTIAL_SPECS["test-missing"]


# ---- Test 5: Multiple required keys all resolved --------------------------


async def test_resolve_multiple_keys(
    backend: InMemoryBackend,
    resolver: CredentialResolver,
) -> None:
    """All required keys are fetched when multiple are declared."""
    CREDENTIAL_SPECS["test-oauth"] = CollectorCredentialSpec(
        collector_id="test-oauth",
        required_keys=["client_id", "client_secret"],
    )
    try:
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.test-oauth.client_id",
            value="ID_ABC",
        )
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.test-oauth.client_secret",
            value="SECRET_XYZ",
        )
        result = await resolver.resolve(TENANT_A, "test-oauth")
        assert len(result) == 2
        assert result["client_id"].name == "client_id"
        assert result["client_id"].secret_value == "ID_ABC"  # noqa: S105
        assert result["client_secret"].name == "client_secret"
        assert result["client_secret"].secret_value == "SECRET_XYZ"  # noqa: S105
    finally:
        del CREDENTIAL_SPECS["test-oauth"]


# ---- Test 6: Partial resolution raises with missing key listed -------------


async def test_resolve_partial_raises_with_missing_listed(
    backend: InMemoryBackend,
    resolver: CredentialResolver,
) -> None:
    """When one key is found but another is missing, error lists the missing key."""
    CREDENTIAL_SPECS["test-partial"] = CollectorCredentialSpec(
        collector_id="test-partial",
        required_keys=["client_id", "client_secret"],
    )
    try:
        # Only set one of the two required keys.
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.test-partial.client_id",
            value="ID_FOUND",
        )
        with pytest.raises(CredentialResolutionError, match=r"client_secret") as exc_info:
            await resolver.resolve(TENANT_A, "test-partial")
        # The found key should NOT appear in the error message.
        assert "client_id" not in str(exc_info.value)
    finally:
        del CREDENTIAL_SPECS["test-partial"]


# ---- Test 7: CollectorCredentialSpec validation ----------------------------


def test_credential_spec_validates_correctly() -> None:
    """CollectorCredentialSpec enforces frozen + extra=forbid."""
    spec = CollectorCredentialSpec(
        collector_id="test-spec",
        required_keys=["api_key"],
    )
    assert spec.collector_id == "test-spec"
    assert spec.required_keys == ["api_key"]

    # Frozen — assignment raises.
    with pytest.raises(ValidationError):
        spec.collector_id = "mutated"  # type: ignore[misc]

    # Extra fields forbidden.
    with pytest.raises(ValidationError):
        CollectorCredentialSpec(
            collector_id="test-extra",
            required_keys=[],
            unexpected_field="boom",  # type: ignore[call-arg]
        )

    # Empty collector_id rejected (min_length=1).
    with pytest.raises(ValidationError):
        CollectorCredentialSpec(collector_id="", required_keys=[])


# ---- Test 8: CREDENTIAL_SPECS has entries for all 5 builtins ---------------


def test_credential_specs_has_all_builtin_entries() -> None:
    """CREDENTIAL_SPECS contains an entry for each of the 5 builtin collectors."""
    for collector_id in BUILTIN_COLLECTORS:
        assert collector_id in CREDENTIAL_SPECS, (
            f"Missing CREDENTIAL_SPECS entry for builtin collector {collector_id!r}"
        )
    # Exactly 5 entries — no stale leftovers.
    assert len(CREDENTIAL_SPECS) == 5


# ---- Test 9: All builtins are credential-free -----------------------------


def test_all_builtin_specs_have_empty_required_keys() -> None:
    """All builtin collector specs declare empty required_keys (no credentials needed)."""
    for collector_id, spec in CREDENTIAL_SPECS.items():
        assert spec.required_keys == [], (
            f"Builtin collector {collector_id!r} unexpectedly requires keys: "
            f"{spec.required_keys}"
        )
        assert spec.collector_id == collector_id, (
            f"Spec collector_id mismatch: key={collector_id!r}, "
            f"spec.collector_id={spec.collector_id!r}"
        )


# ---- Test 10: Error message is descriptive --------------------------------


async def test_credential_resolution_error_message(
    resolver: CredentialResolver,
) -> None:
    """CredentialResolutionError includes collector_id, tenant, and missing keys."""
    CREDENTIAL_SPECS["test-msg"] = CollectorCredentialSpec(
        collector_id="test-msg",
        required_keys=["api_key", "webhook_secret"],
    )
    try:
        with pytest.raises(CredentialResolutionError) as exc_info:
            await resolver.resolve(TENANT_A, "test-msg")
        msg = str(exc_info.value)
        assert "test-msg" in msg
        assert str(TENANT_A) in msg
        assert "api_key" in msg
        assert "webhook_secret" in msg
    finally:
        del CREDENTIAL_SPECS["test-msg"]


# ---- Test 11: Backend key convention encodes collector_id + key_name -------


async def test_backend_key_convention(
    backend: InMemoryBackend,
    resolver: CredentialResolver,
) -> None:
    """Secrets backend key follows ``collector.{collector_id}.{key_name}`` convention."""
    CREDENTIAL_SPECS["test-conv"] = CollectorCredentialSpec(
        collector_id="test-conv",
        required_keys=["api_key"],
    )
    try:
        # Store under the expected convention key.
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.test-conv.api_key",
            value="CONV_VALUE",
        )
        result = await resolver.resolve(TENANT_A, "test-conv")
        assert result["api_key"].secret_value == "CONV_VALUE"  # noqa: S105

        # Verify the resolver does NOT find keys under a different convention.
        await backend.set(
            tenant_id=TENANT_B,
            key="test-conv.api_key",  # wrong convention — no "collector." prefix
            value="WRONG_CONV",
        )
        CREDENTIAL_SPECS["test-conv-b"] = CollectorCredentialSpec(
            collector_id="test-conv-b",
            required_keys=["api_key"],
        )
        # Tenant B has no key under the correct convention; should raise.
        with pytest.raises(CredentialResolutionError):
            await resolver.resolve(TENANT_B, "test-conv-b")
    finally:
        CREDENTIAL_SPECS.pop("test-conv", None)
        CREDENTIAL_SPECS.pop("test-conv-b", None)


# ---- Test 12: Resolver does not cache — fresh fetch each call ---------------


async def test_resolver_does_not_cache(
    backend: InMemoryBackend,
    resolver: CredentialResolver,
) -> None:
    """Each resolve() call fetches fresh values from the backend (no caching)."""
    CREDENTIAL_SPECS["test-nocache"] = CollectorCredentialSpec(
        collector_id="test-nocache",
        required_keys=["api_key"],
    )
    try:
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.test-nocache.api_key",
            value="FIRST_VALUE",
        )
        first = await resolver.resolve(TENANT_A, "test-nocache")
        assert first["api_key"].secret_value == "FIRST_VALUE"  # noqa: S105

        # Rotate the key in the backend.
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.test-nocache.api_key",
            value="ROTATED_VALUE",
        )
        second = await resolver.resolve(TENANT_A, "test-nocache")
        assert second["api_key"].secret_value == "ROTATED_VALUE"  # noqa: S105
    finally:
        del CREDENTIAL_SPECS["test-nocache"]
