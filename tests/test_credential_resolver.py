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
    assert len(CREDENTIAL_SPECS) >= 15


# ---- Test 9: All builtins are credential-free -----------------------------


def test_all_builtin_specs_have_consistent_ids() -> None:
    """All specs have collector_id matching their dict key."""
    for collector_id, spec in CREDENTIAL_SPECS.items():
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


# ---- Test 13: Optional keys resolved when present --------------------------


async def test_resolve_optional_keys_when_present(
    backend: InMemoryBackend,
    resolver: CredentialResolver,
) -> None:
    """Optional keys are returned when the backend has them."""
    CREDENTIAL_SPECS["test-optional"] = CollectorCredentialSpec(
        collector_id="test-optional",
        required_keys=[],
        optional_keys=["api_key"],
    )
    try:
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.test-optional.api_key",
            value="OPT_VALUE",
        )
        result = await resolver.resolve(TENANT_A, "test-optional")
        assert len(result) == 1
        assert "api_key" in result
        assert result["api_key"].secret_value == "OPT_VALUE"  # noqa: S105
    finally:
        del CREDENTIAL_SPECS["test-optional"]


# ---- Test 14: Optional keys missing do not raise ----------------------------


async def test_resolve_optional_keys_missing_no_error(
    resolver: CredentialResolver,
) -> None:
    """Missing optional keys do not raise CredentialResolutionError."""
    CREDENTIAL_SPECS["test-opt-missing"] = CollectorCredentialSpec(
        collector_id="test-opt-missing",
        required_keys=[],
        optional_keys=["api_key"],
    )
    try:
        result = await resolver.resolve(TENANT_A, "test-opt-missing")
        assert result == {}
    finally:
        del CREDENTIAL_SPECS["test-opt-missing"]


# ---- Test 15: Mixed required + optional keys --------------------------------


async def test_resolve_mixed_required_and_optional(
    backend: InMemoryBackend,
    resolver: CredentialResolver,
) -> None:
    """Required keys are enforced; optional keys are best-effort."""
    CREDENTIAL_SPECS["test-mixed"] = CollectorCredentialSpec(
        collector_id="test-mixed",
        required_keys=["api_key"],
        optional_keys=["webhook_secret"],
    )
    try:
        # Store only the required key, not the optional one.
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.test-mixed.api_key",
            value="REQUIRED_VALUE",
        )
        result = await resolver.resolve(TENANT_A, "test-mixed")
        assert len(result) == 1
        assert "api_key" in result
        assert result["api_key"].secret_value == "REQUIRED_VALUE"  # noqa: S105
        # Optional key is absent — no error, not in result.
        assert "webhook_secret" not in result
    finally:
        del CREDENTIAL_SPECS["test-mixed"]


# ---- Test 16: Missing required key still raises even when optional is present -


async def test_resolve_missing_required_with_optional_present(
    backend: InMemoryBackend,
    resolver: CredentialResolver,
) -> None:
    """Missing required key raises even when optional keys are present."""
    CREDENTIAL_SPECS["test-req-miss"] = CollectorCredentialSpec(
        collector_id="test-req-miss",
        required_keys=["api_key"],
        optional_keys=["webhook_secret"],
    )
    try:
        # Store only the optional key, not the required one.
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.test-req-miss.webhook_secret",
            value="OPT_VALUE",
        )
        with pytest.raises(CredentialResolutionError, match=r"api_key"):
            await resolver.resolve(TENANT_A, "test-req-miss")
    finally:
        del CREDENTIAL_SPECS["test-req-miss"]


# ---- Test 17: Optional keys with key_mapping --------------------------------


async def test_resolve_optional_keys_with_key_mapping(
    backend: InMemoryBackend,
    resolver: CredentialResolver,
) -> None:
    """Optional keys respect key_mapping for backend lookups."""
    CREDENTIAL_SPECS["test-opt-map"] = CollectorCredentialSpec(
        collector_id="test-opt-map",
        required_keys=[],
        optional_keys=["api_key"],
        key_mapping={"api_key": "collector.shared.token"},
    )
    try:
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.shared.token",
            value="MAPPED_OPT",
        )
        result = await resolver.resolve(TENANT_A, "test-opt-map")
        assert len(result) == 1
        assert "api_key" in result
        assert result["api_key"].secret_value == "MAPPED_OPT"  # noqa: S105
    finally:
        del CREDENTIAL_SPECS["test-opt-map"]


# ---- Tests 18+: End-to-end credential chain for real collectors ----------
# These tests verify the full chain from backend storage through CREDENTIAL_SPECS
# key_mapping resolution to the credential dict format that collectors expect.
# They use the REAL CREDENTIAL_SPECS entries (not synthetic test entries) to
# catch mismatches between the credential_resolver and the collector code.


class TestRealCollectorCredentialChain:
    """Verify the full credential chain for each collector that requires credentials.

    For each collector, stores credentials under the backend keys used by
    the credential import API (KNOWN_SLOTS), resolves via CredentialResolver,
    then confirms the returned dict keys match what the collector's
    ``__init__`` method looks up in ``self.config.credentials``.
    """

    async def test_scan_shodan_credential_chain(
        self,
        backend: InMemoryBackend,
        resolver: CredentialResolver,
    ) -> None:
        """scan-shodan: stores under shodan-iwide backend key, resolves as shodan_api_key."""
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.shodan-iwide.api_key",
            value="sk-test-shodan-key",
        )
        result = await resolver.resolve(TENANT_A, "scan-shodan")
        assert len(result) == 1
        assert "shodan_api_key" in result
        assert result["shodan_api_key"].secret_value == "sk-test-shodan-key"  # noqa: S105

    async def test_scan_censys_credential_chain(
        self,
        backend: InMemoryBackend,
        resolver: CredentialResolver,
    ) -> None:
        """scan-censys: stores under scan-censys backend keys, resolves as censys_api_id/secret."""
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.scan-censys.api_id",
            value="test-censys-id",
        )
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.scan-censys.api_secret",
            value="test-censys-secret",
        )
        result = await resolver.resolve(TENANT_A, "scan-censys")
        assert len(result) == 2
        assert "censys_api_id" in result
        assert "censys_api_secret" in result
        assert result["censys_api_id"].secret_value == "test-censys-id"  # noqa: S105
        assert result["censys_api_secret"].secret_value == "test-censys-secret"  # noqa: S105

    async def test_ct_censys_credential_chain(
        self,
        backend: InMemoryBackend,
        resolver: CredentialResolver,
    ) -> None:
        """ct-censys: shares scan-censys backend keys via key_mapping."""
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.scan-censys.api_id",
            value="shared-censys-id",
        )
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.scan-censys.api_secret",
            value="shared-censys-secret",
        )
        result = await resolver.resolve(TENANT_A, "ct-censys")
        assert len(result) == 2
        assert "censys_api_id" in result
        assert "censys_api_secret" in result
        # ct-censys shares the same backend keys as scan-censys
        assert result["censys_api_id"].secret_value == "shared-censys-id"  # noqa: S105

    async def test_scan_binaryedge_credential_chain(
        self,
        backend: InMemoryBackend,
        resolver: CredentialResolver,
    ) -> None:
        """scan-binaryedge: stores under scan-binaryedge backend key."""
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.scan-binaryedge.api_key",
            value="test-be-key",
        )
        result = await resolver.resolve(TENANT_A, "scan-binaryedge")
        assert len(result) == 1
        assert "binaryedge_api_key" in result
        assert result["binaryedge_api_key"].secret_value == "test-be-key"  # noqa: S105

    async def test_dns_chaos_credential_chain(
        self,
        backend: InMemoryBackend,
        resolver: CredentialResolver,
    ) -> None:
        """dns-chaos: optional key resolved when present (key_mapping to collector.dns-chaos.api_key)."""
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.dns-chaos.api_key",
            value="test-chaos-key",
        )
        result = await resolver.resolve(TENANT_A, "dns-chaos")
        assert len(result) == 1
        assert "chaos_api_key" in result
        assert result["chaos_api_key"].secret_value == "test-chaos-key"  # noqa: S105

    async def test_dns_chaos_runs_without_credentials(
        self,
        resolver: CredentialResolver,
    ) -> None:
        """dns-chaos: resolves successfully with empty dict when api_key is absent."""
        result = await resolver.resolve(TENANT_A, "dns-chaos")
        assert result == {}

    async def test_github_exposed_credential_chain(
        self,
        backend: InMemoryBackend,
        resolver: CredentialResolver,
    ) -> None:
        """github-exposed: optional api_key resolved via key_mapping to github-exposed.token."""
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.github-exposed.token",
            value="ghp-test-token",
        )
        result = await resolver.resolve(TENANT_A, "github-exposed")
        assert len(result) == 1
        assert "api_key" in result
        assert result["api_key"].secret_value == "ghp-test-token"  # noqa: S105

    async def test_github_exposed_runs_without_credentials(
        self,
        resolver: CredentialResolver,
    ) -> None:
        """github-exposed: resolves successfully with empty dict when token is absent."""
        result = await resolver.resolve(TENANT_A, "github-exposed")
        assert result == {}

    async def test_dns_passive_history_partial_credentials(
        self,
        backend: InMemoryBackend,
        resolver: CredentialResolver,
    ) -> None:
        """dns-passive-history: resolves with only one of two optional keys."""
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.pdns-securitytrails.api_key",
            value="test-st-key",
        )
        # virustotal key NOT set -- should still resolve without error
        result = await resolver.resolve(TENANT_A, "dns-passive-history")
        assert len(result) == 1
        assert "securitytrails_api_key" in result
        assert "virustotal_api_key" not in result

    async def test_tenant_isolation_across_collectors(
        self,
        backend: InMemoryBackend,
        resolver: CredentialResolver,
    ) -> None:
        """Credentials stored for TENANT_A are not visible to TENANT_B."""
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.shodan-iwide.api_key",
            value="tenant-a-key",
        )
        # TENANT_B should not see TENANT_A's credential
        with pytest.raises(CredentialResolutionError, match="Missing credentials"):
            await resolver.resolve(TENANT_B, "scan-shodan")

    async def test_credential_keys_match_collector_expectations(
        self,
        backend: InMemoryBackend,
        resolver: CredentialResolver,
    ) -> None:
        """Resolved credential dict keys match what collectors look up in config.credentials.

        This test cross-references the CREDENTIAL_SPECS key names with the
        actual credential lookup keys used in each collector's __init__ method.
        Covers both required and optional credentials.
        """
        # Store all credentials
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.shodan-iwide.api_key",
            value="v",
        )
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.scan-censys.api_id",
            value="v",
        )
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.scan-censys.api_secret",
            value="v",
        )
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.scan-binaryedge.api_key",
            value="v",
        )
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.dns-chaos.api_key",
            value="v",
        )
        await backend.set(
            tenant_id=TENANT_A,
            key="collector.github-exposed.token",
            value="v",
        )

        # These are the exact keys each collector uses in its __init__:
        expected_keys = {
            "scan-shodan": {"shodan_api_key"},
            "scan-censys": {"censys_api_id", "censys_api_secret"},
            "ct-censys": {"censys_api_id", "censys_api_secret"},
            "scan-binaryedge": {"binaryedge_api_key"},
            "dns-chaos": {"chaos_api_key"},  # optional, via key_mapping
            "github-exposed": {"api_key"},  # optional, via key_mapping
        }

        for collector_id, keys in expected_keys.items():
            result = await resolver.resolve(TENANT_A, collector_id)
            assert set(result.keys()) == keys, (
                f"Key mismatch for {collector_id}: "
                f"expected {keys}, got {set(result.keys())}"
            )
