"""Tests for egress provenance flag (issue #39).

Coverage:

1. DirectEgressProfile.is_anonymizing returns False.
2. Socks5EgressProfile.is_anonymizing returns True when dns_through_proxy=True.
3. Socks5EgressProfile.is_anonymizing returns False when dns_through_proxy=False.
4. WireguardEgressProfile.is_anonymizing returns False.
5. HttpConnectEgressProfile.is_anonymizing returns False.
6. EgressHealthCheck includes egress_anonymized field (default False).
7. EgressHealthCheck with egress_anonymized=True serializes correctly.
8. DispatchResult includes egress_anonymized field (default False).
9. Dispatcher sets egress_anonymized=True when egress profile is anonymizing.
10. Dispatcher sets egress_anonymized=False when egress profile is not anonymizing.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import UUID

import pytest

from expose.collectors.base import (
    Collector,
    CollectorHealthCheck,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import CollectorRegistry
from expose.collectors.tiers import CollectorTier, TenantAuthorizationScope
from expose.egress import (
    DirectEgressProfile,
    HttpConnectEgressProfile,
    Socks5EgressProfile,
    WireguardEgressProfile,
)
from expose.egress.base import EgressHealthCheck, EgressProfileType
from expose.pipeline.dispatcher import (
    DispatchJob,
    DispatchResult,
    DispatchStatus,
    PipelineDispatcher,
)
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

# === Synthetic IDs ============================================================
_TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000E001")
_RUN_ID = UUID("018f1f00-0000-7000-8000-00000000E002")
_NOW = datetime(2026, 5, 10, 14, 0, 0, tzinfo=UTC)


# === Minimal collector for dispatcher tests ===================================


class _StubCollector(Collector):
    """Tier-1 collector that yields one observation — just enough for dispatch."""

    collector_id = "stub-provenance"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        yield Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.DNS_RESOLUTION,
            subject=ObservationSubject(
                identifier_type=ExtendedIdentifierType.DOMAIN,
                identifier_value=seed.value,
            ),
            observed_at=_NOW,
        )

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=1.0,
        )


# === is_anonymizing property tests ===========================================


class TestIsAnonymizing:
    """Verify is_anonymizing on each concrete egress profile."""

    def test_direct_is_not_anonymizing(self) -> None:
        """DirectEgressProfile.is_anonymizing returns False."""
        assert DirectEgressProfile().is_anonymizing is False

    def test_socks5_dns_through_proxy_is_anonymizing(self) -> None:
        """SOCKS5 with dns_through_proxy=True is anonymizing."""
        profile = Socks5EgressProfile(dns_through_proxy=True)
        assert profile.is_anonymizing is True

    def test_socks5_no_dns_through_proxy_is_not_anonymizing(self) -> None:
        """SOCKS5 with dns_through_proxy=False is NOT anonymizing."""
        profile = Socks5EgressProfile(dns_through_proxy=False)
        assert profile.is_anonymizing is False

    def test_wireguard_is_not_anonymizing(self) -> None:
        """WireguardEgressProfile.is_anonymizing returns False."""
        assert WireguardEgressProfile().is_anonymizing is False

    def test_http_connect_is_not_anonymizing(self) -> None:
        """HttpConnectEgressProfile.is_anonymizing returns False."""
        assert HttpConnectEgressProfile().is_anonymizing is False


# === EgressHealthCheck egress_anonymized field ================================


class TestEgressHealthCheckAnonymizedField:
    """Verify the egress_anonymized field on EgressHealthCheck."""

    def test_default_is_false(self) -> None:
        """egress_anonymized defaults to False."""
        check = EgressHealthCheck(
            profile_type=EgressProfileType.DIRECT,
            healthy=True,
            checked_at=_NOW,
        )
        assert check.egress_anonymized is False

    def test_explicit_true(self) -> None:
        """egress_anonymized=True is accepted and serialized."""
        check = EgressHealthCheck(
            profile_type=EgressProfileType.SOCKS5,
            healthy=True,
            checked_at=_NOW,
            egress_anonymized=True,
        )
        assert check.egress_anonymized is True
        dumped = check.model_dump()
        assert dumped["egress_anonymized"] is True


# === DispatchResult egress_anonymized field ===================================


class TestDispatchResultAnonymizedField:
    """Verify the egress_anonymized field on DispatchResult."""

    def test_default_is_false(self) -> None:
        """egress_anonymized defaults to False on DispatchResult."""
        result = DispatchResult(status=DispatchStatus.SUCCESS)
        assert result.egress_anonymized is False


# === Dispatcher integration ===================================================


class TestDispatcherEgressProvenance:
    """Dispatcher propagates egress_anonymized from the active profile."""

    @pytest.fixture()
    def registry(self) -> CollectorRegistry:
        reg = CollectorRegistry()
        reg.register(_StubCollector)
        return reg

    @pytest.fixture()
    def scope(self) -> TenantAuthorizationScope:
        return TenantAuthorizationScope(explicit_entity_identifiers=frozenset())

    @pytest.fixture()
    def seed(self) -> Seed:
        return Seed(seed_type=SeedType.DOMAIN, value="example.com")

    async def test_anonymizing_egress_sets_flag(
        self,
        registry: CollectorRegistry,
        scope: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Dispatcher sets egress_anonymized=True with an anonymizing profile."""
        anon_profile = Socks5EgressProfile(dns_through_proxy=True)
        dispatcher = PipelineDispatcher(
            registry, scope, _TENANT_ID, egress_profile=anon_profile,
        )
        job = DispatchJob(
            collector_id="stub-provenance",
            seed=seed,
            run_id=_RUN_ID,
            tenant_id=_TENANT_ID,
        )
        result = await dispatcher.dispatch(job)

        assert result.status == DispatchStatus.SUCCESS
        assert result.egress_anonymized is True

    async def test_non_anonymizing_egress_clears_flag(
        self,
        registry: CollectorRegistry,
        scope: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Dispatcher sets egress_anonymized=False with a non-anonymizing profile."""
        direct_profile = DirectEgressProfile()
        dispatcher = PipelineDispatcher(
            registry, scope, _TENANT_ID, egress_profile=direct_profile,
        )
        job = DispatchJob(
            collector_id="stub-provenance",
            seed=seed,
            run_id=_RUN_ID,
            tenant_id=_TENANT_ID,
        )
        result = await dispatcher.dispatch(job)

        assert result.status == DispatchStatus.SUCCESS
        assert result.egress_anonymized is False
