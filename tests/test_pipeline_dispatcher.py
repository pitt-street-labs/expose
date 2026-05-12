"""Tests for the pipeline dispatcher (PipelineDispatcher).

Eighteen tests covering the full dispatch lifecycle without live NATS or
Postgres. All collector and registry interactions are satisfied by mock
collector classes defined in this module.

Coverage:

1.  Happy path — Tier-1 collector dispatched, observations returned.
2.  Tier-3 dispatch allowed — entity in scope, collector runs.
3.  Tier-3 dispatch denied — entity not in scope, returns DENIED.
4.  Health check fails — returns HEALTH_CHECK_FAILED.
5.  Collector raises CollectorError — returns COLLECTOR_ERROR with message.
6.  Unknown collector_id — CollectorNotRegisteredError propagates.
7.  Tenant context var set correctly during dispatch.
8.  Duration measured (> 0 ms).
9.  CollectorConfig built with correct tenant_id and run_id.
10. Multiple observations from a multi-yield collector.
11. DispatchJob rejects unknown fields (Pydantic ``extra="forbid"``).
12. DispatchResult is frozen (immutable).
13. ScopeMatcher allows in-scope entity — dispatch proceeds normally.
14. ScopeMatcher denies out-of-scope entity — returns DENIED.
15. ScopeMatcher records enforcement log on denial.
16. CredentialResolver injects credentials into CollectorConfig.
17. CredentialResolver error returns COLLECTOR_ERROR.
18. No scope_matcher (None) — behaviour unchanged (falls through).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from pydantic import ValidationError

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorCredential,
    CollectorError,
    CollectorHealthCheck,
    CollectorSourceUnreachableError,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import CollectorNotRegisteredError, CollectorRegistry
from expose.collectors.tiers import CollectorTier, TenantAuthorizationScope
from expose.pipeline.credential_resolver import CredentialResolutionError, CredentialResolver
from expose.pipeline.dispatcher import (
    _CIRCUIT_BREAKER_THRESHOLD,
    DispatchJob,
    DispatchResult,
    DispatchStatus,
    PipelineDispatcher,
    _health_failure_counts,
    _health_locks,
    clear_health_cache,
    current_tenant_id,
)
from expose.pipeline.enforcement import EnforcementLog
from expose.scope.matcher import ScopeMatcher
from expose.scope.models import AuthorizationScope, ScopeRule, ScopeRuleType
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

# === Synthetic IDs (UUIDv7-style, deterministic, greppable) ==================
TENANT_ID = UUID("018f1f00-0000-7000-8000-000000000D01")
OTHER_TENANT_ID = UUID("018f1f00-0000-7000-8000-000000000D02")
RUN_ID = UUID("018f1f00-0000-7000-8000-000000000D03")

_NOW = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)

# === Mock collectors =========================================================


def _make_observation(
    collector_id: str,
    collector_version: str,
    tenant_id: UUID,
    value: str,
) -> Observation:
    """Build a minimal observation for test assertions."""
    return Observation(
        collector_id=collector_id,
        collector_version=collector_version,
        tenant_id=tenant_id,
        observation_type=ObservationType.DNS_RESOLUTION,
        subject=ObservationSubject(
            identifier_type=ExtendedIdentifierType.DOMAIN,
            identifier_value=value,
        ),
        observed_at=_NOW,
    )


class MockTier1Collector(Collector):
    """Tier-1 collector that yields one observation and passes health check."""

    collector_id = "mock-tier1"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        yield _make_observation(
            self.collector_id,
            self.collector_version,
            self.config.tenant_id,
            seed.value,
        )

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=1.0,
        )


class MockTier3Collector(Collector):
    """Tier-3 collector — subject to attribution gating."""

    collector_id = "mock-tier3"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_3

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        yield _make_observation(
            self.collector_id,
            self.collector_version,
            self.config.tenant_id,
            seed.value,
        )

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=2.0,
        )


class MockUnhealthyCollector(Collector):
    """Collector whose health check always fails."""

    collector_id = "mock-unhealthy"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        yield _make_observation(  # pragma: no cover — never reached
            self.collector_id,
            self.collector_version,
            self.config.tenant_id,
            seed.value,
        )

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.FAILURE,
            checked_at=_NOW,
            error_message="upstream unreachable",
        )


class MockErrorCollector(Collector):
    """Collector whose expand() raises CollectorError."""

    collector_id = "mock-error"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        raise CollectorError("simulated collector failure")
        yield  # type: ignore[misc]

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=1.0,
        )


class MockMultiYieldCollector(Collector):
    """Collector that yields three observations per seed."""

    collector_id = "mock-multi"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        for i in range(3):
            yield _make_observation(
                self.collector_id,
                self.collector_version,
                self.config.tenant_id,
                f"{seed.value}-{i}",
            )

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=0.5,
        )


class MockConfigCapturingCollector(Collector):
    """Collector that stashes its config for test inspection."""

    collector_id = "mock-capture"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    # Class-level stash so the test can inspect what config was passed.
    captured_config: CollectorConfig | None = None

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        MockConfigCapturingCollector.captured_config = config

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        yield _make_observation(
            self.collector_id,
            self.collector_version,
            self.config.tenant_id,
            seed.value,
        )

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=1.0,
        )


class MockTenantContextCollector(Collector):
    """Collector that records the current_tenant_id context var during expand."""

    collector_id = "mock-ctx"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    captured_tenant_id: UUID | None = None

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        MockTenantContextCollector.captured_tenant_id = None

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        MockTenantContextCollector.captured_tenant_id = current_tenant_id.get()
        yield _make_observation(
            self.collector_id,
            self.collector_version,
            self.config.tenant_id,
            seed.value,
        )

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=1.0,
        )


# === Fixtures ================================================================


@pytest.fixture()
def seed() -> Seed:
    return Seed(seed_type=SeedType.DOMAIN, value="example.com")


@pytest.fixture()
def registry() -> CollectorRegistry:
    """Fresh registry with all mock collectors registered."""
    reg = CollectorRegistry()
    reg.register(MockTier1Collector)
    reg.register(MockTier3Collector)
    reg.register(MockUnhealthyCollector)
    reg.register(MockErrorCollector)
    reg.register(MockMultiYieldCollector)
    reg.register(MockConfigCapturingCollector)
    reg.register(MockTenantContextCollector)
    return reg


@pytest.fixture()
def scope_with_example() -> TenantAuthorizationScope:
    """Scope that includes example.com."""
    return TenantAuthorizationScope(
        explicit_entity_identifiers=frozenset({"example.com"}),
    )


@pytest.fixture()
def scope_empty() -> TenantAuthorizationScope:
    """Scope with no explicit entities."""
    return TenantAuthorizationScope(
        explicit_entity_identifiers=frozenset(),
    )


@pytest.fixture(autouse=True)
def _clear_health_cache() -> None:
    """Clear the module-level health-check cache before every test.

    Without this, a cached healthy result from one test can mask a
    timeout or failure in a subsequent test that uses the same
    collector_id.
    """
    clear_health_cache()


def _make_job(collector_id: str, seed: Seed, tenant_id: UUID = TENANT_ID) -> DispatchJob:
    return DispatchJob(
        collector_id=collector_id,
        seed=seed,
        run_id=RUN_ID,
        tenant_id=tenant_id,
    )


# === Tests ===================================================================


class TestPipelineDispatcher:
    """Test suite for PipelineDispatcher.dispatch."""

    @pytest.mark.asyncio
    async def test_happy_path_tier1(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """1. Tier-1 collector dispatched, single observation returned."""
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-tier1", seed))

        assert result.status == DispatchStatus.SUCCESS
        assert len(result.observations) == 1
        assert result.observations[0].subject.identifier_value == "example.com"
        assert result.collector_health is not None
        assert result.collector_health.status == CollectorStatus.SUCCESS
        assert result.error_message is None

    @pytest.mark.asyncio
    async def test_tier3_dispatch_allowed(
        self,
        registry: CollectorRegistry,
        scope_with_example: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """2. Tier-3 collector runs when entity is in scope."""
        dispatcher = PipelineDispatcher(registry, scope_with_example, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-tier3", seed))

        assert result.status == DispatchStatus.SUCCESS
        assert len(result.observations) == 1
        assert result.observations[0].collector_id == "mock-tier3"

    @pytest.mark.asyncio
    async def test_tier3_dispatch_denied(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """3. Tier-3 collector denied when entity is not in scope."""
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-tier3", seed))

        assert result.status == DispatchStatus.DENIED
        assert result.observations == []
        assert result.error_message is not None
        assert "Tier-3 dispatch denied" in result.error_message
        assert "example.com" in result.error_message

    @pytest.mark.asyncio
    async def test_health_check_fails(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """4. Unhealthy collector returns HEALTH_CHECK_FAILED."""
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-unhealthy", seed))

        assert result.status == DispatchStatus.HEALTH_CHECK_FAILED
        assert result.observations == []
        assert result.collector_health is not None
        assert result.collector_health.status == CollectorStatus.FAILURE
        assert result.error_message == "upstream unreachable"

    @pytest.mark.asyncio
    async def test_collector_error(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """5. CollectorError returns COLLECTOR_ERROR with message."""
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-error", seed))

        assert result.status == DispatchStatus.COLLECTOR_ERROR
        assert result.error_message == "simulated collector failure"
        assert result.observations == []
        assert result.collector_health is not None

    @pytest.mark.asyncio
    async def test_unknown_collector_propagates(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """6. Unknown collector_id raises CollectorNotRegisteredError."""
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        with pytest.raises(CollectorNotRegisteredError, match="no-such-collector"):
            await dispatcher.dispatch(_make_job("no-such-collector", seed))

    @pytest.mark.asyncio
    async def test_tenant_context_var_set(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """7. current_tenant_id context var is set during dispatch."""
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-ctx", seed))

        assert result.status == DispatchStatus.SUCCESS
        assert MockTenantContextCollector.captured_tenant_id == TENANT_ID

    @pytest.mark.asyncio
    async def test_duration_measured(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """8. Duration is measured and > 0 ms."""
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-tier1", seed))

        assert result.duration_ms > 0.0

    @pytest.mark.asyncio
    async def test_collector_config_built_correctly(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """9. CollectorConfig carries the correct tenant_id and run_id."""
        MockConfigCapturingCollector.captured_config = None
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-capture", seed))

        assert result.status == DispatchStatus.SUCCESS
        captured = MockConfigCapturingCollector.captured_config
        assert captured is not None
        assert captured.tenant_id == TENANT_ID
        assert captured.run_id == RUN_ID

    @pytest.mark.asyncio
    async def test_multi_yield_collector(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """10. Collector yielding multiple observations collects them all."""
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-multi", seed))

        assert result.status == DispatchStatus.SUCCESS
        assert len(result.observations) == 3
        values = [obs.subject.identifier_value for obs in result.observations]
        assert values == ["example.com-0", "example.com-1", "example.com-2"]

    def test_dispatch_job_rejects_extra_fields(self, seed: Seed) -> None:
        """11. DispatchJob with extra fields raises ValidationError."""
        with pytest.raises(ValueError, match="extra"):
            DispatchJob(
                collector_id="mock-tier1",
                seed=seed,
                run_id=RUN_ID,
                tenant_id=TENANT_ID,
                bogus="nope",  # type: ignore[call-arg]
            )

    def test_dispatch_result_is_frozen(self) -> None:
        """12. DispatchResult is immutable (frozen=True)."""
        result = DispatchResult(status=DispatchStatus.SUCCESS)
        with pytest.raises(ValidationError):
            result.status = DispatchStatus.DENIED  # type: ignore[misc]

    # === ScopeMatcher integration (A1) ========================================

    @pytest.mark.asyncio
    async def test_scope_matcher_allows_in_scope_entity(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """13. ScopeMatcher says in_scope=True — dispatch proceeds normally."""
        auth_scope = AuthorizationScope(
            tenant_id=TENANT_ID,
            rules=[ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="example.com")],
            last_modified=_NOW,
            modified_by="test",
        )
        matcher = ScopeMatcher(auth_scope)
        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID, scope_matcher=matcher,
        )
        result = await dispatcher.dispatch(_make_job("mock-tier1", seed))

        assert result.status == DispatchStatus.SUCCESS
        assert len(result.observations) == 1

    @pytest.mark.asyncio
    async def test_scope_matcher_denies_out_of_scope_entity(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """14. ScopeMatcher says in_scope=False — returns DENIED."""
        auth_scope = AuthorizationScope(
            tenant_id=TENANT_ID,
            rules=[ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="other.net")],
            last_modified=_NOW,
            modified_by="test",
        )
        matcher = ScopeMatcher(auth_scope)
        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID, scope_matcher=matcher,
        )
        result = await dispatcher.dispatch(_make_job("mock-tier1", seed))

        assert result.status == DispatchStatus.DENIED
        assert result.observations == []
        assert result.error_message is not None

    @pytest.mark.asyncio
    async def test_scope_matcher_records_enforcement_log(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """15. ScopeMatcher denial records a ScopeRefusalEvent."""
        auth_scope = AuthorizationScope(
            tenant_id=TENANT_ID,
            rules=[ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="other.net")],
            last_modified=_NOW,
            modified_by="test",
        )
        matcher = ScopeMatcher(auth_scope)
        log = EnforcementLog()
        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID,
            enforcement_log=log, scope_matcher=matcher,
        )
        result = await dispatcher.dispatch(_make_job("mock-tier1", seed))

        assert result.status == DispatchStatus.DENIED
        assert log.refusal_count == 1
        refusal = log.refusals[0]
        assert refusal.entity_identifier == "example.com"
        assert refusal.collector_id == "mock-tier1"

    @pytest.mark.asyncio
    async def test_no_scope_matcher_falls_through(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """18. scope_matcher=None — behaviour unchanged, dispatch proceeds."""
        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID, scope_matcher=None,
        )
        result = await dispatcher.dispatch(_make_job("mock-tier1", seed))

        assert result.status == DispatchStatus.SUCCESS
        assert len(result.observations) == 1

    # === CredentialResolver integration (A2) ==================================

    @pytest.mark.asyncio
    async def test_credential_resolver_injects_credentials(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """16. Resolved credentials appear in CollectorConfig."""
        MockConfigCapturingCollector.captured_config = None
        cred = CollectorCredential(name="api_key", secret_value="s3cret")  # noqa: S106
        resolver = AsyncMock(spec=CredentialResolver)
        resolver.resolve = AsyncMock(return_value={"api_key": cred})

        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID, credential_resolver=resolver,
        )
        result = await dispatcher.dispatch(_make_job("mock-capture", seed))

        assert result.status == DispatchStatus.SUCCESS
        captured = MockConfigCapturingCollector.captured_config
        assert captured is not None
        assert "api_key" in captured.credentials
        assert captured.credentials["api_key"].secret_value == "s3cret"  # noqa: S105
        resolver.resolve.assert_awaited_once_with(TENANT_ID, "mock-capture")

    @pytest.mark.asyncio
    async def test_credential_resolver_error_returns_skipped(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """17. CredentialResolutionError returns SKIPPED (not COLLECTOR_ERROR).

        Missing credentials are a configuration gap, not a collector bug.
        Returning SKIPPED ensures these do not inflate the failure count.
        """
        resolver = AsyncMock(spec=CredentialResolver)
        resolver.resolve = AsyncMock(
            side_effect=CredentialResolutionError("missing api_key"),
        )

        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID, credential_resolver=resolver,
        )
        result = await dispatcher.dispatch(_make_job("mock-tier1", seed))

        assert result.status == DispatchStatus.SKIPPED
        assert result.observations == []
        assert result.error_message == "missing api_key"

    # === Egress fallback retry (issue #76) ====================================

    @pytest.mark.asyncio
    async def test_source_unreachable_no_fallback_returns_error(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """19. CollectorSourceUnreachableError without fallbacks returns COLLECTOR_ERROR."""
        registry.register(MockSourceUnreachableCollector)
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-unreachable", seed))

        assert result.status == DispatchStatus.COLLECTOR_ERROR
        assert "source unreachable" in (result.error_message or "").lower()
        assert result.observations == []

    @pytest.mark.asyncio
    async def test_source_unreachable_fallback_succeeds(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """20. Source unreachable on primary, fallback egress succeeds."""
        registry.register(MockUnreachableThenOkCollector)
        MockUnreachableThenOkCollector.call_count = 0

        from expose.egress.direct import DirectEgressProfile  # noqa: PLC0415
        from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

        fallback = Socks5EgressProfile(proxy_url="socks5://127.0.0.1:9050")
        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID,
            egress_profile=DirectEgressProfile(),
            egress_fallbacks=[fallback],
        )
        result = await dispatcher.dispatch(_make_job("mock-unreachable-then-ok", seed))

        assert result.status == DispatchStatus.SUCCESS
        assert len(result.observations) == 1
        # The collector was called twice: once primary (fail), once fallback (ok)
        assert MockUnreachableThenOkCollector.call_count == 2

    @pytest.mark.asyncio
    async def test_source_unreachable_all_fallbacks_fail(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """21. Source unreachable on primary and all fallbacks returns original error."""
        registry.register(MockSourceUnreachableCollector)

        from expose.egress.direct import DirectEgressProfile  # noqa: PLC0415
        from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

        fb1 = Socks5EgressProfile(proxy_url="socks5://127.0.0.1:9050")
        fb2 = Socks5EgressProfile(proxy_url="socks5://127.0.0.1:9051")
        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID,
            egress_profile=DirectEgressProfile(),
            egress_fallbacks=[fb1, fb2],
        )
        result = await dispatcher.dispatch(_make_job("mock-unreachable", seed))

        assert result.status == DispatchStatus.COLLECTOR_ERROR
        assert "source unreachable" in (result.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_non_unreachable_collector_error_skips_fallback(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """22. Generic CollectorError (not source-unreachable) does NOT trigger fallback."""
        from expose.egress.direct import DirectEgressProfile  # noqa: PLC0415
        from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

        fallback = Socks5EgressProfile(proxy_url="socks5://127.0.0.1:9050")
        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID,
            egress_profile=DirectEgressProfile(),
            egress_fallbacks=[fallback],
        )
        # MockErrorCollector raises generic CollectorError, not SourceUnreachable
        result = await dispatcher.dispatch(_make_job("mock-error", seed))

        assert result.status == DispatchStatus.COLLECTOR_ERROR
        assert result.error_message == "simulated collector failure"

    @pytest.mark.asyncio
    async def test_egress_profile_restored_after_fallback(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """23. The original egress profile is restored after fallback attempt."""
        registry.register(MockUnreachableThenOkCollector)
        MockUnreachableThenOkCollector.call_count = 0

        from expose.egress.direct import DirectEgressProfile  # noqa: PLC0415
        from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

        original_egress = DirectEgressProfile()
        fallback = Socks5EgressProfile(proxy_url="socks5://127.0.0.1:9050")
        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID,
            egress_profile=original_egress,
            egress_fallbacks=[fallback],
        )
        await dispatcher.dispatch(_make_job("mock-unreachable-then-ok", seed))

        # Verify the original profile is restored
        assert dispatcher._egress_profile is original_egress


# === Mock collectors for egress fallback tests ================================


class MockSourceUnreachableCollector(Collector):
    """Collector that always raises CollectorSourceUnreachableError."""

    collector_id = "mock-unreachable"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        raise CollectorSourceUnreachableError("simulated source unreachable")
        yield  # type: ignore[misc]

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=1.0,
        )


class MockUnreachableThenOkCollector(Collector):
    """Collector that fails on first call, succeeds on subsequent calls.

    Simulates the scenario where the primary egress path is blocked but
    a fallback egress path succeeds.
    """

    collector_id = "mock-unreachable-then-ok"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    # Class-level counter so the test can verify call count
    call_count: int = 0

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        MockUnreachableThenOkCollector.call_count += 1
        if MockUnreachableThenOkCollector.call_count == 1:
            raise CollectorSourceUnreachableError("primary path blocked")
        yield _make_observation(
            self.collector_id,
            self.collector_version,
            self.config.tenant_id,
            seed.value,
        )

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=1.0,
        )


# === Tests for egress wiring (_build_socks5_fallback + tenant config) =========


class TestBuildSocks5Fallback:
    """Tests for the _build_socks5_fallback helper in runs.py."""

    def test_returns_empty_when_socksio_missing(self) -> None:
        """When socksio is not installed, return [] and log a warning."""
        from unittest.mock import patch  # noqa: PLC0415

        from expose.api.runs import _build_socks5_fallback  # noqa: PLC0415

        with patch("importlib.util.find_spec", return_value=None):
            result = _build_socks5_fallback("socks5://127.0.0.1:9050")

        assert result == []

    def test_returns_profile_with_explicit_proxy(self) -> None:
        """When socksio is available and proxy URL is explicit, use it."""
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        from expose.api.runs import _build_socks5_fallback  # noqa: PLC0415
        from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

        # Mock find_spec to report socksio as available
        mock_spec = MagicMock()
        with patch("importlib.util.find_spec", return_value=mock_spec):
            result = _build_socks5_fallback("socks5://10.0.0.1:1080")

        assert len(result) == 1
        assert isinstance(result[0], Socks5EgressProfile)
        assert result[0].proxy_url == "socks5://10.0.0.1:1080"

    def test_defaults_to_tor_proxy_when_no_url(self) -> None:
        """When socks5_proxy is empty/None, default to localhost:9050 (Tor)."""
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        from expose.api.runs import _DEFAULT_TOR_PROXY, _build_socks5_fallback  # noqa: PLC0415
        from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

        mock_spec = MagicMock()
        with patch("importlib.util.find_spec", return_value=mock_spec):
            result = _build_socks5_fallback(None)

        assert len(result) == 1
        assert isinstance(result[0], Socks5EgressProfile)
        assert result[0].proxy_url == _DEFAULT_TOR_PROXY
        assert result[0].proxy_url == "socks5://localhost:9050"

    def test_defaults_to_tor_proxy_when_empty_string(self) -> None:
        """Empty string socks5_proxy also defaults to Tor."""
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        from expose.api.runs import _build_socks5_fallback  # noqa: PLC0415
        from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

        mock_spec = MagicMock()
        with patch("importlib.util.find_spec", return_value=mock_spec):
            result = _build_socks5_fallback("")

        assert len(result) == 1
        assert isinstance(result[0], Socks5EgressProfile)
        assert result[0].proxy_url == "socks5://localhost:9050"


class TestGetTenantConfigData:
    """Tests for the get_tenant_config_data accessor."""

    def test_returns_defaults_for_unknown_tenant(self) -> None:
        """Unknown tenant gets sensible defaults."""
        from uuid import uuid4  # noqa: PLC0415

        from expose.api.tenant_config import get_tenant_config_data  # noqa: PLC0415

        cfg = get_tenant_config_data(uuid4())
        assert cfg["egress_fallbacks"] == []
        assert cfg["socks5_proxy"] is None
        assert cfg["egress_profile"] == "direct"

    def test_returns_stored_config(self) -> None:
        """When config is stored, it is returned correctly."""
        from uuid import uuid4  # noqa: PLC0415

        from expose.api.tenant_config import (  # noqa: PLC0415
            _configs,
            _default_config,
            get_tenant_config_data,
        )

        tid = uuid4()
        stored = _default_config(tid)
        stored["egress_fallbacks"] = ["socks5"]
        stored["socks5_proxy"] = "socks5://tor-exit:9050"
        _configs[tid] = stored

        try:
            cfg = get_tenant_config_data(tid)
            assert cfg["egress_fallbacks"] == ["socks5"]
            assert cfg["socks5_proxy"] == "socks5://tor-exit:9050"
        finally:
            # Clean up the in-memory store
            _configs.pop(tid, None)

    def test_returns_copy_not_reference(self) -> None:
        """Mutations to the returned dict must not affect the store."""
        from uuid import uuid4  # noqa: PLC0415

        from expose.api.tenant_config import (  # noqa: PLC0415
            _configs,
            _default_config,
            get_tenant_config_data,
        )

        tid = uuid4()
        stored = _default_config(tid)
        _configs[tid] = stored

        try:
            cfg = get_tenant_config_data(tid)
            cfg["egress_fallbacks"] = ["socks5", "wireguard"]

            # The store must be unaffected
            original = _configs[tid]
            assert original["egress_fallbacks"] == []
        finally:
            _configs.pop(tid, None)


class TestSocks5EgressProfileConfigure:
    """Tests for Socks5EgressProfile.configure_httpx_client compatibility."""

    def test_configure_returns_proxy_kwarg(self) -> None:
        """configure_httpx_client returns a dict with 'proxy' key."""
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

        profile = Socks5EgressProfile(
            proxy_url="socks5://127.0.0.1:9050",
            dns_through_proxy=True,
        )

        # Mock socksio as available
        with patch("expose.egress.socks5._socksio_available", return_value=True):
            kwargs = profile.configure_httpx_client()

        assert "proxy" in kwargs
        # dns_through_proxy=True should rewrite to socks5h://
        assert kwargs["proxy"] == "socks5h://127.0.0.1:9050"

    def test_configure_without_dns_proxy_keeps_socks5(self) -> None:
        """Without dns_through_proxy, the scheme stays socks5://."""
        from unittest.mock import patch  # noqa: PLC0415

        from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

        profile = Socks5EgressProfile(
            proxy_url="socks5://127.0.0.1:9050",
            dns_through_proxy=False,
        )

        with patch("expose.egress.socks5._socksio_available", return_value=True):
            kwargs = profile.configure_httpx_client()

        assert kwargs["proxy"] == "socks5://127.0.0.1:9050"

    def test_configure_raises_when_socksio_missing(self) -> None:
        """configure_httpx_client raises RuntimeError without socksio."""
        from unittest.mock import patch  # noqa: PLC0415

        from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

        profile = Socks5EgressProfile(proxy_url="socks5://127.0.0.1:9050")

        with patch("expose.egress.socks5._socksio_available", return_value=False):
            with pytest.raises(RuntimeError, match="socksio"):
                profile.configure_httpx_client()

    def test_is_anonymizing_with_dns_proxy(self) -> None:
        """SOCKS5 profile is anonymizing when DNS goes through proxy."""
        from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

        profile = Socks5EgressProfile(
            proxy_url="socks5://127.0.0.1:9050",
            dns_through_proxy=True,
        )
        assert profile.is_anonymizing is True

    def test_not_anonymizing_without_dns_proxy(self) -> None:
        """SOCKS5 profile is NOT anonymizing when DNS leaks."""
        from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

        profile = Socks5EgressProfile(
            proxy_url="socks5://127.0.0.1:9050",
            dns_through_proxy=False,
        )
        assert profile.is_anonymizing is False


class TestEgressFallbackEndToEnd:
    """End-to-end: tenant config -> dispatcher with SOCKS5 fallback."""

    @pytest.mark.asyncio
    async def test_fallback_with_socks5_from_tenant_config(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Dispatcher with SOCKS5 fallback (built from tenant config) retries on unreachable."""
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        from expose.api.runs import _build_socks5_fallback  # noqa: PLC0415

        registry.register(MockUnreachableThenOkCollector)
        MockUnreachableThenOkCollector.call_count = 0

        from expose.egress.direct import DirectEgressProfile  # noqa: PLC0415

        # Simulate socksio being available
        mock_spec = MagicMock()
        with patch("importlib.util.find_spec", return_value=mock_spec):
            fallbacks = _build_socks5_fallback("socks5://127.0.0.1:9050")

        assert len(fallbacks) == 1

        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID,
            egress_profile=DirectEgressProfile(),
            egress_fallbacks=fallbacks,
        )
        result = await dispatcher.dispatch(_make_job("mock-unreachable-then-ok", seed))

        assert result.status == DispatchStatus.SUCCESS
        assert MockUnreachableThenOkCollector.call_count == 2

    @pytest.mark.asyncio
    async def test_no_fallback_when_socksio_missing(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """When socksio is missing, no fallback is configured; unreachable becomes error."""
        from unittest.mock import patch  # noqa: PLC0415

        from expose.api.runs import _build_socks5_fallback  # noqa: PLC0415

        registry.register(MockSourceUnreachableCollector)

        from expose.egress.direct import DirectEgressProfile  # noqa: PLC0415

        with patch("importlib.util.find_spec", return_value=None):
            fallbacks = _build_socks5_fallback("socks5://127.0.0.1:9050")

        assert fallbacks == []

        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID,
            egress_profile=DirectEgressProfile(),
            egress_fallbacks=fallbacks,
        )
        result = await dispatcher.dispatch(_make_job("mock-unreachable", seed))

        assert result.status == DispatchStatus.COLLECTOR_ERROR
        assert "source unreachable" in (result.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_socks5_fallback_egress_anonymized_flag(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """When fallback succeeds via SOCKS5, egress_anonymized is True."""
        from unittest.mock import MagicMock, patch  # noqa: PLC0415

        from expose.api.runs import _build_socks5_fallback  # noqa: PLC0415
        from expose.egress.direct import DirectEgressProfile  # noqa: PLC0415

        registry.register(MockUnreachableThenOkCollector)
        MockUnreachableThenOkCollector.call_count = 0

        mock_spec = MagicMock()
        with patch("importlib.util.find_spec", return_value=mock_spec):
            fallbacks = _build_socks5_fallback("socks5://127.0.0.1:9050")

        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID,
            egress_profile=DirectEgressProfile(),
            egress_fallbacks=fallbacks,
        )
        result = await dispatcher.dispatch(_make_job("mock-unreachable-then-ok", seed))

        assert result.status == DispatchStatus.SUCCESS
        # SOCKS5 with dns_through_proxy=True (default) is anonymizing
        assert result.egress_anonymized is True


class TestCredentialChainEndToEnd:
    """End-to-end tests: InMemoryBackend -> CredentialResolver -> Dispatcher -> CollectorConfig.

    Uses a real InMemoryBackend and CredentialResolver (no mocks) to verify
    that credentials stored in the backend reach the collector's config.
    """

    @pytest.mark.asyncio
    async def test_real_resolver_delivers_credentials_to_collector(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Credentials stored in InMemoryBackend reach CollectorConfig.credentials."""
        from expose.pipeline.credential_resolver import (  # noqa: PLC0415
            CREDENTIAL_SPECS,
            CollectorCredentialSpec,
            CredentialResolver,
        )
        from expose.secrets.memory_backend import InMemoryBackend  # noqa: PLC0415

        # Register a test spec for the mock-capture collector
        CREDENTIAL_SPECS["mock-capture"] = CollectorCredentialSpec(
            collector_id="mock-capture",
            required_keys=["api_key"],
        )
        try:
            backend = InMemoryBackend()
            await backend.set(
                tenant_id=TENANT_ID,
                key="collector.mock-capture.api_key",
                value="real-secret-value",
            )

            resolver = CredentialResolver(backend)
            MockConfigCapturingCollector.captured_config = None

            dispatcher = PipelineDispatcher(
                registry, scope_empty, TENANT_ID,
                credential_resolver=resolver,
            )
            result = await dispatcher.dispatch(_make_job("mock-capture", seed))

            assert result.status == DispatchStatus.SUCCESS
            captured = MockConfigCapturingCollector.captured_config
            assert captured is not None
            assert "api_key" in captured.credentials
            assert captured.credentials["api_key"].secret_value == "real-secret-value"  # noqa: S105, E501
        finally:
            CREDENTIAL_SPECS.pop("mock-capture", None)

    @pytest.mark.asyncio
    async def test_missing_credential_returns_skipped(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Missing credential in backend returns SKIPPED, not COLLECTOR_ERROR.

        Missing credentials are a configuration gap — the collector is not
        broken, it just cannot run without an API key.
        """
        from expose.pipeline.credential_resolver import (  # noqa: PLC0415
            CREDENTIAL_SPECS,
            CollectorCredentialSpec,
            CredentialResolver,
        )
        from expose.secrets.memory_backend import InMemoryBackend  # noqa: PLC0415

        CREDENTIAL_SPECS["mock-tier1"] = CollectorCredentialSpec(
            collector_id="mock-tier1",
            required_keys=["api_key"],
        )
        try:
            backend = InMemoryBackend()  # empty -- no credentials stored
            resolver = CredentialResolver(backend)

            dispatcher = PipelineDispatcher(
                registry, scope_empty, TENANT_ID,
                credential_resolver=resolver,
            )
            result = await dispatcher.dispatch(_make_job("mock-tier1", seed))

            # Should skip at credential resolution, not fail
            assert result.status == DispatchStatus.SKIPPED
            assert "Missing credentials" in (result.error_message or "")
            assert "mock-tier1" in (result.error_message or "")
        finally:
            CREDENTIAL_SPECS.pop("mock-tier1", None)

    @pytest.mark.asyncio
    async def test_no_resolver_passes_empty_credentials(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Without a credential resolver, collectors receive empty credentials dict."""
        MockConfigCapturingCollector.captured_config = None

        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID,
            credential_resolver=None,
        )
        result = await dispatcher.dispatch(_make_job("mock-capture", seed))

        assert result.status == DispatchStatus.SUCCESS
        captured = MockConfigCapturingCollector.captured_config
        assert captured is not None
        assert captured.credentials == {}


# === Enforcement log integration tests ========================================


class TestEnforcementDispatcherIntegration:
    """Tests for enforcement log wiring into the dispatcher."""

    @pytest.mark.asyncio
    async def test_enforcement_denied_dispatch_creates_refusal(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Denied Tier-3 dispatch creates a ScopeRefusalEvent in the enforcement log."""
        log = EnforcementLog()
        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID,
            enforcement_log=log,
        )
        result = await dispatcher.dispatch(_make_job("mock-tier3", seed))

        assert result.status == DispatchStatus.DENIED
        assert log.refusal_count == 1
        refusal = log.refusals[0]
        assert refusal.tenant_id == TENANT_ID
        assert refusal.entity_identifier == "example.com"
        assert refusal.collector_id == "mock-tier3"
        assert refusal.attribution_tier is None
        assert refusal.reason  # non-empty denial reason

    @pytest.mark.asyncio
    async def test_enforcement_log_none_safe(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Dispatcher with enforcement_log=None does not crash on denial."""
        # When enforcement_log is None, __init__ creates a default EnforcementLog.
        # The dispatch must complete without AttributeError or TypeError.
        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID,
            enforcement_log=None,
        )
        result = await dispatcher.dispatch(_make_job("mock-tier3", seed))
        assert result.status == DispatchStatus.DENIED
        assert result.error_message is not None

        # Also verify that a successful dispatch with no log works fine.
        result_ok = await dispatcher.dispatch(_make_job("mock-tier1", seed))
        assert result_ok.status == DispatchStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_enforcement_refusals_serialized(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Refusals are serializable via model_dump and contain expected fields."""
        log = EnforcementLog()
        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID,
            enforcement_log=log,
        )
        await dispatcher.dispatch(_make_job("mock-tier3", seed))

        assert log.refusal_count == 1
        serialized = [r.model_dump(mode="json") for r in log.refusals]
        assert len(serialized) == 1
        entry = serialized[0]
        assert entry["entity_identifier"] == "example.com"
        assert entry["collector_id"] == "mock-tier3"
        assert entry["tenant_id"] == str(TENANT_ID)
        assert "reason" in entry
        assert "timestamp" in entry
        assert "enforcement_mode" in entry

    @pytest.mark.asyncio
    async def test_enforcement_tier3_denial_recorded(
        self,
        registry: CollectorRegistry,
        seed: Seed,
    ) -> None:
        """Tier-3 denial records refusal with correct enforcement mode from scope."""
        from expose.collectors.tiers import EnforcementMode  # noqa: PLC0415

        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(),
            enforcement_mode=EnforcementMode.HARD,
        )
        log = EnforcementLog()
        dispatcher = PipelineDispatcher(
            registry, scope, TENANT_ID,
            enforcement_log=log,
        )
        result = await dispatcher.dispatch(_make_job("mock-tier3", seed))

        assert result.status == DispatchStatus.DENIED
        assert log.refusal_count == 1
        refusal = log.refusals[0]
        assert refusal.enforcement_mode == EnforcementMode.HARD
        assert "Tier-3 dispatch denied" in refusal.reason
        assert refusal.entity_identifier == "example.com"
        assert refusal.collector_id == "mock-tier3"


# === Tier-3 attribution gate tests ==========================================


class TestTier3AttributionGate:
    """Tests for the Tier-3 attribution status gate in PipelineDispatcher.

    Operator-provided seeds (those in the tenant's explicit authorization
    scope) bypass the attribution gate — they are implicitly authorized for
    active probing.  Discovered entities NOT in scope are still gated on
    attribution status.
    """

    @pytest.mark.asyncio
    async def test_tier3_gate_denied_unattributed_discovered_entity(
        self,
        registry: CollectorRegistry,
        scope_with_example: TenantAuthorizationScope,
    ) -> None:
        """Tier-3 dispatch denied for discovered (non-operator) entity with 'unattributed' status."""
        # sub.other.com is NOT in scope_with_example — simulates a discovered entity
        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="sub.other.com",
            properties={"attribution_status": "unattributed"},
        )
        dispatcher = PipelineDispatcher(registry, scope_with_example, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-tier3", seed))

        assert result.status == DispatchStatus.DENIED
        assert result.error_message == "entity_not_attributed_for_tier3"
        assert result.observations == []

    @pytest.mark.asyncio
    async def test_tier3_gate_denied_requires_review_discovered_entity(
        self,
        registry: CollectorRegistry,
        scope_with_example: TenantAuthorizationScope,
    ) -> None:
        """Tier-3 dispatch denied for discovered entity with 'requires_review' status."""
        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="sub.other.com",
            properties={"attribution_status": "requires_review"},
        )
        dispatcher = PipelineDispatcher(registry, scope_with_example, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-tier3", seed))

        assert result.status == DispatchStatus.DENIED
        assert result.error_message == "entity_not_attributed_for_tier3"

    @pytest.mark.asyncio
    async def test_tier3_gate_allowed_operator_seed_unattributed(
        self,
        registry: CollectorRegistry,
        scope_with_example: TenantAuthorizationScope,
    ) -> None:
        """Operator-provided seeds bypass attribution gate even when 'unattributed'."""
        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"attribution_status": "unattributed"},
        )
        dispatcher = PipelineDispatcher(registry, scope_with_example, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-tier3", seed))

        # example.com is in scope -> operator-provided -> bypass attribution gate
        assert result.status == DispatchStatus.SUCCESS
        assert len(result.observations) == 1

    @pytest.mark.asyncio
    async def test_tier3_gate_allowed_operator_seed_no_attribution(
        self,
        registry: CollectorRegistry,
        scope_with_example: TenantAuthorizationScope,
    ) -> None:
        """Operator-provided seeds pass when attribution_status is absent from properties."""
        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={},
        )
        dispatcher = PipelineDispatcher(registry, scope_with_example, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-tier3", seed))

        assert result.status == DispatchStatus.SUCCESS
        assert len(result.observations) == 1

    @pytest.mark.asyncio
    async def test_tier3_gate_allowed_confirmed(
        self,
        registry: CollectorRegistry,
        scope_with_example: TenantAuthorizationScope,
    ) -> None:
        """Tier-3 dispatch allowed when entity attribution_status is 'confirmed'."""
        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"attribution_status": "confirmed"},
        )
        dispatcher = PipelineDispatcher(registry, scope_with_example, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-tier3", seed))

        assert result.status == DispatchStatus.SUCCESS
        assert len(result.observations) == 1
        assert result.observations[0].collector_id == "mock-tier3"

    @pytest.mark.asyncio
    async def test_tier3_gate_allowed_confirmed_discovered_entity(
        self,
        registry: CollectorRegistry,
        scope_with_example: TenantAuthorizationScope,
    ) -> None:
        """Discovered entity with 'confirmed' attribution passes Tier-3 gate."""
        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="sub.other.com",
            properties={"attribution_status": "confirmed"},
        )
        dispatcher = PipelineDispatcher(registry, scope_with_example, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-tier3", seed))

        # confirmed attribution passes even for entities not in explicit scope
        assert result.status == DispatchStatus.SUCCESS
        assert len(result.observations) == 1

    @pytest.mark.asyncio
    async def test_tier3_gate_tier1_not_affected(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
    ) -> None:
        """Tier-1 collectors are not affected by the attribution gate."""
        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={"attribution_status": "unattributed"},
        )
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-tier1", seed))

        assert result.status == DispatchStatus.SUCCESS
        assert len(result.observations) == 1

    @pytest.mark.asyncio
    async def test_tier3_gate_no_attribution_property_falls_through(
        self,
        registry: CollectorRegistry,
        scope_with_example: TenantAuthorizationScope,
    ) -> None:
        """When attribution_status is absent from seed properties, the gate passes through."""
        seed = Seed(
            seed_type=SeedType.DOMAIN,
            value="example.com",
            properties={},
        )
        dispatcher = PipelineDispatcher(registry, scope_with_example, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-tier3", seed))

        # No attribution_status in properties -> falls through to existing
        # Tier-3 gate which allows because example.com is in scope
        assert result.status == DispatchStatus.SUCCESS
        assert len(result.observations) == 1


# === Mock collectors for timeout and cleanup tests ============================


class MockSlowHealthCheckCollector(Collector):
    """Collector whose health_check() hangs indefinitely (for timeout tests)."""

    collector_id = "mock-slow-health"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        yield _make_observation(
            self.collector_id,
            self.collector_version,
            self.config.tenant_id,
            seed.value,
        )

    async def health_check(self) -> CollectorHealthCheck:
        # Block forever -- the dispatcher must time this out
        await asyncio.sleep(999999)
        # Unreachable, but satisfies the return type
        return CollectorHealthCheck(  # pragma: no cover
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=1.0,
        )


class MockSlowExpandCollector(Collector):
    """Collector whose expand() hangs indefinitely (for timeout tests)."""

    collector_id = "mock-slow-expand"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        # Block forever -- the dispatcher must time this out
        await asyncio.sleep(999999)
        yield _make_observation(  # pragma: no cover
            self.collector_id,
            self.collector_version,
            self.config.tenant_id,
            seed.value,
        )

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=1.0,
        )


class MockCloseableCollector(Collector):
    """Collector with a close() method to verify resource cleanup."""

    collector_id = "mock-closeable"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    close_called: bool = False

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        MockCloseableCollector.close_called = False

    async def close(self) -> None:
        MockCloseableCollector.close_called = True

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        yield _make_observation(
            self.collector_id,
            self.collector_version,
            self.config.tenant_id,
            seed.value,
        )

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=1.0,
        )


class MockCloseableErrorCollector(Collector):
    """Collector with close() that verifies cleanup even after expand errors."""

    collector_id = "mock-closeable-error"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    close_called: bool = False

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)
        MockCloseableErrorCollector.close_called = False

    async def close(self) -> None:
        MockCloseableErrorCollector.close_called = True

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        raise CollectorError("simulated failure for cleanup test")
        yield  # type: ignore[misc]

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=1.0,
        )


# === Timeout tests ============================================================


class TestDispatcherTimeouts:
    """Tests for health-check and expand timeout enforcement."""

    @pytest.mark.asyncio
    async def test_health_check_timeout(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Health check that exceeds the timeout returns HEALTH_CHECK_FAILED."""
        from unittest.mock import patch  # noqa: PLC0415

        registry.register(MockSlowHealthCheckCollector)
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)

        # Shrink the timeout constant so the test finishes instantly
        with patch("expose.pipeline.dispatcher.HEALTH_CHECK_TIMEOUT", 0.01):
            result = await dispatcher.dispatch(_make_job("mock-slow-health", seed))

        assert result.status == DispatchStatus.HEALTH_CHECK_FAILED
        assert "timed out" in (result.error_message or "").lower()
        assert result.observations == []

    @pytest.mark.asyncio
    async def test_expand_timeout(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Expand that exceeds the timeout returns COLLECTOR_ERROR."""
        from unittest.mock import patch  # noqa: PLC0415

        registry.register(MockSlowExpandCollector)
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)

        # Shrink the timeout constant so the test finishes instantly
        with patch("expose.pipeline.dispatcher.EXPAND_TIMEOUT", 0.01):
            result = await dispatcher.dispatch(_make_job("mock-slow-expand", seed))

        assert result.status == DispatchStatus.COLLECTOR_ERROR
        assert "timed out" in (result.error_message or "").lower()
        assert result.observations == []
        assert result.collector_health is not None


# === Resource cleanup tests ===================================================


class TestCollectorResourceCleanup:
    """Tests for collector close() cleanup after dispatch."""

    @pytest.mark.asyncio
    async def test_close_called_on_success(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """close() is called after a successful dispatch."""
        registry.register(MockCloseableCollector)
        MockCloseableCollector.close_called = False
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-closeable", seed))

        assert result.status == DispatchStatus.SUCCESS
        assert MockCloseableCollector.close_called is True

    @pytest.mark.asyncio
    async def test_close_called_on_error(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """close() is called even when expand() raises."""
        registry.register(MockCloseableErrorCollector)
        MockCloseableErrorCollector.close_called = False
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-closeable-error", seed))

        assert result.status == DispatchStatus.COLLECTOR_ERROR
        assert MockCloseableErrorCollector.close_called is True

    @pytest.mark.asyncio
    async def test_no_close_method_is_fine(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Collectors without close() still dispatch successfully (duck-typing)."""
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)
        result = await dispatcher.dispatch(_make_job("mock-tier1", seed))

        assert result.status == DispatchStatus.SUCCESS
        assert len(result.observations) == 1


# === Egress profile mutation race condition test ==============================


class TestEgressProfileImmutability:
    """Tests that egress profile is passed explicitly, never mutated on self."""

    @pytest.mark.asyncio
    async def test_egress_profile_never_mutated_during_fallback(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """self._egress_profile is never modified during fallback dispatch."""
        registry.register(MockUnreachableThenOkCollector)
        MockUnreachableThenOkCollector.call_count = 0

        from expose.egress.direct import DirectEgressProfile  # noqa: PLC0415
        from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

        original_egress = DirectEgressProfile()
        fallback = Socks5EgressProfile(proxy_url="socks5://127.0.0.1:9050")
        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID,
            egress_profile=original_egress,
            egress_fallbacks=[fallback],
        )

        # Capture every value of _egress_profile during dispatch
        profile_snapshots: list[object] = []
        original_run_expand = dispatcher._run_expand

        async def tracking_run_expand(*args, **kwargs):  # noqa: ANN002, ANN003
            profile_snapshots.append(dispatcher._egress_profile)
            return await original_run_expand(*args, **kwargs)

        dispatcher._run_expand = tracking_run_expand  # type: ignore[method-assign]
        await dispatcher.dispatch(_make_job("mock-unreachable-then-ok", seed))

        # _egress_profile should be the original throughout (never swapped)
        for snap in profile_snapshots:
            assert snap is original_egress, (
                "self._egress_profile was mutated during fallback dispatch"
            )


# === Health cache thundering herd tests (issue #156) ===========================


class MockSlowHealthCollector(Collector):
    """Collector with a slow health check that counts invocations.

    Used to verify that concurrent dispatches for the same collector_id
    only trigger one health check (the rest wait on the lock and read the
    cached result).
    """

    collector_id = "mock-slow-counted"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    health_check_count: int = 0

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        yield _make_observation(
            self.collector_id,
            self.collector_version,
            self.config.tenant_id,
            seed.value,
        )

    async def health_check(self) -> CollectorHealthCheck:
        MockSlowHealthCollector.health_check_count += 1
        # Small delay to simulate network latency and widen the race window
        await asyncio.sleep(0.05)
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=50.0,
        )


class TestHealthCacheThunderingHerd:
    """Tests for per-collector-ID asyncio.Lock preventing thundering herd."""

    @pytest.mark.asyncio
    async def test_concurrent_health_checks_coalesced(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Concurrent dispatches for the same collector only run one health check.

        When multiple dispatches for the same collector_id arrive
        concurrently, the per-collector lock ensures only the first task
        performs the actual health probe.  Subsequent tasks acquire the
        lock and find the cached result.
        """
        registry.register(MockSlowHealthCollector)
        MockSlowHealthCollector.health_check_count = 0

        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)

        # Fire 5 concurrent dispatches for the same collector
        jobs = [_make_job("mock-slow-counted", seed) for _ in range(5)]
        results = await asyncio.gather(
            *[dispatcher.dispatch(job) for job in jobs],
        )

        # All should succeed
        assert all(r.status == DispatchStatus.SUCCESS for r in results)
        assert all(len(r.observations) == 1 for r in results)

        # Only one health check should have been executed (the rest
        # hit the cache after the lock was released).
        assert MockSlowHealthCollector.health_check_count == 1

    @pytest.mark.asyncio
    async def test_health_lock_created_per_collector_id(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Each collector_id gets its own lock in _health_locks."""
        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)

        await dispatcher.dispatch(_make_job("mock-tier1", seed))
        assert "mock-tier1" in _health_locks
        assert isinstance(_health_locks["mock-tier1"], asyncio.Lock)

    @pytest.mark.asyncio
    async def test_clear_health_cache_clears_locks(self) -> None:
        """clear_health_cache() also clears the per-collector lock map."""
        _health_locks["test-collector"] = asyncio.Lock()
        clear_health_cache()
        assert _health_locks == {}

    @pytest.mark.asyncio
    async def test_concurrent_lock_acquisition_uses_same_lock(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """setdefault ensures concurrent dispatches for a new collector_id share one Lock.

        This is the regression test for the race condition in issue #129:
        the old ``if key not in dict`` pattern could create two different
        Lock instances for the same collector_id when two coroutines
        interleaved at the check-then-set boundary.

        With ``setdefault``, the dict operation is atomic in CPython, so
        all coroutines always see the same Lock object.
        """
        registry.register(MockSlowHealthCollector)
        MockSlowHealthCollector.health_check_count = 0

        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)

        # Fire 10 concurrent dispatches — all for the same collector_id.
        # If separate locks were created, multiple health checks would
        # execute concurrently.
        jobs = [_make_job("mock-slow-counted", seed) for _ in range(10)]
        results = await asyncio.gather(
            *[dispatcher.dispatch(job) for job in jobs],
        )

        # All should succeed
        assert all(r.status == DispatchStatus.SUCCESS for r in results)

        # Exactly one lock should exist for this collector_id
        assert "mock-slow-counted" in _health_locks
        lock = _health_locks["mock-slow-counted"]
        assert isinstance(lock, asyncio.Lock)

        # Only one health check should have been performed
        assert MockSlowHealthCollector.health_check_count == 1


# === Circuit breaker tests (issue #129) =======================================


class MockAlwaysUnhealthyCollector(Collector):
    """Collector whose health check always returns FAILURE.

    Used to test circuit breaker behavior — after N consecutive failures
    the dispatcher should short-circuit without performing another probe.
    """

    collector_id = "mock-always-unhealthy"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    health_check_count: int = 0

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        yield _make_observation(  # pragma: no cover — never reached
            self.collector_id,
            self.collector_version,
            self.config.tenant_id,
            seed.value,
        )

    async def health_check(self) -> CollectorHealthCheck:
        MockAlwaysUnhealthyCollector.health_check_count += 1
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.FAILURE,
            checked_at=_NOW,
            error_message="always failing",
        )


class MockRecoveringCollector(Collector):
    """Collector that fails N times then recovers.

    Used to verify the circuit breaker resets after a successful health check.
    """

    collector_id = "mock-recovering"
    collector_version = "1.0.0"
    requires_credentials = False
    rate_limit_per_minute = None
    tier = CollectorTier.TIER_1

    call_count: int = 0
    fail_until: int = 2  # fail the first N health checks

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        yield _make_observation(
            self.collector_id,
            self.collector_version,
            self.config.tenant_id,
            seed.value,
        )

    async def health_check(self) -> CollectorHealthCheck:
        MockRecoveringCollector.call_count += 1
        if MockRecoveringCollector.call_count <= MockRecoveringCollector.fail_until:
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=_NOW,
                error_message="temporarily failing",
            )
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=_NOW,
            latency_ms=1.0,
        )


class TestCircuitBreaker:
    """Tests for the health-check circuit breaker (issue #129)."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_trips_after_threshold(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """After N consecutive health-check failures, the circuit breaker opens.

        The collector should NOT be probed again once the breaker is open.
        Instead, the dispatcher returns HEALTH_CHECK_FAILED immediately
        with a "Circuit breaker open" error message.
        """
        registry.register(MockAlwaysUnhealthyCollector)
        MockAlwaysUnhealthyCollector.health_check_count = 0

        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)

        # Dispatch N times to trip the breaker.  Each dispatch clears the
        # health cache entry so the health check is actually re-executed.
        for i in range(_CIRCUIT_BREAKER_THRESHOLD):
            # Clear cache to force a fresh health probe each time
            _health_cache = __import__(
                "expose.pipeline.dispatcher", fromlist=["_health_cache"]
            )._health_cache
            _health_cache.pop("mock-always-unhealthy", None)

            result = await dispatcher.dispatch(
                _make_job("mock-always-unhealthy", seed),
            )
            assert result.status == DispatchStatus.HEALTH_CHECK_FAILED, (
                f"dispatch {i+1} should be HEALTH_CHECK_FAILED"
            )

        # Verify the breaker is now open
        assert _health_failure_counts.get("mock-always-unhealthy", 0) >= _CIRCUIT_BREAKER_THRESHOLD

        # Next dispatch should be short-circuited (no health check call)
        probes_before = MockAlwaysUnhealthyCollector.health_check_count
        result = await dispatcher.dispatch(
            _make_job("mock-always-unhealthy", seed),
        )
        assert result.status == DispatchStatus.HEALTH_CHECK_FAILED
        assert "Circuit breaker open" in (result.error_message or "")
        # No additional health probe should have been made
        assert MockAlwaysUnhealthyCollector.health_check_count == probes_before

    @pytest.mark.asyncio
    async def test_circuit_breaker_does_not_trip_below_threshold(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """Fewer than N failures does not open the circuit breaker.

        The collector is still probed on each dispatch (after cache
        eviction).
        """
        registry.register(MockAlwaysUnhealthyCollector)
        MockAlwaysUnhealthyCollector.health_check_count = 0

        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)

        # Dispatch one fewer than the threshold
        for _ in range(_CIRCUIT_BREAKER_THRESHOLD - 1):
            from expose.pipeline.dispatcher import _health_cache as _hc  # noqa: PLC0415

            _hc.pop("mock-always-unhealthy", None)
            result = await dispatcher.dispatch(
                _make_job("mock-always-unhealthy", seed),
            )
            assert result.status == DispatchStatus.HEALTH_CHECK_FAILED

        # Breaker should NOT be open yet
        assert (
            _health_failure_counts.get("mock-always-unhealthy", 0)
            < _CIRCUIT_BREAKER_THRESHOLD
        )

        # Next dispatch should still probe the health check (not short-circuited)
        from expose.pipeline.dispatcher import _health_cache as _hc2  # noqa: PLC0415

        _hc2.pop("mock-always-unhealthy", None)
        probes_before = MockAlwaysUnhealthyCollector.health_check_count
        result = await dispatcher.dispatch(
            _make_job("mock-always-unhealthy", seed),
        )
        assert result.status == DispatchStatus.HEALTH_CHECK_FAILED
        assert "Circuit breaker" not in (result.error_message or "")
        assert MockAlwaysUnhealthyCollector.health_check_count == probes_before + 1

    @pytest.mark.asyncio
    async def test_circuit_breaker_resets_on_success(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """A successful health check resets the failure counter to zero.

        If a collector fails twice (below threshold=3), then recovers,
        the counter is cleared. Subsequent failures start counting from
        zero again.
        """
        registry.register(MockRecoveringCollector)
        MockRecoveringCollector.call_count = 0
        MockRecoveringCollector.fail_until = 2

        dispatcher = PipelineDispatcher(registry, scope_empty, TENANT_ID)

        # First two dispatches: health check fails
        for _ in range(2):
            from expose.pipeline.dispatcher import _health_cache as _hc  # noqa: PLC0415

            _hc.pop("mock-recovering", None)
            result = await dispatcher.dispatch(
                _make_job("mock-recovering", seed),
            )
            assert result.status == DispatchStatus.HEALTH_CHECK_FAILED

        assert _health_failure_counts.get("mock-recovering", 0) == 2

        # Third dispatch: health check succeeds
        from expose.pipeline.dispatcher import _health_cache as _hc3  # noqa: PLC0415

        _hc3.pop("mock-recovering", None)
        result = await dispatcher.dispatch(
            _make_job("mock-recovering", seed),
        )
        assert result.status == DispatchStatus.SUCCESS

        # Failure counter should be reset
        assert _health_failure_counts.get("mock-recovering", 0) == 0

    @pytest.mark.asyncio
    async def test_clear_health_cache_resets_circuit_breaker(self) -> None:
        """clear_health_cache() also resets the circuit breaker failure counters."""
        _health_failure_counts["test-collector"] = 99
        _health_locks["test-collector"] = asyncio.Lock()
        clear_health_cache()
        assert _health_failure_counts == {}
        assert _health_locks == {}

    @pytest.mark.asyncio
    async def test_circuit_breaker_threshold_is_three(self) -> None:
        """Default circuit breaker threshold is 3."""
        assert _CIRCUIT_BREAKER_THRESHOLD == 3
