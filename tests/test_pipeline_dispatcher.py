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
    DispatchJob,
    DispatchResult,
    DispatchStatus,
    PipelineDispatcher,
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
    async def test_credential_resolver_error_returns_collector_error(
        self,
        registry: CollectorRegistry,
        scope_empty: TenantAuthorizationScope,
        seed: Seed,
    ) -> None:
        """17. CredentialResolutionError returns COLLECTOR_ERROR."""
        resolver = AsyncMock(spec=CredentialResolver)
        resolver.resolve = AsyncMock(
            side_effect=CredentialResolutionError("missing api_key"),
        )

        dispatcher = PipelineDispatcher(
            registry, scope_empty, TENANT_ID, credential_resolver=resolver,
        )
        result = await dispatcher.dispatch(_make_job("mock-tier1", seed))

        assert result.status == DispatchStatus.COLLECTOR_ERROR
        assert result.observations == []
        assert result.error_message == "missing api_key"
