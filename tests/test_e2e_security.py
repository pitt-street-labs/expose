"""End-to-end security and compliance tests for the EXPOSE platform.

Five tests covering cross-cutting security enforcement:

1. **Scope matcher blocks out-of-scope seeds** — ScopeMatcher with APEX_DOMAIN
   rule for ``other.net`` denies dispatch of ``example.com`` seed.
2. **Credential resolver injects credentials** — InMemorySecretsBackend with a
   stored key resolves correctly via CredentialResolver.
3. **Misuse detector alerts on high denial rate** — MisuseDetector with a low
   denial threshold fires HIGH_DENIAL_RATE alert.
4. **Multi-tenant entity isolation** — Two pipeline runs with different tenant
   IDs write only to their own entity repository.
5. **Enforcement log records refusals** — PipelineDispatcher with an empty
   TenantAuthorizationScope and a Tier-3 collector records a structured
   ScopeRefusalEvent.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
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
from expose.compliance.misuse_detection import (
    MisuseDetector,
    MisuseIndicator,
    MisuseThresholds,
)
from expose.pipeline.credential_resolver import (
    CREDENTIAL_SPECS,
    CollectorCredentialSpec,
    CredentialResolver,
)
from expose.pipeline.dispatcher import (
    DispatchJob,
    DispatchStatus,
    PipelineDispatcher,
)
from expose.pipeline.enforcement import EnforcementLog
from expose.pipeline.run_executor import RunExecutor
from expose.scope.matcher import ScopeMatcher
from expose.scope.models import AuthorizationScope, ScopeRule, ScopeRuleType
from expose.secrets.memory_backend import InMemoryBackend
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

# === Deterministic synthetic IDs (UUIDv7-style, greppable) ==================

TENANT_A = UUID("018f1f00-0000-7000-8000-00000000a001")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000b002")
RUN_A = UUID("018f1f00-0000-7000-8000-00000000a003")
RUN_B = UUID("018f1f00-0000-7000-8000-00000000b004")

_NOW = datetime(2026, 5, 10, 14, 0, 0, tzinfo=UTC)


# === Mock collectors ========================================================


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


class _MockTier1Collector(Collector):
    """Tier-1 collector that yields one observation and passes health check."""

    collector_id = "sec-mock-tier1"
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


class _MockTier3Collector(Collector):
    """Tier-3 collector subject to attribution/scope gating."""

    collector_id = "sec-mock-tier3"
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
            latency_ms=1.0,
        )


# === Helpers ================================================================


def _make_registry(*collectors: type[Collector]) -> CollectorRegistry:
    """Build a registry with the given collector classes."""
    reg = CollectorRegistry()
    for cls in collectors:
        reg.register(cls)
    return reg


def _make_job(
    collector_id: str,
    seed_value: str,
    tenant_id: UUID = TENANT_A,
    run_id: UUID = RUN_A,
) -> DispatchJob:
    return DispatchJob(
        collector_id=collector_id,
        seed=Seed(seed_type=SeedType.DOMAIN, value=seed_value),
        run_id=run_id,
        tenant_id=tenant_id,
    )


def _make_run_row(run_id: UUID, tenant_id: UUID, state: str = "pending") -> MagicMock:
    """Build a mock Run ORM row."""
    row = MagicMock()
    row.id = run_id
    row.tenant_id = tenant_id
    row.state = state
    return row


# === Tests ==================================================================


class TestE2eSecurity:
    """End-to-end security and compliance test suite."""

    async def test_scope_matcher_blocks_out_of_scope(self) -> None:
        """1. ScopeMatcher with APEX_DOMAIN 'other.net' denies 'example.com'.

        The dispatcher must return DENIED when the seed does not match any
        inclusion rule in the authorization scope. This validates the
        authorization perimeter enforcement path end-to-end from
        PipelineDispatcher through ScopeMatcher.
        """
        auth_scope = AuthorizationScope(
            tenant_id=TENANT_A,
            rules=[
                ScopeRule(
                    rule_type=ScopeRuleType.APEX_DOMAIN,
                    value="other.net",
                ),
            ],
            last_modified=_NOW,
            modified_by="test",
        )
        matcher = ScopeMatcher(auth_scope)
        registry = _make_registry(_MockTier1Collector)
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(),
        )
        dispatcher = PipelineDispatcher(
            registry,
            scope,
            TENANT_A,
            scope_matcher=matcher,
        )

        result = await dispatcher.dispatch(
            _make_job("sec-mock-tier1", "example.com"),
        )

        assert result.status == DispatchStatus.DENIED
        assert result.observations == []
        assert result.error_message is not None
        assert "No matching scope rule found" in result.error_message

    async def test_credential_resolver_injects_credentials(self) -> None:
        """2. CredentialResolver fetches secrets from InMemoryBackend.

        Stores a secret in the InMemoryBackend under the convention key
        ``collector.shodan-test.api_key``, creates a CredentialResolver,
        and verifies that ``resolve()`` returns the correct credential.
        """
        # Temporarily register a spec with a required key so we can test
        # the resolve path. Save and restore to avoid polluting other tests.
        original = CREDENTIAL_SPECS.get("shodan-test")
        try:
            CREDENTIAL_SPECS["shodan-test"] = CollectorCredentialSpec(
                collector_id="shodan-test",
                required_keys=["api_key"],
            )

            backend = InMemoryBackend()
            await backend.set(
                tenant_id=TENANT_A,
                key="collector.shodan-test.api_key",
                value="sk-test-12345",
            )

            resolver = CredentialResolver(backend)
            credentials = await resolver.resolve(TENANT_A, "shodan-test")

            assert "api_key" in credentials
            assert credentials["api_key"].name == "api_key"
            assert credentials["api_key"].secret_value == "sk-test-12345"  # noqa: S105
        finally:
            # Restore original state of the module-level dict.
            if original is None:
                CREDENTIAL_SPECS.pop("shodan-test", None)
            else:
                CREDENTIAL_SPECS["shodan-test"] = original  # pragma: no cover

    async def test_misuse_detector_alerts_high_denial(self) -> None:
        """3. MisuseDetector fires HIGH_DENIAL_RATE when denials exceed threshold.

        With a low denial_rate_pct threshold (0.3) and 15 out of 20
        dispatches denied (75%), the detector must produce at least one
        alert with indicator HIGH_DENIAL_RATE.
        """
        detector = MisuseDetector(
            thresholds=MisuseThresholds(denial_rate_pct=0.3),
        )

        alerts = detector.evaluate_run(
            tenant_id=TENANT_A,
            run_id=RUN_A,
            in_scope=1,
            out_of_scope=0,
            tier3_dispatches=0,
            total_dispatches=20,
            denied=15,
            run_timestamp=datetime.now(UTC),
        )

        assert len(alerts) > 0
        denial_alerts = [
            a for a in alerts if a.indicator == MisuseIndicator.HIGH_DENIAL_RATE
        ]
        assert len(denial_alerts) == 1
        alert = denial_alerts[0]
        assert alert.tenant_id == TENANT_A
        assert alert.run_id == RUN_A
        assert alert.evidence["denied"] == 15
        assert alert.evidence["total"] == 20
        assert alert.evidence["denial_rate"] == 0.75

    @pytest.mark.integration
    async def test_multi_tenant_entity_isolation(self) -> None:
        """4. Two pipeline runs with different tenants write only to their own repo.

        Executes two RunExecutor.execute() calls — one for TENANT_A and one
        for TENANT_B — each with its own entity_repo mock. Verifies that
        each entity_repo only received create_or_update calls for its own
        tenant_id.
        """
        registry = _make_registry(_MockTier1Collector)

        # --- Tenant A setup ---
        scope_a = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset({"alpha.com"}),
        )
        dispatcher_a = PipelineDispatcher(registry, scope_a, TENANT_A)

        run_repo_a = AsyncMock()
        run_repo_a.get_by_id = AsyncMock(
            return_value=_make_run_row(RUN_A, TENANT_A),
        )
        run_repo_a.update_state = AsyncMock()

        entity_repo_a = AsyncMock()
        entity_repo_a.create_or_update = AsyncMock(return_value=MagicMock())

        executor_a = RunExecutor(
            dispatcher=dispatcher_a,
            run_repo=run_repo_a,
            entity_repo=entity_repo_a,
        )

        # --- Tenant B setup ---
        scope_b = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset({"bravo.com"}),
        )
        dispatcher_b = PipelineDispatcher(registry, scope_b, TENANT_B)

        run_repo_b = AsyncMock()
        run_repo_b.get_by_id = AsyncMock(
            return_value=_make_run_row(RUN_B, TENANT_B),
        )
        run_repo_b.update_state = AsyncMock()

        entity_repo_b = AsyncMock()
        entity_repo_b.create_or_update = AsyncMock(return_value=MagicMock())

        executor_b = RunExecutor(
            dispatcher=dispatcher_b,
            run_repo=run_repo_b,
            entity_repo=entity_repo_b,
        )

        # --- Execute both runs ---
        result_a = await executor_a.execute(
            run_id=RUN_A,
            tenant_id=TENANT_A,
            seeds=[Seed(seed_type=SeedType.DOMAIN, value="alpha.com")],
            collector_ids=["sec-mock-tier1"],
        )
        result_b = await executor_b.execute(
            run_id=RUN_B,
            tenant_id=TENANT_B,
            seeds=[Seed(seed_type=SeedType.DOMAIN, value="bravo.com")],
            collector_ids=["sec-mock-tier1"],
        )

        # Both runs should complete successfully.
        assert result_a.final_state == "completed"
        assert result_b.final_state == "completed"

        # Both repos should have been called at least once.
        assert entity_repo_a.create_or_update.call_count >= 1
        assert entity_repo_b.create_or_update.call_count >= 1

        # RunExecutor calls entity_repo.create_or_update with keyword args
        # including tenant_id. Verify each repo only received its own tenant.
        for call in entity_repo_a.create_or_update.call_args_list:
            tid = call.kwargs.get("tenant_id")
            assert tid is not None, "create_or_update called without tenant_id"
            assert UUID(str(tid)) == TENANT_A, (
                f"Tenant A repo received call for wrong tenant: {tid}"
            )

        for call in entity_repo_b.create_or_update.call_args_list:
            tid = call.kwargs.get("tenant_id")
            assert tid is not None, "create_or_update called without tenant_id"
            assert UUID(str(tid)) == TENANT_B, (
                f"Tenant B repo received call for wrong tenant: {tid}"
            )

    async def test_enforcement_log_records_refusals(self) -> None:
        """5. EnforcementLog records a ScopeRefusalEvent for a Tier-3 denial.

        Dispatching a Tier-3 collector against an entity that is NOT in the
        tenant's empty authorization scope must result in a DENIED status
        and a recorded refusal event with the correct entity identifier
        and collector ID.
        """
        registry = _make_registry(_MockTier3Collector)
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(),
        )
        log = EnforcementLog()
        dispatcher = PipelineDispatcher(
            registry,
            scope,
            TENANT_A,
            enforcement_log=log,
        )

        result = await dispatcher.dispatch(
            _make_job("sec-mock-tier3", "example.com"),
        )

        assert result.status == DispatchStatus.DENIED
        assert result.observations == []
        assert log.refusal_count == 1

        refusal = log.refusals[0]
        assert refusal.entity_identifier == "example.com"
        assert refusal.collector_id == "sec-mock-tier3"
        assert refusal.tenant_id == TENANT_A
        assert "Tier-3 dispatch denied" in refusal.reason
