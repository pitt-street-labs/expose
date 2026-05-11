"""Tests for authorization-scope enforcement mode (Gitea issue #29).

Coverage:

- ``ScopeRefusalEvent`` model validation (Pydantic frozen, extra=forbid).
- ``EnforcementLog`` accumulation, count, and immutability.
- ``EnforcementMode`` enum membership and default on ``TenantAuthorizationScope``.
- Tier-3 gating behavior is mode-independent (``is_tier_3_dispatch_allowed``
  returns the same bool regardless of enforcement mode; the caller decides
  how to act on ``False``).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from expose.collectors.tiers import (
    EnforcementMode,
    EntityAttributionView,
    TenantAuthorizationScope,
    is_tier_3_dispatch_allowed,
)
from expose.pipeline.enforcement import EnforcementLog, ScopeRefusalEvent
from expose.types.canonical import AttributionTier

# Synthetic IDs — deterministic, grep-friendly.
TENANT_A = UUID("018f1f00-0000-7000-8000-00000000E001")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000E002")


def _make_refusal(
    *,
    tenant_id: UUID = TENANT_A,
    entity_identifier: str = "unknown.example",
    attribution_tier: str | None = None,
    enforcement_mode: EnforcementMode = EnforcementMode.HARD,
    collector_id: str = "tls-prober",
    reason: str = "Entity not in authorization scope",
    timestamp: datetime | None = None,
) -> ScopeRefusalEvent:
    """Factory for ``ScopeRefusalEvent`` with sensible defaults."""
    return ScopeRefusalEvent(
        tenant_id=tenant_id,
        entity_identifier=entity_identifier,
        attribution_tier=attribution_tier,
        enforcement_mode=enforcement_mode,
        collector_id=collector_id,
        reason=reason,
        timestamp=timestamp or datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
    )


# === ScopeRefusalEvent model ==================================================
class TestScopeRefusalEvent:
    """Pydantic model validation for structured refusal records."""

    def test_valid_event_round_trips(self) -> None:
        """A well-formed event constructs and serializes without error."""
        event = _make_refusal()
        assert event.tenant_id == TENANT_A
        assert event.entity_identifier == "unknown.example"
        assert event.attribution_tier is None
        assert event.enforcement_mode == EnforcementMode.HARD
        assert event.collector_id == "tls-prober"
        assert event.reason == "Entity not in authorization scope"

    def test_event_is_frozen(self) -> None:
        """Events are immutable after construction."""
        event = _make_refusal()
        with pytest.raises(ValidationError):
            event.entity_identifier = "mutated.example"  # type: ignore[misc]

    def test_event_rejects_extra_fields(self) -> None:
        """Extra fields are rejected (extra=forbid)."""
        with pytest.raises(ValidationError):
            ScopeRefusalEvent(
                tenant_id=TENANT_A,
                entity_identifier="x.example",
                attribution_tier=None,
                enforcement_mode=EnforcementMode.HARD,
                collector_id="tls-prober",
                reason="test",
                timestamp=datetime(2026, 5, 10, tzinfo=UTC),
                unexpected_field="should fail",  # type: ignore[call-arg]
            )

    def test_event_requires_non_empty_entity_identifier(self) -> None:
        """Empty entity identifier is rejected."""
        with pytest.raises(ValidationError):
            _make_refusal(entity_identifier="")

    def test_event_requires_non_empty_collector_id(self) -> None:
        """Empty collector ID is rejected."""
        with pytest.raises(ValidationError):
            _make_refusal(collector_id="")

    def test_event_requires_non_empty_reason(self) -> None:
        """Empty reason is rejected."""
        with pytest.raises(ValidationError):
            _make_refusal(reason="")

    def test_event_includes_all_required_fields(self) -> None:
        """Every field declared on the model is present in the instance."""
        event = _make_refusal(
            attribution_tier="medium",
            enforcement_mode=EnforcementMode.MEDIUM,
        )
        # Verify via model_fields_set — all fields were explicitly provided.
        expected_fields = {
            "tenant_id",
            "entity_identifier",
            "attribution_tier",
            "enforcement_mode",
            "collector_id",
            "reason",
            "timestamp",
        }
        assert event.model_fields_set == expected_fields

    def test_event_accepts_string_attribution_tier(self) -> None:
        """attribution_tier is str | None, not the enum — allows any tier label."""
        event = _make_refusal(attribution_tier="confirmed")
        assert event.attribution_tier == "confirmed"


# === EnforcementLog ===========================================================
class TestEnforcementLog:
    """Accumulation and immutability of the per-run enforcement log."""

    def test_empty_log_has_zero_count(self) -> None:
        """A fresh log has no refusals."""
        log = EnforcementLog()
        assert log.refusal_count == 0
        assert log.refusals == []

    def test_record_refusal_increments_count(self) -> None:
        """Each recorded event increments the count."""
        log = EnforcementLog()
        log.record_refusal(_make_refusal())
        assert log.refusal_count == 1
        log.record_refusal(_make_refusal(entity_identifier="second.example"))
        assert log.refusal_count == 2

    def test_refusals_returns_copy(self) -> None:
        """Mutating the returned list does not affect the log's internal state."""
        log = EnforcementLog()
        log.record_refusal(_make_refusal())
        snapshot = log.refusals
        snapshot.clear()  # mutate the copy
        assert log.refusal_count == 1  # original unaffected
        assert len(log.refusals) == 1

    def test_refusals_contain_recorded_events(self) -> None:
        """Refusal list contains the exact events that were recorded."""
        log = EnforcementLog()
        e1 = _make_refusal(entity_identifier="a.example")
        e2 = _make_refusal(entity_identifier="b.example")
        log.record_refusal(e1)
        log.record_refusal(e2)
        refusals = log.refusals
        assert refusals[0].entity_identifier == "a.example"
        assert refusals[1].entity_identifier == "b.example"

    def test_record_refusal_emits_log_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Recording a refusal emits a warning-level log message."""
        log = EnforcementLog()
        with caplog.at_level(logging.WARNING, logger="expose.pipeline.enforcement"):
            log.record_refusal(_make_refusal(entity_identifier="logged.example"))
        assert "logged.example" in caplog.text
        assert "Scope refusal" in caplog.text


# === EnforcementMode on TenantAuthorizationScope ==============================
class TestEnforcementModeIntegration:
    """Enforcement mode field on the authorization scope dataclass."""

    def test_default_enforcement_mode_is_medium(self) -> None:
        """Without explicit mode, scope defaults to MEDIUM."""
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(),
        )
        assert scope.enforcement_mode == EnforcementMode.MEDIUM

    def test_explicit_hard_mode(self) -> None:
        """Hard mode can be set explicitly."""
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(["a.example"]),
            enforcement_mode=EnforcementMode.HARD,
        )
        assert scope.enforcement_mode == EnforcementMode.HARD

    def test_medium_mode_gating_unchanged_confirmed_passes(self) -> None:
        """Medium mode: confirmed attribution passes (existing behavior)."""
        entity = EntityAttributionView(
            entity_identifier="api.acme.example",
            attribution_tier=AttributionTier.CONFIRMED,
        )
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(),
            enforcement_mode=EnforcementMode.MEDIUM,
        )
        assert is_tier_3_dispatch_allowed(entity, scope)

    def test_medium_mode_gating_unchanged_unattributed_denied(self) -> None:
        """Medium mode: unattributed entity outside scope is denied."""
        entity = EntityAttributionView(
            entity_identifier="unknown.example",
            attribution_tier=None,
        )
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(),
            enforcement_mode=EnforcementMode.MEDIUM,
        )
        assert not is_tier_3_dispatch_allowed(entity, scope)

    def test_hard_mode_gating_confirmed_passes(self) -> None:
        """Hard mode: same bool result as medium for confirmed attribution."""
        entity = EntityAttributionView(
            entity_identifier="api.acme.example",
            attribution_tier=AttributionTier.CONFIRMED,
        )
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(),
            enforcement_mode=EnforcementMode.HARD,
        )
        assert is_tier_3_dispatch_allowed(entity, scope)

    def test_hard_mode_gating_unattributed_denied(self) -> None:
        """Hard mode: unattributed out-of-scope is denied (same bool)."""
        entity = EntityAttributionView(
            entity_identifier="unknown.example",
            attribution_tier=None,
        )
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(),
            enforcement_mode=EnforcementMode.HARD,
        )
        assert not is_tier_3_dispatch_allowed(entity, scope)

    def test_hard_mode_scope_membership_overrides(self) -> None:
        """Hard mode: explicit scope membership still allows dispatch."""
        entity = EntityAttributionView(
            entity_identifier="in-scope.example",
            attribution_tier=None,
        )
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(["in-scope.example"]),
            enforcement_mode=EnforcementMode.HARD,
        )
        assert is_tier_3_dispatch_allowed(entity, scope)


# === EnforcementMode enum =====================================================
class TestEnforcementModeEnum:
    """EnforcementMode StrEnum has exactly the expected members."""

    def test_has_medium(self) -> None:
        assert EnforcementMode.MEDIUM == "medium"

    def test_has_hard(self) -> None:
        assert EnforcementMode.HARD == "hard"

    def test_exactly_two_members(self) -> None:
        assert len(EnforcementMode) == 2

    def test_is_str_enum(self) -> None:
        """Values are plain strings for JSON serialization."""
        assert isinstance(EnforcementMode.MEDIUM, str)
        assert isinstance(EnforcementMode.HARD, str)


# === Dispatcher integration — enforcement log wiring ==========================


class TestEnforcementDispatcherWiring:
    """Verify that enforcement logging works end-to-end through the dispatcher.

    These tests import the dispatcher and mock collectors to confirm that
    refusal events flow from denied dispatches into the enforcement log.
    """

    @pytest.fixture()
    def _dispatcher_fixtures(self) -> tuple:
        """Build a dispatcher registry with Tier-1 and Tier-3 mock collectors."""
        from collections.abc import AsyncIterator  # noqa: PLC0415
        from uuid import UUID as _UUID  # noqa: PLC0415

        from expose.collectors.base import (  # noqa: PLC0415
            Collector,
            CollectorConfig,
            CollectorHealthCheck,
            Observation,
            ObservationSubject,
            ObservationType,
            Seed,
            SeedType,
        )
        from expose.collectors.registry import CollectorRegistry  # noqa: PLC0415
        from expose.collectors.tiers import CollectorTier  # noqa: PLC0415
        from expose.types.canonical import CollectorStatus, ExtendedIdentifierType  # noqa: PLC0415

        _now = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)

        class _Tier1(Collector):
            collector_id = "enf-tier1"
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
                    observed_at=_now,
                )

            async def health_check(self) -> CollectorHealthCheck:
                return CollectorHealthCheck(
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    status=CollectorStatus.SUCCESS,
                    checked_at=_now,
                    latency_ms=1.0,
                )

        class _Tier3(Collector):
            collector_id = "enf-tier3"
            collector_version = "1.0.0"
            requires_credentials = False
            rate_limit_per_minute = None
            tier = CollectorTier.TIER_3

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
                    observed_at=_now,
                )

            async def health_check(self) -> CollectorHealthCheck:
                return CollectorHealthCheck(
                    collector_id=self.collector_id,
                    collector_version=self.collector_version,
                    status=CollectorStatus.SUCCESS,
                    checked_at=_now,
                    latency_ms=1.0,
                )

        reg = CollectorRegistry()
        reg.register(_Tier1)
        reg.register(_Tier3)

        seed = Seed(seed_type=SeedType.DOMAIN, value="target.example")

        return reg, seed, _Tier1, _Tier3

    @pytest.mark.asyncio
    async def test_enforcement_denied_dispatch_creates_refusal(
        self,
        _dispatcher_fixtures: tuple,
    ) -> None:
        """Denied Tier-3 dispatch records a ScopeRefusalEvent in the log."""
        from expose.pipeline.dispatcher import (  # noqa: PLC0415
            DispatchJob,
            DispatchStatus,
            PipelineDispatcher,
        )

        reg, seed, _, _ = _dispatcher_fixtures
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(),
        )
        log = EnforcementLog()
        dispatcher = PipelineDispatcher(
            reg, scope, TENANT_A, enforcement_log=log,
        )

        run_id = UUID("018f1f00-0000-7000-8000-00000000E010")
        job = DispatchJob(
            collector_id="enf-tier3",
            seed=seed,
            run_id=run_id,
            tenant_id=TENANT_A,
        )
        result = await dispatcher.dispatch(job)

        assert result.status == DispatchStatus.DENIED
        assert log.refusal_count == 1
        refusal = log.refusals[0]
        assert refusal.tenant_id == TENANT_A
        assert refusal.entity_identifier == "target.example"
        assert refusal.collector_id == "enf-tier3"

    @pytest.mark.asyncio
    async def test_enforcement_log_none_safe(
        self,
        _dispatcher_fixtures: tuple,
    ) -> None:
        """Dispatcher with enforcement_log=None does not crash."""
        from expose.pipeline.dispatcher import (  # noqa: PLC0415
            DispatchJob,
            DispatchStatus,
            PipelineDispatcher,
        )

        reg, seed, _, _ = _dispatcher_fixtures
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(),
        )
        dispatcher = PipelineDispatcher(
            reg, scope, TENANT_A, enforcement_log=None,
        )

        run_id = UUID("018f1f00-0000-7000-8000-00000000E011")
        job = DispatchJob(
            collector_id="enf-tier3",
            seed=seed,
            run_id=run_id,
            tenant_id=TENANT_A,
        )
        # Should not raise, even though no external log is provided
        result = await dispatcher.dispatch(job)
        assert result.status == DispatchStatus.DENIED

    @pytest.mark.asyncio
    async def test_enforcement_refusals_serialized(
        self,
        _dispatcher_fixtures: tuple,
    ) -> None:
        """Refusals serialize to JSON-compatible dicts."""
        from expose.pipeline.dispatcher import (  # noqa: PLC0415
            DispatchJob,
            PipelineDispatcher,
        )

        reg, seed, _, _ = _dispatcher_fixtures
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(),
        )
        log = EnforcementLog()
        dispatcher = PipelineDispatcher(
            reg, scope, TENANT_A, enforcement_log=log,
        )

        run_id = UUID("018f1f00-0000-7000-8000-00000000E012")
        job = DispatchJob(
            collector_id="enf-tier3",
            seed=seed,
            run_id=run_id,
            tenant_id=TENANT_A,
        )
        await dispatcher.dispatch(job)

        serialized = [r.model_dump(mode="json") for r in log.refusals]
        assert len(serialized) == 1
        entry = serialized[0]
        assert isinstance(entry, dict)
        assert entry["entity_identifier"] == "target.example"
        assert entry["collector_id"] == "enf-tier3"
        assert entry["tenant_id"] == str(TENANT_A)
        assert isinstance(entry["timestamp"], str)
        assert "enforcement_mode" in entry

    @pytest.mark.asyncio
    async def test_enforcement_tier3_denial_recorded(
        self,
        _dispatcher_fixtures: tuple,
    ) -> None:
        """Tier-3 denial records refusal with HARD enforcement mode when scope is HARD."""
        from expose.pipeline.dispatcher import (  # noqa: PLC0415
            DispatchJob,
            DispatchStatus,
            PipelineDispatcher,
        )

        reg, seed, _, _ = _dispatcher_fixtures
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(),
            enforcement_mode=EnforcementMode.HARD,
        )
        log = EnforcementLog()
        dispatcher = PipelineDispatcher(
            reg, scope, TENANT_A, enforcement_log=log,
        )

        run_id = UUID("018f1f00-0000-7000-8000-00000000E013")
        job = DispatchJob(
            collector_id="enf-tier3",
            seed=seed,
            run_id=run_id,
            tenant_id=TENANT_A,
        )
        result = await dispatcher.dispatch(job)

        assert result.status == DispatchStatus.DENIED
        assert log.refusal_count == 1
        refusal = log.refusals[0]
        assert refusal.enforcement_mode == EnforcementMode.HARD
        assert "Tier-3 dispatch denied" in refusal.reason
        assert refusal.entity_identifier == "target.example"

    @pytest.mark.asyncio
    async def test_enforcement_allowed_dispatch_no_refusal(
        self,
        _dispatcher_fixtures: tuple,
    ) -> None:
        """Successful Tier-1 dispatch does not create any refusal events."""
        from expose.pipeline.dispatcher import (  # noqa: PLC0415
            DispatchJob,
            DispatchStatus,
            PipelineDispatcher,
        )

        reg, seed, _, _ = _dispatcher_fixtures
        scope = TenantAuthorizationScope(
            explicit_entity_identifiers=frozenset(),
        )
        log = EnforcementLog()
        dispatcher = PipelineDispatcher(
            reg, scope, TENANT_A, enforcement_log=log,
        )

        run_id = UUID("018f1f00-0000-7000-8000-00000000E014")
        job = DispatchJob(
            collector_id="enf-tier1",
            seed=seed,
            run_id=run_id,
            tenant_id=TENANT_A,
        )
        result = await dispatcher.dispatch(job)

        assert result.status == DispatchStatus.SUCCESS
        assert log.refusal_count == 0
