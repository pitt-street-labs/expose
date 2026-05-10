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
