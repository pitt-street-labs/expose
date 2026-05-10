"""Unit tests for the retention policy model (issue #12).

These are pure-unit tests — no database, no testcontainers, no I/O. The
retention policy layer is entirely deterministic: given an entity's age,
attribution status, and a tenant's policy configuration, the function
returns a ``RetentionDecision`` with the recommended action.

Coverage targets:
- Default policy values match SPEC §5.5 / §10.1
- Litigation hold overrides all actions
- Incidental (not_yours) entity lifecycle
- Owned entity hot → cold → delete lifecycle
- Unattributed entity treatment (conservative = incidental)
- Custom policy overrides
- Scheduler single + batch processing
- Enum value correctness
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from expose.maintenance.retention_policy import (
    RetentionAction,
    RetentionDecision,
    RetentionPolicy,
    RetentionScheduler,
    RetentionTier,
    evaluate_retention,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TENANT_ID = uuid4()


def _default_policy(**overrides: object) -> RetentionPolicy:
    """Build a policy with defaults, applying any keyword overrides."""
    return RetentionPolicy(tenant_id=_TENANT_ID, **overrides)  # type: ignore[arg-type]


def _decide(
    age_days: int,
    attribution_status: str,
    policy: RetentionPolicy | None = None,
) -> RetentionDecision:
    """Shorthand: run retention logic with a default entity identifier."""
    return evaluate_retention(
        entity_identifier="example.test",
        entity_age_days=age_days,
        attribution_status=attribution_status,
        policy=policy or _default_policy(),
    )


# ---------------------------------------------------------------------------
# 1. Default policy values match SPEC
# ---------------------------------------------------------------------------


def test_default_policy_matches_spec() -> None:
    """SPEC §5.5: 30-day incidental. §10.1: 365 hot, 2555 cold."""
    policy = _default_policy()
    assert policy.incidental_days == 30
    assert policy.hot_tier_days == 365
    assert policy.cold_tier_days == 2555
    assert policy.evidence_hot_days == 365
    assert policy.evidence_cold_days == 2555
    assert policy.litigation_hold is False


# ---------------------------------------------------------------------------
# 2. Litigation hold: always KEEP
# ---------------------------------------------------------------------------


def test_litigation_hold_keeps_regardless_of_age() -> None:
    """Litigation hold must override all deletion/migration decisions."""
    policy = _default_policy(litigation_hold=True)
    decision = evaluate_retention(
        entity_identifier="old.example.test",
        entity_age_days=10000,
        attribution_status="not_yours",
        policy=policy,
    )
    assert decision.action == RetentionAction.KEEP
    assert "litigation hold" in decision.reason


# ---------------------------------------------------------------------------
# 3. not_yours at 29 days: KEEP
# ---------------------------------------------------------------------------


def test_not_yours_within_window_kept() -> None:
    """A not_yours entity at 29 days (under 30-day default) should be kept."""
    decision = _decide(29, "not_yours")
    assert decision.action == RetentionAction.KEEP
    assert decision.current_tier == RetentionTier.HOT


# ---------------------------------------------------------------------------
# 4. not_yours at 31 days: DELETE
# ---------------------------------------------------------------------------


def test_not_yours_past_window_deleted() -> None:
    """A not_yours entity at 31 days (over 30-day default) should be deleted."""
    decision = _decide(31, "not_yours")
    assert decision.action == RetentionAction.DELETE
    assert decision.current_tier == RetentionTier.DELETE
    assert "incidental" in decision.reason


# ---------------------------------------------------------------------------
# 5. confirmed at 100 days: KEEP (hot)
# ---------------------------------------------------------------------------


def test_confirmed_entity_in_hot_tier() -> None:
    """A confirmed entity at 100 days (under 365-day hot) stays in hot tier."""
    decision = _decide(100, "confirmed")
    assert decision.action == RetentionAction.KEEP
    assert decision.current_tier == RetentionTier.HOT
    assert "hot tier" in decision.reason


# ---------------------------------------------------------------------------
# 6. confirmed at 400 days: MIGRATE_COLD
# ---------------------------------------------------------------------------


def test_confirmed_entity_migrates_to_cold() -> None:
    """A confirmed entity at 400 days (past 365 hot, within 365+2555 cold)
    should migrate to cold storage."""
    decision = _decide(400, "confirmed")
    assert decision.action == RetentionAction.MIGRATE_COLD
    assert decision.current_tier == RetentionTier.COLD
    assert "cold storage" in decision.reason


# ---------------------------------------------------------------------------
# 7. confirmed at 3000 days: DELETE
# ---------------------------------------------------------------------------


def test_confirmed_entity_past_cold_deleted() -> None:
    """A confirmed entity at 3000 days (past 365+2555=2920 total) should be
    deleted."""
    decision = _decide(3000, "confirmed")
    assert decision.action == RetentionAction.DELETE
    assert decision.current_tier == RetentionTier.DELETE


# ---------------------------------------------------------------------------
# 8. Unattributed treated as incidental
# ---------------------------------------------------------------------------


def test_unattributed_treated_as_incidental() -> None:
    """An entity with an unknown attribution status is treated as incidental
    (conservative default per module docstring)."""
    # Under window: kept
    decision_young = _decide(15, "unknown_status")
    assert decision_young.action == RetentionAction.KEEP
    assert "unattributed" in decision_young.reason

    # Over window: deleted
    decision_old = _decide(35, "unknown_status")
    assert decision_old.action == RetentionAction.DELETE
    assert "unattributed" in decision_old.reason


# ---------------------------------------------------------------------------
# 9. Custom policy overrides
# ---------------------------------------------------------------------------


def test_custom_policy_overrides_defaults() -> None:
    """A policy with custom values should use those instead of defaults."""
    policy = RetentionPolicy(
        tenant_id=_TENANT_ID,
        incidental_days=7,
        hot_tier_days=90,
        cold_tier_days=180,
    )
    # not_yours at 8 days: deleted with 7-day custom window
    decision = evaluate_retention(
        entity_identifier="custom.test",
        entity_age_days=8,
        attribution_status="not_yours",
        policy=policy,
    )
    assert decision.action == RetentionAction.DELETE

    # confirmed at 100 days: should be in cold tier (past 90-day hot)
    decision2 = evaluate_retention(
        entity_identifier="custom2.test",
        entity_age_days=100,
        attribution_status="confirmed",
        policy=policy,
    )
    assert decision2.action == RetentionAction.MIGRATE_COLD

    # confirmed at 280 days: past 90+180=270 total, should delete
    decision3 = evaluate_retention(
        entity_identifier="custom3.test",
        entity_age_days=280,
        attribution_status="confirmed",
        policy=policy,
    )
    assert decision3.action == RetentionAction.DELETE


# ---------------------------------------------------------------------------
# 10. Scheduler single-entity processing
# ---------------------------------------------------------------------------


def test_scheduler_single_entity() -> None:
    """RetentionScheduler wraps the retention function with the bound policy."""
    policy = _default_policy()
    scheduler = RetentionScheduler(policy)

    decision = scheduler.evaluate("sched.test", 400, "confirmed")
    assert decision.action == RetentionAction.MIGRATE_COLD
    assert decision.entity_identifier == "sched.test"
    assert decision.days_since_last_observed == 400


# ---------------------------------------------------------------------------
# 11. Scheduler batch processing
# ---------------------------------------------------------------------------


def test_scheduler_batch_processing() -> None:
    """Batch processing returns one decision per entity in input order."""
    policy = _default_policy()
    scheduler = RetentionScheduler(policy)

    entities: list[dict[str, int | str]] = [
        {"entity_identifier": "a.test", "age_days": 10, "attribution_status": "not_yours"},
        {"entity_identifier": "b.test", "age_days": 400, "attribution_status": "confirmed"},
        {"entity_identifier": "c.test", "age_days": 3000, "attribution_status": "high"},
    ]
    decisions = scheduler.evaluate_batch(entities)

    assert len(decisions) == 3
    assert decisions[0].action == RetentionAction.KEEP
    assert decisions[0].entity_identifier == "a.test"
    assert decisions[1].action == RetentionAction.MIGRATE_COLD
    assert decisions[1].entity_identifier == "b.test"
    assert decisions[2].action == RetentionAction.DELETE
    assert decisions[2].entity_identifier == "c.test"


# ---------------------------------------------------------------------------
# 12. Enum values
# ---------------------------------------------------------------------------


def test_retention_tier_values() -> None:
    """RetentionTier enum values match the expected strings."""
    assert RetentionTier.HOT.value == "hot"
    assert RetentionTier.COLD.value == "cold"
    assert RetentionTier.DELETE.value == "delete"
    assert len(RetentionTier) == 3


def test_retention_action_values() -> None:
    """RetentionAction enum values match the expected strings."""
    assert RetentionAction.KEEP.value == "keep"
    assert RetentionAction.MIGRATE_COLD.value == "migrate_cold"
    assert RetentionAction.DELETE.value == "delete"
    assert len(RetentionAction) == 3


# ---------------------------------------------------------------------------
# 13. Litigation hold overrides DELETE-eligible entities
# ---------------------------------------------------------------------------


def test_litigation_hold_overrides_delete_eligible() -> None:
    """Even a confirmed entity past the cold tier deadline must be kept when
    litigation hold is active."""
    policy = _default_policy(litigation_hold=True)

    # Confirmed entity at 5000 days — well past hot+cold=2920
    decision = evaluate_retention(
        entity_identifier="litigated.test",
        entity_age_days=5000,
        attribution_status="confirmed",
        policy=policy,
    )
    assert decision.action == RetentionAction.KEEP
    assert "litigation hold" in decision.reason
    assert decision.days_since_last_observed == 5000


# ---------------------------------------------------------------------------
# 14. All owned attribution statuses get full lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status",
    ["confirmed", "high", "medium", "requires_review"],
)
def test_all_owned_statuses_get_hot_cold_lifecycle(status: str) -> None:
    """Every owned attribution status follows the hot->cold->delete lifecycle."""
    policy = _default_policy()

    hot = evaluate_retention(
        entity_identifier=f"{status}.test",
        entity_age_days=100,
        attribution_status=status,
        policy=policy,
    )
    assert hot.action == RetentionAction.KEEP
    assert hot.current_tier == RetentionTier.HOT

    cold = evaluate_retention(
        entity_identifier=f"{status}.test",
        entity_age_days=500,
        attribution_status=status,
        policy=policy,
    )
    assert cold.action == RetentionAction.MIGRATE_COLD
    assert cold.current_tier == RetentionTier.COLD

    delete = evaluate_retention(
        entity_identifier=f"{status}.test",
        entity_age_days=3000,
        attribution_status=status,
        policy=policy,
    )
    assert delete.action == RetentionAction.DELETE
    assert delete.current_tier == RetentionTier.DELETE


# ---------------------------------------------------------------------------
# 15. Boundary conditions — exact day thresholds
# ---------------------------------------------------------------------------


def test_boundary_incidental_exact_day() -> None:
    """Entity at exactly the incidental_days threshold should be kept (> not >=)."""
    decision = _decide(30, "not_yours")
    assert decision.action == RetentionAction.KEEP


def test_boundary_hot_tier_exact_day() -> None:
    """Entity at exactly hot_tier_days should be kept (hot window is inclusive)."""
    decision = _decide(365, "confirmed")
    assert decision.action == RetentionAction.KEEP
    assert decision.current_tier == RetentionTier.HOT


def test_boundary_cold_tier_exact_day() -> None:
    """Entity at exactly hot+cold days should be migrated to cold (not deleted)."""
    decision = _decide(365 + 2555, "confirmed")
    assert decision.action == RetentionAction.MIGRATE_COLD
    assert decision.current_tier == RetentionTier.COLD


# ---------------------------------------------------------------------------
# 16. Model immutability and validation
# ---------------------------------------------------------------------------


def test_retention_policy_is_frozen() -> None:
    """RetentionPolicy is immutable — config changes require a new instance."""
    policy = _default_policy()
    with pytest.raises(Exception):  # noqa: B017
        policy.incidental_days = 99  # type: ignore[misc]


def test_retention_decision_is_frozen() -> None:
    """RetentionDecision is immutable — decisions cannot be altered after creation."""
    decision = _decide(10, "not_yours")
    with pytest.raises(Exception):  # noqa: B017
        decision.action = RetentionAction.DELETE  # type: ignore[misc]


def test_retention_policy_forbids_extra_fields() -> None:
    """RetentionPolicy rejects unknown fields (extra='forbid')."""
    with pytest.raises(Exception):  # noqa: B017
        RetentionPolicy(tenant_id=_TENANT_ID, bogus_field=42)  # type: ignore[call-arg]


def test_retention_policy_rejects_non_positive_days() -> None:
    """Zero or negative day values should be rejected by the gt=0 constraint."""
    with pytest.raises(Exception):  # noqa: B017
        RetentionPolicy(tenant_id=_TENANT_ID, incidental_days=0)
    with pytest.raises(Exception):  # noqa: B017
        RetentionPolicy(tenant_id=_TENANT_ID, hot_tier_days=-1)


# ---------------------------------------------------------------------------
# 17. Scheduler exposes its policy
# ---------------------------------------------------------------------------


def test_scheduler_policy_property() -> None:
    """RetentionScheduler.policy returns the bound policy."""
    policy = _default_policy()
    scheduler = RetentionScheduler(policy)
    assert scheduler.policy is policy
