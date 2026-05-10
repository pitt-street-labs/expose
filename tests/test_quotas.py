"""Tests for per-tenant resource quotas (issue #24).

Coverage:

1.  Default quota values are sensible.
2.  set_quota + get_quota round-trip.
3.  check_run_allowed returns allowed=True when under quota.
4.  check_run_allowed returns allowed=False when at daily limit.
5.  check_entity_limit under quota returns allowed.
6.  check_entity_limit over quota returns denied with reason.
7.  record_run_start increments active_runs and runs_today.
8.  record_run_complete decrements active_runs.
9.  Max concurrent runs enforced.
10. assert_run_allowed raises QuotaExceededError.
11. Unknown tenant_id uses default quota.
12. QuotaCheckResult includes descriptive reason and field name.
13. record_run_complete does not go below zero (defensive).
14. record_entities_added accumulates correctly.
15. Frozen model rejects extra fields.
"""

from __future__ import annotations

from uuid import UUID

import pytest
from pydantic import ValidationError

from expose.quotas import (
    QuotaCheckResult,
    QuotaExceededError,
    QuotaTracker,
    TenantQuota,
)

# Synthetic tenant UUIDs matching the project convention from
# tests/test_tenant_isolation.py and tests/test_secrets.py.
TENANT_A = UUID("018f1f00-0000-7000-8000-00000000A001")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000B002")


@pytest.fixture
def tracker() -> QuotaTracker:
    """Fresh tracker per test (no cross-test bleed)."""
    return QuotaTracker()


# -- 1. Default quota values are sensible ------------------------------------


def test_default_quota_values() -> None:
    """Default TenantQuota has reasonable limits for a mid-size deployment."""
    q = TenantQuota(tenant_id=TENANT_A)
    assert q.max_runs_per_day == 100
    assert q.max_entities == 1_000_000
    assert q.max_collectors_per_run == 20
    assert q.max_seeds_per_run == 1000
    assert q.max_evidence_storage_gb == 100.0
    assert q.max_concurrent_runs == 5


# -- 2. set_quota + get_quota round-trip -------------------------------------


def test_set_get_quota_round_trip(tracker: QuotaTracker) -> None:
    """A quota stored via set_quota is returned verbatim by get_quota."""
    quota = TenantQuota(tenant_id=TENANT_A, max_runs_per_day=10, max_entities=500)
    tracker.set_quota(quota)
    got = tracker.get_quota(TENANT_A)
    assert got == quota
    assert got.max_runs_per_day == 10
    assert got.max_entities == 500


# -- 3. check_run_allowed under quota returns allowed -----------------------


def test_check_run_allowed_under_quota(tracker: QuotaTracker) -> None:
    """A fresh tenant with no usage is allowed to start a run."""
    result = tracker.check_run_allowed(TENANT_A)
    assert result.allowed is True
    assert result.reason is None
    assert result.quota_field is None


# -- 4. check_run_allowed at daily limit returns denied ----------------------


def test_check_run_allowed_daily_limit(tracker: QuotaTracker) -> None:
    """When daily runs are exhausted, check_run_allowed returns denied."""
    tracker.set_quota(TenantQuota(tenant_id=TENANT_A, max_runs_per_day=2))
    tracker.record_run_start(TENANT_A)
    tracker.record_run_complete(TENANT_A)
    tracker.record_run_start(TENANT_A)
    tracker.record_run_complete(TENANT_A)

    result = tracker.check_run_allowed(TENANT_A)
    assert result.allowed is False
    assert result.quota_field == "max_runs_per_day"
    assert result.current_value == 2
    assert result.limit_value == 2


# -- 5. check_entity_limit under quota returns allowed -----------------------


def test_check_entity_limit_under_quota(tracker: QuotaTracker) -> None:
    """Adding entities within the limit is allowed."""
    tracker.set_quota(TenantQuota(tenant_id=TENANT_A, max_entities=100))
    tracker.record_entities_added(TENANT_A, 50)

    result = tracker.check_entity_limit(TENANT_A, additional=10)
    assert result.allowed is True


# -- 6. check_entity_limit over quota returns denied with reason -------------


def test_check_entity_limit_over_quota(tracker: QuotaTracker) -> None:
    """Adding entities beyond the limit is denied with a descriptive reason."""
    tracker.set_quota(TenantQuota(tenant_id=TENANT_A, max_entities=100))
    tracker.record_entities_added(TENANT_A, 95)

    result = tracker.check_entity_limit(TENANT_A, additional=10)
    assert result.allowed is False
    assert result.quota_field == "max_entities"
    assert result.current_value == 95
    assert result.limit_value == 100
    assert result.reason is not None
    assert "105" in result.reason  # projected count appears in the message


# -- 7. record_run_start increments both counters ---------------------------


def test_record_run_start_increments(tracker: QuotaTracker) -> None:
    """record_run_start bumps both runs_today and active_runs."""
    tracker.record_run_start(TENANT_A)
    usage = tracker.get_usage(TENANT_A)
    assert usage.runs_today == 1
    assert usage.active_runs == 1

    tracker.record_run_start(TENANT_A)
    usage = tracker.get_usage(TENANT_A)
    assert usage.runs_today == 2
    assert usage.active_runs == 2


# -- 8. record_run_complete decrements active_runs --------------------------


def test_record_run_complete_decrements(tracker: QuotaTracker) -> None:
    """record_run_complete decreases active_runs but NOT runs_today."""
    tracker.record_run_start(TENANT_A)
    tracker.record_run_start(TENANT_A)
    tracker.record_run_complete(TENANT_A)

    usage = tracker.get_usage(TENANT_A)
    assert usage.active_runs == 1
    assert usage.runs_today == 2  # daily total unchanged


# -- 9. Max concurrent runs enforced ----------------------------------------


def test_max_concurrent_runs_enforced(tracker: QuotaTracker) -> None:
    """When all concurrent slots are full, new runs are denied."""
    tracker.set_quota(TenantQuota(tenant_id=TENANT_A, max_concurrent_runs=2))
    tracker.record_run_start(TENANT_A)
    tracker.record_run_start(TENANT_A)

    result = tracker.check_run_allowed(TENANT_A)
    assert result.allowed is False
    assert result.quota_field == "max_concurrent_runs"
    assert result.current_value == 2
    assert result.limit_value == 2

    # Completing one frees a slot.
    tracker.record_run_complete(TENANT_A)
    result = tracker.check_run_allowed(TENANT_A)
    assert result.allowed is True


# -- 10. assert_run_allowed raises QuotaExceededError -----------------------


def test_assert_run_allowed_raises(tracker: QuotaTracker) -> None:
    """assert_run_allowed raises QuotaExceededError when denied."""
    tracker.set_quota(TenantQuota(tenant_id=TENANT_A, max_runs_per_day=0))

    with pytest.raises(QuotaExceededError) as exc_info:
        tracker.assert_run_allowed(TENANT_A)

    assert exc_info.value.result.allowed is False
    assert exc_info.value.result.quota_field == "max_runs_per_day"
    assert "Daily run limit" in str(exc_info.value)


# -- 11. Unknown tenant_id uses default quota --------------------------------


def test_unknown_tenant_gets_default_quota(tracker: QuotaTracker) -> None:
    """A tenant with no explicit quota receives default limits."""
    unknown = UUID("018f1f00-0000-7000-8000-0000000FF099")
    quota = tracker.get_quota(unknown)

    assert quota.tenant_id == unknown
    assert quota.max_runs_per_day == 100
    assert quota.max_entities == 1_000_000

    # And operations against that tenant work normally.
    result = tracker.check_run_allowed(unknown)
    assert result.allowed is True


# -- 12. QuotaCheckResult includes descriptive reason and field name ---------


def test_quota_check_result_diagnostic_fields(tracker: QuotaTracker) -> None:
    """Denied results carry reason, quota_field, current_value, limit_value."""
    tracker.set_quota(TenantQuota(tenant_id=TENANT_A, max_entities=10))
    tracker.record_entities_added(TENANT_A, 10)

    result = tracker.check_entity_limit(TENANT_A, additional=1)
    assert result.allowed is False
    assert result.reason is not None
    assert "max_entities" not in result.reason or result.quota_field == "max_entities"
    assert result.quota_field == "max_entities"
    assert result.current_value == 10
    assert result.limit_value == 10

    # Allowed results have None for diagnostic fields.
    allowed = QuotaCheckResult(allowed=True)
    assert allowed.reason is None
    assert allowed.quota_field is None
    assert allowed.current_value is None
    assert allowed.limit_value is None


# -- 13. record_run_complete does not go below zero --------------------------


def test_run_complete_does_not_go_negative(tracker: QuotaTracker) -> None:
    """Completing more runs than started does not produce negative active_runs."""
    tracker.record_run_complete(TENANT_A)
    tracker.record_run_complete(TENANT_A)

    usage = tracker.get_usage(TENANT_A)
    assert usage.active_runs == 0


# -- 14. record_entities_added accumulates correctly -------------------------


def test_entities_added_accumulates(tracker: QuotaTracker) -> None:
    """Multiple record_entities_added calls accumulate the total."""
    tracker.record_entities_added(TENANT_A, 100)
    tracker.record_entities_added(TENANT_A, 200)
    tracker.record_entities_added(TENANT_A, 50)

    usage = tracker.get_usage(TENANT_A)
    assert usage.total_entities == 350


# -- 15. Frozen model rejects extra fields -----------------------------------


def test_frozen_model_rejects_extras() -> None:
    """TenantQuota and QuotaUsage reject unknown fields (extra='forbid')."""
    with pytest.raises(ValidationError):
        TenantQuota(tenant_id=TENANT_A, unknown_field="boom")  # type: ignore[call-arg]

    with pytest.raises(ValidationError):
        QuotaCheckResult(allowed=True, extra_thing=42)  # type: ignore[call-arg]


# -- 16. Tenant isolation: quotas and usage are independent ------------------


def test_tenant_isolation(tracker: QuotaTracker) -> None:
    """Quotas and usage for tenant A do not affect tenant B (ADR-007)."""
    tracker.set_quota(TenantQuota(tenant_id=TENANT_A, max_runs_per_day=1))
    tracker.set_quota(TenantQuota(tenant_id=TENANT_B, max_runs_per_day=100))

    tracker.record_run_start(TENANT_A)

    # A is at limit; B is not.
    assert tracker.check_run_allowed(TENANT_A).allowed is False
    assert tracker.check_run_allowed(TENANT_B).allowed is True

    # B's entity count is independent.
    tracker.record_entities_added(TENANT_A, 999)
    assert tracker.get_usage(TENANT_B).total_entities == 0
