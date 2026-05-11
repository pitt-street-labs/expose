"""Tests for per-tenant LLM cost tracking and billing model.

Coverage:

1.  record_cost accumulates correctly across multiple calls.
2.  Monthly ceiling enforcement raises CostCeilingExceededError.
3.  Ceiling check is pre-flight (state unchanged on rejection).
4.  check_cost_allowed returns False when ceiling would be breached.
5.  check_cost_allowed returns True when no ceiling is set.
6.  get_summary returns correct aggregation.
7.  cost_this_month only counts current calendar month (UTC).
8.  cost_today only counts today (UTC date boundary).
9.  Multiple tenants are independent (ADR-007).
10. No ceiling set means unlimited (record_cost never raises).
11. Ceiling of 0.0 blocks all costs.
12. get_records with since filter excludes older records.
13. get_records without filter returns all records.
14. set/get monthly ceiling round-trip.
15. CostCeilingExceededError carries diagnostic attributes.
16. Frozen models reject extra fields.
17. Summary with no records returns zeroes.
18. Ceiling remaining never goes negative in summary.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from pydantic import ValidationError

from expose.quotas.cost_tracking import (
    CostCeilingExceededError,
    TenantCostRecord,
    TenantCostSummary,
    TenantCostTracker,
)

# Synthetic tenant UUIDs matching the project convention.
TENANT_A = UUID("018f1f00-0000-7000-8000-00000000A001")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000B002")
RUN_1 = UUID("018f1f00-0000-7000-8000-000000001001")
RUN_2 = UUID("018f1f00-0000-7000-8000-000000002002")


def _make_record(
    tenant_id: UUID = TENANT_A,
    run_id: UUID = RUN_1,
    cost_usd: float = 0.05,
    provider_id: str = "openai",
    enrichment_type: str = "entity_enrichment",
    recorded_at: datetime | None = None,
) -> TenantCostRecord:
    """Helper to build a TenantCostRecord with sensible defaults."""
    return TenantCostRecord(
        tenant_id=tenant_id,
        run_id=run_id,
        cost_usd=cost_usd,
        provider_id=provider_id,
        enrichment_type=enrichment_type,
        recorded_at=recorded_at or datetime.now(UTC),
    )


@pytest.fixture
def tracker() -> TenantCostTracker:
    """Fresh tracker per test (no cross-test bleed)."""
    return TenantCostTracker()


# -- 1. record_cost accumulates correctly -------------------------------------


def test_record_cost_accumulates(tracker: TenantCostTracker) -> None:
    """Multiple record_cost calls accumulate in get_records and summary."""
    tracker.record_cost(_make_record(cost_usd=0.10))
    tracker.record_cost(_make_record(cost_usd=0.25))
    tracker.record_cost(_make_record(cost_usd=0.15))

    records = tracker.get_records(TENANT_A)
    assert len(records) == 3
    total = sum(r.cost_usd for r in records)
    assert abs(total - 0.50) < 1e-9


# -- 2. Monthly ceiling enforcement raises CostCeilingExceededError -----------


def test_ceiling_enforcement_raises(tracker: TenantCostTracker) -> None:
    """Recording a cost that breaches the ceiling raises the error."""
    tracker.set_monthly_ceiling(TENANT_A, 1.00)
    tracker.record_cost(_make_record(cost_usd=0.80))

    with pytest.raises(CostCeilingExceededError) as exc_info:
        tracker.record_cost(_make_record(cost_usd=0.30))

    assert exc_info.value.tenant_id == TENANT_A
    assert abs(exc_info.value.current - 0.80) < 1e-9
    assert exc_info.value.ceiling == 1.00
    assert abs(exc_info.value.requested - 0.30) < 1e-9


# -- 3. Ceiling check is pre-flight (state unchanged on rejection) -----------


def test_ceiling_rejection_preserves_state(tracker: TenantCostTracker) -> None:
    """A rejected record_cost does not store the record."""
    tracker.set_monthly_ceiling(TENANT_A, 0.50)
    tracker.record_cost(_make_record(cost_usd=0.40))

    with pytest.raises(CostCeilingExceededError):
        tracker.record_cost(_make_record(cost_usd=0.20))

    # Only the first record was stored.
    records = tracker.get_records(TENANT_A)
    assert len(records) == 1
    assert abs(records[0].cost_usd - 0.40) < 1e-9


# -- 4. check_cost_allowed returns False when ceiling would be breached -------


def test_check_cost_allowed_false(tracker: TenantCostTracker) -> None:
    """check_cost_allowed returns False when the estimated cost would breach."""
    tracker.set_monthly_ceiling(TENANT_A, 1.00)
    tracker.record_cost(_make_record(cost_usd=0.90))

    assert tracker.check_cost_allowed(TENANT_A, 0.20) is False


# -- 5. check_cost_allowed returns True when no ceiling is set ----------------


def test_check_cost_allowed_no_ceiling(tracker: TenantCostTracker) -> None:
    """Without a ceiling, check_cost_allowed always returns True."""
    tracker.record_cost(_make_record(cost_usd=999.99))
    assert tracker.check_cost_allowed(TENANT_A, 1000.0) is True


# -- 6. get_summary returns correct aggregation -------------------------------


def test_get_summary_aggregation(tracker: TenantCostTracker) -> None:
    """get_summary returns accurate totals, counts, and ceiling info."""
    tracker.set_monthly_ceiling(TENANT_A, 50.00)

    now = datetime.now(UTC)
    tracker.record_cost(_make_record(cost_usd=1.00, recorded_at=now))
    tracker.record_cost(_make_record(cost_usd=2.00, recorded_at=now))
    tracker.record_cost(
        _make_record(cost_usd=0.50, run_id=RUN_2, recorded_at=now)
    )

    summary = tracker.get_summary(TENANT_A)
    assert summary.tenant_id == TENANT_A
    assert abs(summary.total_cost_usd - 3.50) < 1e-9
    assert abs(summary.cost_this_month_usd - 3.50) < 1e-9
    assert abs(summary.cost_today_usd - 3.50) < 1e-9
    assert summary.call_count == 3
    assert summary.call_count_this_month == 3
    assert summary.monthly_ceiling_usd == 50.00
    assert summary.ceiling_remaining_usd is not None
    assert abs(summary.ceiling_remaining_usd - 46.50) < 1e-9
    assert summary.last_cost_event is not None


# -- 7. cost_this_month only counts current calendar month (UTC) ---------------


def test_cost_this_month_excludes_previous(tracker: TenantCostTracker) -> None:
    """Records from a previous month are excluded from cost_this_month."""
    now = datetime.now(UTC)
    last_month = now.replace(day=1) - timedelta(days=1)

    tracker.record_cost(_make_record(cost_usd=5.00, recorded_at=last_month))
    tracker.record_cost(_make_record(cost_usd=2.00, recorded_at=now))

    assert abs(tracker.get_cost_this_month(TENANT_A) - 2.00) < 1e-9

    # Total across all time includes both.
    summary = tracker.get_summary(TENANT_A)
    assert abs(summary.total_cost_usd - 7.00) < 1e-9


# -- 8. cost_today only counts today (UTC date boundary) ----------------------


def test_cost_today_excludes_yesterday(tracker: TenantCostTracker) -> None:
    """Records from yesterday are excluded from cost_today."""
    now = datetime.now(UTC)
    yesterday = now - timedelta(days=1)

    tracker.record_cost(_make_record(cost_usd=3.00, recorded_at=yesterday))
    tracker.record_cost(_make_record(cost_usd=1.00, recorded_at=now))

    assert abs(tracker.get_cost_today(TENANT_A) - 1.00) < 1e-9


# -- 9. Multiple tenants are independent (ADR-007) ----------------------------


def test_tenant_isolation(tracker: TenantCostTracker) -> None:
    """Cost records and ceilings for tenant A do not affect tenant B."""
    tracker.set_monthly_ceiling(TENANT_A, 1.00)
    tracker.record_cost(_make_record(tenant_id=TENANT_A, cost_usd=0.90))
    tracker.record_cost(_make_record(tenant_id=TENANT_B, cost_usd=5.00))

    # A is near ceiling; B has no ceiling.
    assert tracker.check_cost_allowed(TENANT_A, 0.20) is False
    assert tracker.check_cost_allowed(TENANT_B, 100.0) is True

    # Summaries are independent.
    summary_a = tracker.get_summary(TENANT_A)
    summary_b = tracker.get_summary(TENANT_B)
    assert summary_a.call_count == 1
    assert summary_b.call_count == 1
    assert abs(summary_a.total_cost_usd - 0.90) < 1e-9
    assert abs(summary_b.total_cost_usd - 5.00) < 1e-9


# -- 10. No ceiling set means unlimited ---------------------------------------


def test_no_ceiling_means_unlimited(tracker: TenantCostTracker) -> None:
    """Without a ceiling, record_cost never raises regardless of amount."""
    for _ in range(100):
        tracker.record_cost(_make_record(cost_usd=100.00))

    assert len(tracker.get_records(TENANT_A)) == 100
    summary = tracker.get_summary(TENANT_A)
    assert summary.monthly_ceiling_usd is None
    assert summary.ceiling_remaining_usd is None


# -- 11. Ceiling of 0.0 blocks all costs --------------------------------------


def test_zero_ceiling_blocks_all(tracker: TenantCostTracker) -> None:
    """A ceiling of $0.00 blocks even the smallest cost."""
    tracker.set_monthly_ceiling(TENANT_A, 0.0)

    with pytest.raises(CostCeilingExceededError):
        tracker.record_cost(_make_record(cost_usd=0.001))

    assert tracker.check_cost_allowed(TENANT_A, 0.001) is False

    # Zero-cost records still pass (0 + 0 does not exceed 0).
    tracker.record_cost(_make_record(cost_usd=0.0))
    assert len(tracker.get_records(TENANT_A)) == 1


# -- 12. get_records with since filter ----------------------------------------


def test_get_records_since_filter(tracker: TenantCostTracker) -> None:
    """get_records with since excludes older records."""
    now = datetime.now(UTC)
    old = now - timedelta(hours=2)
    recent = now - timedelta(minutes=30)

    tracker.record_cost(_make_record(cost_usd=1.00, recorded_at=old))
    tracker.record_cost(_make_record(cost_usd=2.00, recorded_at=recent))
    tracker.record_cost(_make_record(cost_usd=3.00, recorded_at=now))

    cutoff = now - timedelta(hours=1)
    filtered = tracker.get_records(TENANT_A, since=cutoff)
    assert len(filtered) == 2
    assert all(r.recorded_at >= cutoff for r in filtered)


# -- 13. get_records without filter returns all --------------------------------


def test_get_records_all(tracker: TenantCostTracker) -> None:
    """get_records without since returns all records for the tenant."""
    for i in range(5):
        tracker.record_cost(_make_record(cost_usd=float(i)))
    assert len(tracker.get_records(TENANT_A)) == 5


# -- 14. set/get monthly ceiling round-trip ------------------------------------


def test_ceiling_round_trip(tracker: TenantCostTracker) -> None:
    """set_monthly_ceiling and get_monthly_ceiling round-trip correctly."""
    assert tracker.get_monthly_ceiling(TENANT_A) is None
    tracker.set_monthly_ceiling(TENANT_A, 42.50)
    assert tracker.get_monthly_ceiling(TENANT_A) == 42.50

    # Replace ceiling.
    tracker.set_monthly_ceiling(TENANT_A, 100.00)
    assert tracker.get_monthly_ceiling(TENANT_A) == 100.00


# -- 15. CostCeilingExceededError carries diagnostic attributes ----------------


def test_error_diagnostic_attributes(tracker: TenantCostTracker) -> None:
    """CostCeilingExceededError exposes tenant_id, current, ceiling, requested."""
    tracker.set_monthly_ceiling(TENANT_A, 5.00)
    tracker.record_cost(_make_record(cost_usd=4.00))

    with pytest.raises(CostCeilingExceededError) as exc_info:
        tracker.record_cost(_make_record(cost_usd=2.00))

    err = exc_info.value
    assert err.tenant_id == TENANT_A
    assert abs(err.current - 4.00) < 1e-9
    assert err.ceiling == 5.00
    assert abs(err.requested - 2.00) < 1e-9
    assert "exceeds ceiling" in str(err)
    assert str(TENANT_A) in str(err)


# -- 16. Frozen models reject extra fields ------------------------------------


def test_frozen_models_reject_extras() -> None:
    """TenantCostRecord and TenantCostSummary reject unknown fields."""
    with pytest.raises(ValidationError):
        TenantCostRecord(
            tenant_id=TENANT_A,
            run_id=RUN_1,
            cost_usd=0.01,
            provider_id="openai",
            enrichment_type="test",
            recorded_at=datetime.now(UTC),
            bogus_field="nope",  # type: ignore[call-arg]
        )

    with pytest.raises(ValidationError):
        TenantCostSummary(
            tenant_id=TENANT_A,
            total_cost_usd=0,
            cost_this_month_usd=0,
            cost_today_usd=0,
            call_count=0,
            call_count_this_month=0,
            monthly_ceiling_usd=None,
            ceiling_remaining_usd=None,
            last_cost_event=None,
            extra_thing=42,  # type: ignore[call-arg]
        )


# -- 17. Summary with no records returns zeroes --------------------------------


def test_summary_empty_tenant(tracker: TenantCostTracker) -> None:
    """get_summary for a tenant with no records returns all zeroes."""
    summary = tracker.get_summary(TENANT_A)
    assert summary.tenant_id == TENANT_A
    assert summary.total_cost_usd == 0.0
    assert summary.cost_this_month_usd == 0.0
    assert summary.cost_today_usd == 0.0
    assert summary.call_count == 0
    assert summary.call_count_this_month == 0
    assert summary.monthly_ceiling_usd is None
    assert summary.ceiling_remaining_usd is None
    assert summary.last_cost_event is None


# -- 18. Ceiling remaining never goes negative in summary ----------------------


def test_ceiling_remaining_not_negative(tracker: TenantCostTracker) -> None:
    """If historical records somehow exceed the ceiling, remaining is 0, not negative.

    This covers the case where a ceiling is lowered after costs were recorded.
    """
    tracker.record_cost(_make_record(cost_usd=10.00))
    # Set a ceiling *below* what's already recorded.
    tracker.set_monthly_ceiling(TENANT_A, 5.00)

    summary = tracker.get_summary(TENANT_A)
    assert summary.ceiling_remaining_usd == 0.0
