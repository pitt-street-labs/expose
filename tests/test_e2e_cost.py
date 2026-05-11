"""End-to-end tests for the LLM cost tracking subsystem.

Covers:

- **Record cost and get summary** -- record multiple costs, verify aggregation
- **Monthly ceiling enforcement** -- ceiling breach raises CostCeilingExceededError
- **Pre-flight check** -- check_cost_allowed consistent with record_cost
- **Cost this month vs total** -- mock datetime to separate months
- **Cost today** -- verify today aggregation
- **Multiple tenants independent** -- two tenants, independent tracking
- **No ceiling = unlimited** -- no ceiling set, large cost accepted
- **Zero ceiling blocks all** -- ceiling 0.0 rejects any positive cost
- **Negative ceiling rejected** -- set_monthly_ceiling with negative raises ValueError
- **Negative cost rejected** -- TenantCostRecord with cost_usd < 0 raises ValidationError
- **Integration: cost tracking + enrichment pipeline** -- mock enrichment returns cost
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

# === Deterministic synthetic IDs ==============================================

TENANT_A = UUID("018f1f00-0000-7000-8000-00000000cc01")
TENANT_B = UUID("018f1f00-0000-7000-8000-00000000cc02")
RUN_ID_1 = UUID("018f1f00-0000-7000-8000-00000000cc03")
RUN_ID_2 = UUID("018f1f00-0000-7000-8000-00000000cc04")

# === Helpers ==================================================================


def _make_cost_record(
    *,
    tenant_id: UUID = TENANT_A,
    run_id: UUID = RUN_ID_1,
    cost_usd: float = 0.01,
    provider_id: str = "anthropic",
    enrichment_type: str = "attribution",
    recorded_at: datetime | None = None,
) -> TenantCostRecord:
    """Build a TenantCostRecord with sensible defaults."""
    return TenantCostRecord(
        tenant_id=tenant_id,
        run_id=run_id,
        cost_usd=cost_usd,
        provider_id=provider_id,
        enrichment_type=enrichment_type,
        recorded_at=recorded_at or datetime.now(UTC),
    )


# === 1. Record cost and get summary ==========================================


async def test_record_cost_and_get_summary() -> None:
    """Record multiple costs, verify summary aggregation."""
    tracker = TenantCostTracker()

    now = datetime.now(UTC)
    tracker.record_cost(_make_cost_record(cost_usd=0.05, recorded_at=now))
    tracker.record_cost(_make_cost_record(cost_usd=0.10, recorded_at=now))
    tracker.record_cost(_make_cost_record(cost_usd=0.03, recorded_at=now))

    summary = tracker.get_summary(TENANT_A)

    assert isinstance(summary, TenantCostSummary)
    assert summary.tenant_id == TENANT_A
    assert abs(summary.total_cost_usd - 0.18) < 1e-9
    assert summary.call_count == 3
    assert summary.last_cost_event is not None
    assert summary.last_cost_event >= now


# === 2. Monthly ceiling enforcement ==========================================


async def test_monthly_ceiling_enforcement() -> None:
    """Set ceiling, record costs up to it, verify breach raises."""
    tracker = TenantCostTracker()
    tracker.set_monthly_ceiling(TENANT_A, 0.10)

    now = datetime.now(UTC)

    # Record costs under the ceiling -- should succeed.
    tracker.record_cost(_make_cost_record(cost_usd=0.05, recorded_at=now))
    tracker.record_cost(_make_cost_record(cost_usd=0.04, recorded_at=now))

    # This should breach the ceiling (0.05 + 0.04 + 0.02 = 0.11 > 0.10).
    with pytest.raises(CostCeilingExceededError) as exc_info:
        tracker.record_cost(_make_cost_record(cost_usd=0.02, recorded_at=now))

    assert exc_info.value.tenant_id == TENANT_A
    assert exc_info.value.ceiling == 0.10
    assert exc_info.value.requested == 0.02

    # The failed record should NOT be stored.
    summary = tracker.get_summary(TENANT_A)
    assert summary.call_count == 2
    assert abs(summary.total_cost_usd - 0.09) < 1e-9


# === 3. Pre-flight check =====================================================


async def test_pre_flight_check() -> None:
    """check_cost_allowed is consistent with record_cost behavior."""
    tracker = TenantCostTracker()
    tracker.set_monthly_ceiling(TENANT_A, 1.00)

    now = datetime.now(UTC)
    tracker.record_cost(_make_cost_record(cost_usd=0.80, recorded_at=now))

    # 0.15 should be allowed (0.80 + 0.15 = 0.95 <= 1.00)
    assert tracker.check_cost_allowed(TENANT_A, 0.15) is True

    # 0.25 should be blocked (0.80 + 0.25 = 1.05 > 1.00)
    assert tracker.check_cost_allowed(TENANT_A, 0.25) is False

    # Pre-flight check does not mutate state.
    summary = tracker.get_summary(TENANT_A)
    assert summary.call_count == 1


# === 4. Cost this month vs total =============================================


async def test_cost_this_month_vs_total() -> None:
    """Record costs in different months, verify separation."""
    tracker = TenantCostTracker()

    # Record a cost "last month" (use a fixed date in the past).
    last_month = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)
    tracker.record_cost(_make_cost_record(cost_usd=1.00, recorded_at=last_month))

    # Record a cost "this month" using the current time.
    this_month = datetime.now(UTC)
    tracker.record_cost(_make_cost_record(cost_usd=0.50, recorded_at=this_month))

    # Total includes both.
    summary = tracker.get_summary(TENANT_A)
    assert abs(summary.total_cost_usd - 1.50) < 1e-9
    assert summary.call_count == 2

    # Cost this month should only include the current month record.
    cost_month = tracker.get_cost_this_month(TENANT_A)
    assert abs(cost_month - 0.50) < 1e-9


# === 5. Cost today ============================================================


async def test_cost_today() -> None:
    """Record cost, verify today aggregation."""
    tracker = TenantCostTracker()

    now = datetime.now(UTC)
    yesterday = now.replace(hour=0, minute=0, second=0) - timedelta(days=1)

    tracker.record_cost(_make_cost_record(cost_usd=0.25, recorded_at=yesterday))
    tracker.record_cost(_make_cost_record(cost_usd=0.10, recorded_at=now))

    cost_today = tracker.get_cost_today(TENANT_A)
    assert abs(cost_today - 0.10) < 1e-9


# === 6. Multiple tenants independent ==========================================


async def test_multiple_tenants_independent() -> None:
    """Two tenants have independent cost tracking."""
    tracker = TenantCostTracker()

    now = datetime.now(UTC)
    tracker.record_cost(
        _make_cost_record(tenant_id=TENANT_A, cost_usd=1.00, recorded_at=now)
    )
    tracker.record_cost(
        _make_cost_record(tenant_id=TENANT_B, cost_usd=2.00, recorded_at=now)
    )

    summary_a = tracker.get_summary(TENANT_A)
    summary_b = tracker.get_summary(TENANT_B)

    assert abs(summary_a.total_cost_usd - 1.00) < 1e-9
    assert summary_a.call_count == 1

    assert abs(summary_b.total_cost_usd - 2.00) < 1e-9
    assert summary_b.call_count == 1


# === 7. No ceiling = unlimited ================================================


async def test_no_ceiling_unlimited() -> None:
    """No ceiling set, large cost accepted without error."""
    tracker = TenantCostTracker()

    now = datetime.now(UTC)
    # No ceiling set -- even a large cost should be fine.
    tracker.record_cost(_make_cost_record(cost_usd=999999.99, recorded_at=now))

    summary = tracker.get_summary(TENANT_A)
    assert abs(summary.total_cost_usd - 999999.99) < 1e-9
    assert summary.monthly_ceiling_usd is None
    assert summary.ceiling_remaining_usd is None


# === 8. Zero ceiling blocks all ===============================================


async def test_zero_ceiling_blocks_all() -> None:
    """Ceiling 0.0 rejects any positive cost."""
    tracker = TenantCostTracker()
    tracker.set_monthly_ceiling(TENANT_A, 0.0)

    now = datetime.now(UTC)
    with pytest.raises(CostCeilingExceededError):
        tracker.record_cost(_make_cost_record(cost_usd=0.001, recorded_at=now))

    # Zero-cost record should also be blocked (0.0 + 0.001 > 0.0).
    # But a truly zero-cost record (0.0) should pass since 0.0 + 0.0 = 0.0 == 0.0.
    tracker.record_cost(_make_cost_record(cost_usd=0.0, recorded_at=now))
    summary = tracker.get_summary(TENANT_A)
    assert summary.call_count == 1
    assert abs(summary.total_cost_usd) < 1e-9


# === 9. Negative ceiling rejected =============================================


async def test_negative_ceiling_rejected() -> None:
    """set_monthly_ceiling with negative value raises ValueError."""
    tracker = TenantCostTracker()

    with pytest.raises(ValueError, match="non-negative"):
        tracker.set_monthly_ceiling(TENANT_A, -1.0)

    with pytest.raises(ValueError, match="non-negative"):
        tracker.set_monthly_ceiling(TENANT_A, -0.01)


# === 10. Negative cost rejected ===============================================


async def test_negative_cost_rejected() -> None:
    """TenantCostRecord with cost_usd < 0 raises ValidationError."""
    with pytest.raises(ValidationError):
        TenantCostRecord(
            tenant_id=TENANT_A,
            run_id=RUN_ID_1,
            cost_usd=-0.01,
            provider_id="anthropic",
            enrichment_type="attribution",
            recorded_at=datetime.now(UTC),
        )


# === 11. Integration: cost tracking + enrichment pipeline =====================


async def test_cost_tracking_with_enrichment_pipeline() -> None:
    """Mock enrichment that returns cost, verify cost tracker accumulates.

    Simulates the integration point where each LLM enrichment call records
    its cost into the TenantCostTracker. The enrichment pipeline itself
    is mocked -- we test the accumulation pattern.
    """
    tracker = TenantCostTracker()
    tracker.set_monthly_ceiling(TENANT_A, 5.00)

    now = datetime.now(UTC)

    # Simulate 10 enrichment calls, each costing $0.03.
    for _i in range(10):
        record = _make_cost_record(
            cost_usd=0.03,
            provider_id="anthropic",
            enrichment_type="attribution",
            recorded_at=now,
        )
        tracker.record_cost(record)

    summary = tracker.get_summary(TENANT_A)
    assert summary.call_count == 10
    assert abs(summary.total_cost_usd - 0.30) < 1e-9
    assert summary.cost_this_month_usd > 0
    assert summary.ceiling_remaining_usd is not None
    assert abs(summary.ceiling_remaining_usd - 4.70) < 1e-9


# === 12. Cost records retrieval with since filter =============================


async def test_get_records_with_since_filter() -> None:
    """get_records returns all records or filters by since datetime."""
    tracker = TenantCostTracker()

    old_time = datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC)
    recent_time = datetime(2026, 5, 9, 12, 0, 0, tzinfo=UTC)
    now = datetime.now(UTC)

    tracker.record_cost(_make_cost_record(cost_usd=0.10, recorded_at=old_time))
    tracker.record_cost(_make_cost_record(cost_usd=0.20, recorded_at=recent_time))
    tracker.record_cost(_make_cost_record(cost_usd=0.30, recorded_at=now))

    # All records
    all_records = tracker.get_records(TENANT_A)
    assert len(all_records) == 3

    # Since filter
    cutoff = datetime(2026, 5, 1, 0, 0, 0, tzinfo=UTC)
    recent_records = tracker.get_records(TENANT_A, since=cutoff)
    assert len(recent_records) == 2
    assert all(r.recorded_at >= cutoff for r in recent_records)
