"""Per-tenant LLM cost tracking with monthly ceiling enforcement.

Bridges the per-run :class:`CostTracker` (in ``expose.llm.models``) with
the per-tenant :class:`QuotaTracker` (in this package). Each LLM call's
cost is recorded as a :class:`TenantCostRecord`; the
:class:`TenantCostTracker` aggregates these across runs and enforces an
optional monthly spending ceiling per tenant.

Phase 1: in-memory storage (same pattern as :class:`QuotaTracker`).
Phase 3 adds Postgres persistence behind the same public API.

Thread safety: targets a single asyncio event loop (no threads), so
plain dict mutation is safe — matching the approach in ``tracker.py``.

Per ADR-007 (multi-tenancy): every public method takes ``tenant_id``
explicitly.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TenantCostRecord(BaseModel):
    """Single cost event from one LLM call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    run_id: UUID
    cost_usd: float = Field(ge=0.0)
    provider_id: str = Field(min_length=1)
    enrichment_type: str = Field(min_length=1)
    recorded_at: datetime


class TenantCostSummary(BaseModel):
    """Aggregated cost view for a tenant."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    total_cost_usd: float
    cost_this_month_usd: float
    cost_today_usd: float
    call_count: int
    call_count_this_month: int
    monthly_ceiling_usd: float | None
    ceiling_remaining_usd: float | None
    last_cost_event: datetime | None


class CostCeilingExceededError(Exception):
    """Raised when tenant monthly cost ceiling would be exceeded."""

    def __init__(
        self, tenant_id: UUID, current: float, ceiling: float, requested: float
    ) -> None:
        self.tenant_id = tenant_id
        self.current = current
        self.ceiling = ceiling
        self.requested = requested
        super().__init__(
            f"Tenant {tenant_id}: monthly cost ${current:.4f} "
            f"+ ${requested:.4f} exceeds ceiling ${ceiling:.2f}"
        )


class TenantCostTracker:
    """Tracks LLM costs per tenant with optional monthly ceiling enforcement.

    In-memory for v1 (Phase 3 adds Postgres persistence). Monthly and
    daily boundaries use UTC calendar dates.
    """

    def __init__(self) -> None:
        self._records: dict[UUID, list[TenantCostRecord]] = defaultdict(list)
        self._ceilings: dict[UUID, float] = {}

    # -- Ceiling configuration -------------------------------------------------

    def set_monthly_ceiling(self, tenant_id: UUID, ceiling_usd: float) -> None:
        """Set or replace the monthly spending ceiling for *tenant_id*."""
        if ceiling_usd < 0:
            msg = f"ceiling_usd must be non-negative, got {ceiling_usd}"
            raise ValueError(msg)
        self._ceilings[tenant_id] = ceiling_usd

    def get_monthly_ceiling(self, tenant_id: UUID) -> float | None:
        """Return the monthly ceiling for *tenant_id*, or ``None`` if unset."""
        return self._ceilings.get(tenant_id)

    # -- Recording -------------------------------------------------------------

    def record_cost(self, record: TenantCostRecord) -> None:
        """Record a cost event.

        Raises :class:`CostCeilingExceededError` if adding
        ``record.cost_usd`` would breach the tenant's monthly ceiling.
        The ceiling check runs *before* the record is stored, so a
        rejected call leaves state unchanged.
        """
        ceiling = self._ceilings.get(record.tenant_id)
        if ceiling is not None:
            current_month = self._cost_in_month(
                record.tenant_id,
                record.recorded_at.year,
                record.recorded_at.month,
            )
            if current_month + record.cost_usd > ceiling:
                raise CostCeilingExceededError(
                    tenant_id=record.tenant_id,
                    current=current_month,
                    ceiling=ceiling,
                    requested=record.cost_usd,
                )
        self._records[record.tenant_id].append(record)

    # -- Pre-flight check ------------------------------------------------------

    def check_cost_allowed(
        self, tenant_id: UUID, estimated_cost: float
    ) -> bool:
        """Pre-flight check: would *estimated_cost* breach the monthly ceiling?

        Returns ``True`` when the cost is permissible (including when no
        ceiling is configured). Does not mutate state.
        """
        ceiling = self._ceilings.get(tenant_id)
        if ceiling is None:
            return True
        now = datetime.now(UTC)
        current_month = self._cost_in_month(tenant_id, now.year, now.month)
        return current_month + estimated_cost <= ceiling

    # -- Queries ---------------------------------------------------------------

    def get_summary(self, tenant_id: UUID) -> TenantCostSummary:
        """Return an aggregated cost summary for *tenant_id*."""
        records = self._records.get(tenant_id, [])
        now = datetime.now(UTC)

        total_cost = sum(r.cost_usd for r in records)
        month_records = [
            r
            for r in records
            if r.recorded_at.year == now.year and r.recorded_at.month == now.month
        ]
        today_records = [
            r for r in records if r.recorded_at.date() == now.date()
        ]

        cost_this_month = sum(r.cost_usd for r in month_records)
        cost_today = sum(r.cost_usd for r in today_records)

        ceiling = self._ceilings.get(tenant_id)
        ceiling_remaining: float | None = None
        if ceiling is not None:
            ceiling_remaining = max(0.0, ceiling - cost_this_month)

        last_event: datetime | None = None
        if records:
            last_event = max(r.recorded_at for r in records)

        return TenantCostSummary(
            tenant_id=tenant_id,
            total_cost_usd=total_cost,
            cost_this_month_usd=cost_this_month,
            cost_today_usd=cost_today,
            call_count=len(records),
            call_count_this_month=len(month_records),
            monthly_ceiling_usd=ceiling,
            ceiling_remaining_usd=ceiling_remaining,
            last_cost_event=last_event,
        )

    def get_cost_this_month(self, tenant_id: UUID) -> float:
        """Return total cost for *tenant_id* in the current calendar month (UTC)."""
        now = datetime.now(UTC)
        return self._cost_in_month(tenant_id, now.year, now.month)

    def get_cost_today(self, tenant_id: UUID) -> float:
        """Return total cost for *tenant_id* today (UTC date boundary)."""
        today = datetime.now(UTC).date()
        return sum(
            r.cost_usd
            for r in self._records.get(tenant_id, [])
            if r.recorded_at.date() == today
        )

    def get_records(
        self, tenant_id: UUID, *, since: datetime | None = None
    ) -> list[TenantCostRecord]:
        """Return cost records for *tenant_id*, optionally filtered to *since*."""
        records = list(self._records.get(tenant_id, []))
        if since is not None:
            records = [r for r in records if r.recorded_at >= since]
        return records

    # -- Internal --------------------------------------------------------------

    def _cost_in_month(
        self, tenant_id: UUID, year: int, month: int
    ) -> float:
        """Sum cost_usd for all records in the given calendar month."""
        return sum(
            r.cost_usd
            for r in self._records.get(tenant_id, [])
            if r.recorded_at.year == year and r.recorded_at.month == month
        )


__all__ = [
    "CostCeilingExceededError",
    "TenantCostRecord",
    "TenantCostSummary",
    "TenantCostTracker",
]
