"""In-memory per-tenant quota tracker (issue #24).

:class:`QuotaTracker` maintains usage counters and enforces configured
limits before resource-consuming operations begin. All state is held in
plain dicts — no external dependencies. Production deployments will back
this with Redis or Postgres counters behind the same interface.

Thread safety: the tracker targets a single asyncio event loop (no
threads), so plain dict mutation is safe. If threaded callers appear in
a future iteration, a ``threading.Lock`` can be added without changing
the public API.

Per ADR-007 (multi-tenancy): every public method takes ``tenant_id``
explicitly. Unknown tenants receive a default :class:`TenantQuota`
rather than an error, so newly onboarded tenants work immediately
without an explicit quota-setup step.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from expose.quotas.models import QuotaCheckResult, QuotaUsage, TenantQuota


class QuotaExceededError(Exception):
    """Raised when a tenant operation would exceed a quota limit.

    Carries the :class:`QuotaCheckResult` that describes the violation
    so callers can inspect ``result.quota_field`` and ``result.reason``
    without re-checking.
    """

    def __init__(self, result: QuotaCheckResult) -> None:
        self.result = result
        super().__init__(result.reason)


class QuotaTracker:
    """Tracks per-tenant resource usage against configured quotas.

    In-memory tracker for now. Production: backed by Redis or Postgres
    counters. The public surface is intentionally small — check, record,
    query — so backing-store swaps do not ripple through call sites.
    """

    def __init__(self) -> None:
        self._quotas: dict[UUID, TenantQuota] = {}
        self._usage: dict[UUID, _MutableUsage] = {}

    # -- Configuration --------------------------------------------------------

    def set_quota(self, quota: TenantQuota) -> None:
        """Register or replace the quota for ``quota.tenant_id``."""
        self._quotas[quota.tenant_id] = quota

    def get_quota(self, tenant_id: UUID) -> TenantQuota:
        """Return the quota for *tenant_id*, or a default if none is set."""
        if tenant_id in self._quotas:
            return self._quotas[tenant_id]
        return TenantQuota(tenant_id=tenant_id)

    # -- Usage queries --------------------------------------------------------

    def get_usage(self, tenant_id: UUID) -> QuotaUsage:
        """Return a frozen snapshot of the tenant's current usage."""
        mu = self._ensure_usage(tenant_id)
        return QuotaUsage(
            tenant_id=tenant_id,
            runs_today=mu.runs_today,
            total_entities=mu.total_entities,
            active_runs=mu.active_runs,
            evidence_storage_gb=mu.evidence_storage_gb,
            measured_at=datetime.now(UTC),
        )

    # -- Pre-flight checks ----------------------------------------------------

    def check_run_allowed(self, tenant_id: UUID) -> QuotaCheckResult:
        """Check whether a new run can be started for *tenant_id*.

        Evaluates both the daily run limit and the concurrent-run limit.
        Returns the first violation found (if any).
        """
        quota = self.get_quota(tenant_id)
        mu = self._ensure_usage(tenant_id)

        if mu.runs_today >= quota.max_runs_per_day:
            return QuotaCheckResult(
                allowed=False,
                reason=(
                    f"Daily run limit reached: {mu.runs_today}/{quota.max_runs_per_day} "
                    f"runs used today"
                ),
                quota_field="max_runs_per_day",
                current_value=mu.runs_today,
                limit_value=quota.max_runs_per_day,
            )

        if mu.active_runs >= quota.max_concurrent_runs:
            return QuotaCheckResult(
                allowed=False,
                reason=(
                    f"Concurrent run limit reached: {mu.active_runs}/{quota.max_concurrent_runs} "
                    f"runs active"
                ),
                quota_field="max_concurrent_runs",
                current_value=mu.active_runs,
                limit_value=quota.max_concurrent_runs,
            )

        return QuotaCheckResult(allowed=True)

    def check_entity_limit(self, tenant_id: UUID, additional: int = 1) -> QuotaCheckResult:
        """Check whether adding *additional* entities would exceed the quota.

        The check is pre-flight: it does NOT mutate the counter. Call
        :meth:`record_entities_added` after the entities are persisted.
        """
        quota = self.get_quota(tenant_id)
        mu = self._ensure_usage(tenant_id)
        projected = mu.total_entities + additional

        if projected > quota.max_entities:
            return QuotaCheckResult(
                allowed=False,
                reason=(
                    f"Entity limit would be exceeded: {mu.total_entities} existing + "
                    f"{additional} new = {projected}, limit is {quota.max_entities}"
                ),
                quota_field="max_entities",
                current_value=mu.total_entities,
                limit_value=quota.max_entities,
            )

        return QuotaCheckResult(allowed=True)

    # -- Enforcement ----------------------------------------------------------

    def assert_run_allowed(self, tenant_id: UUID) -> None:
        """Raise :class:`QuotaExceededError` if a run cannot be started.

        Convenience wrapper around :meth:`check_run_allowed` for
        call sites that prefer exceptions over result objects.
        """
        result = self.check_run_allowed(tenant_id)
        if not result.allowed:
            raise QuotaExceededError(result)

    # -- Recording ------------------------------------------------------------

    def record_run_start(self, tenant_id: UUID) -> None:
        """Record that a run has started: increments both daily and active counters."""
        mu = self._ensure_usage(tenant_id)
        mu.runs_today += 1
        mu.active_runs += 1

    def record_run_complete(self, tenant_id: UUID) -> None:
        """Record that a run has finished: decrements the active-run counter.

        Does not decrement below zero (defensive — a double-complete should
        not produce negative counts).
        """
        mu = self._ensure_usage(tenant_id)
        mu.active_runs = max(0, mu.active_runs - 1)

    def record_entities_added(self, tenant_id: UUID, count: int) -> None:
        """Record that *count* entities were persisted for *tenant_id*."""
        mu = self._ensure_usage(tenant_id)
        mu.total_entities += count

    # -- Internal -------------------------------------------------------------

    def _ensure_usage(self, tenant_id: UUID) -> _MutableUsage:
        """Return the mutable usage record for *tenant_id*, creating if absent."""
        if tenant_id not in self._usage:
            self._usage[tenant_id] = _MutableUsage()
        return self._usage[tenant_id]


class _MutableUsage:
    """Internal mutable usage counters.

    Kept separate from :class:`QuotaUsage` (which is a frozen Pydantic
    model) so the tracker can mutate counters freely while exposing
    immutable snapshots via :meth:`QuotaTracker.get_usage`.
    """

    __slots__ = ("active_runs", "evidence_storage_gb", "runs_today", "total_entities")

    def __init__(self) -> None:
        self.runs_today: int = 0
        self.total_entities: int = 0
        self.active_runs: int = 0
        self.evidence_storage_gb: float = 0.0


__all__ = ["QuotaExceededError", "QuotaTracker"]
