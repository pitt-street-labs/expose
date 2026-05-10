"""Pydantic models for per-tenant resource quotas (issue #24).

All models use ``frozen=True`` + ``extra="forbid"`` for immutability and
strict schema enforcement, consistent with the project-wide Pydantic
conventions in ``expose.types``.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class TenantQuota(BaseModel):
    """Configurable resource limits for a single tenant.

    Default values are reasonable for a mid-size deployment. Override
    per-tenant via :meth:`QuotaTracker.set_quota` based on subscription
    tier or contractual agreement.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    max_runs_per_day: int = 100
    max_entities: int = 1_000_000
    max_collectors_per_run: int = 20
    max_seeds_per_run: int = 1000
    max_evidence_storage_gb: float = 100.0
    max_concurrent_runs: int = 5


class QuotaUsage(BaseModel):
    """Point-in-time snapshot of a tenant's resource consumption.

    Counters are maintained by :class:`QuotaTracker`; callers should
    treat this as read-only (enforced by ``frozen=True``).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    runs_today: int = 0
    total_entities: int = 0
    active_runs: int = 0
    evidence_storage_gb: float = 0.0
    measured_at: datetime


class QuotaCheckResult(BaseModel):
    """Result of a pre-flight quota check.

    When ``allowed`` is ``False``, the remaining fields describe which
    quota was exceeded and by how much, providing actionable diagnostics
    for operators and API consumers.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    reason: str | None = None
    quota_field: str | None = None
    current_value: int | float | None = None
    limit_value: int | float | None = None


__all__ = ["QuotaCheckResult", "QuotaUsage", "TenantQuota"]
