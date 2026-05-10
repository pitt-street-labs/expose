"""Per-tenant resource quotas for EXPOSE Core (issue #24).

Multi-tenant platforms without quotas allow a single tenant to monopolize
shared resources. This package provides configurable per-tenant limits on
runs, entities, concurrent executions, and evidence storage, enforced
before operations begin rather than after resources are consumed.

Sub-modules:

- ``models`` — Pydantic frozen models: :class:`TenantQuota` (limits),
  :class:`QuotaUsage` (current counters), :class:`QuotaCheckResult`
  (pass/fail with diagnostic).
- ``tracker`` — :class:`QuotaTracker` in-memory usage tracker with
  check-and-record methods. Production: backed by Redis or Postgres
  counters.

Per ADR-007 (multi-tenancy): every public method takes ``tenant_id``
explicitly. Unknown tenants receive default quotas rather than errors,
so newly onboarded tenants work immediately.
"""

from expose.quotas.models import QuotaCheckResult, QuotaUsage, TenantQuota
from expose.quotas.tracker import QuotaExceededError, QuotaTracker

__all__ = [
    "QuotaCheckResult",
    "QuotaExceededError",
    "QuotaTracker",
    "QuotaUsage",
    "TenantQuota",
]
