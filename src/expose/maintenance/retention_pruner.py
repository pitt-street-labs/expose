"""Incidental data retention pruner — implements ADR-008 §Layer 3.

ADR-008 commits the engine to bounded retention of incidental ("not yours")
observations: the observation graph stores them so attribution decisions stay
explainable, but they must not linger past a configurable retention window.
``docs/SPEC.md`` §5.5 sets the default window at 30 days and stipulates the
job must be per-tenant.

This module ships ``IncidentalDataPruner``: a small, intentionally boring
async deleter that:

- Resolves "now" via an injectable clock (so tests can freeze time without
  monkey-patching ``datetime``).
- Computes a cutoff timestamp ``cutoff_at = now - retention_days``.
- Issues a single tenant-scoped ``DELETE`` against ``entities``, gated on
  ``attribution_status = 'not_yours'`` and ``last_observed_at < cutoff_at``.
- Captures the rowcount and emits one structured-log event named
  ``incidental_data_pruned`` carrying ``(tenant_id, deleted_count, cutoff_at,
  retention_days)`` — and *deliberately* nothing else. The whole point of
  retention pruning is data minimization; logging entity identifiers we just
  deleted would re-create the very record we promised to drop.

No advisory locking is taken in v1. Concurrent invocations on the same tenant
will race the row scan, and Postgres will resolve that with row locks during
the delete; both losers' rowcounts will simply be smaller. This is acceptable
because the operation is idempotent: a second run after a first that deleted
the rows finds nothing and returns ``deleted_count = 0``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, cast
from uuid import UUID

import structlog
from sqlalchemy import CursorResult, text
from sqlalchemy.ext.asyncio import AsyncSession

# Retention window per ADR-008 §Layer 3 / SPEC §5.5. Operators may override
# per tenant; v1 ships the default and exposes the constant for visibility.
DEFAULT_RETENTION_DAYS: Final[int] = 30

# Structured log event name. Pinned so log aggregation / SIEM rules can subscribe
# to it without scraping log messages. Kept module-private (single-source-of-truth
# constant) to discourage drift.
_LOG_EVENT_PRUNED: Final[str] = "incidental_data_pruned"

# Targeted DELETE — tenant-scoped, status-gated, cutoff-gated. No subqueries,
# no joins, no returning clause; we want a small, predictable plan that the
# planner can reach via ``idx_entities_attribution`` (defined on
# ``(tenant_id, attribution_status, attribution_confidence)``).
_DELETE_STMT: Final[str] = (
    "DELETE FROM entities "
    "WHERE tenant_id = :tenant_id "
    "AND attribution_status = 'not_yours' "
    "AND last_observed_at < :cutoff_at"
)


def _default_clock() -> datetime:
    """Module-default clock: timezone-aware UTC ``now``.

    Extracted so tests (and any operator wanting to back-date for replay) can
    inject a deterministic substitute via the constructor.
    """
    return datetime.now(tz=UTC)


@dataclass(frozen=True)
class PruneResult:
    """Outcome of a single ``prune_tenant`` invocation.

    Frozen so callers (CLI, scheduler, test asserts) cannot mutate the record
    after the fact. The fields mirror what gets logged so audit log and return
    value never disagree.
    """

    tenant_id: UUID
    deleted_count: int
    cutoff_at: datetime
    retention_days: int


class IncidentalDataPruner:
    """Deletes ``Entity`` rows classified ``not_yours`` past their retention window.

    Per-tenant, async, idempotent. See module docstring for the
    minimization-first logging contract and the ADR-008 §Layer 3 reference.
    """

    def __init__(
        self,
        session: AsyncSession,
        *,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Construct a pruner bound to a single ``AsyncSession``.

        Args:
            session: Async SQLAlchemy session. Caller owns the transaction
                lifecycle (commit / rollback); the pruner only flushes the
                ``DELETE``.
            retention_days: Window in days. Observations older than this are
                pruned. Must be positive — a zero/negative window would delete
                every ``not_yours`` row and is almost certainly a config error.
            clock: Callable returning a timezone-aware ``datetime``. Defaults
                to ``datetime.now(UTC)``. Inject a frozen clock in tests.
        """
        if retention_days <= 0:
            raise ValueError(
                "retention_days must be positive; "
                f"got {retention_days!r}. ADR-008 §Layer 3 requires a "
                "non-zero retention window.",
            )
        self._session = session
        self._retention_days = retention_days
        self._clock = clock if clock is not None else _default_clock
        # Bind a logger up front so the per-call hot path doesn't repeatedly
        # incur ``get_logger`` overhead. Module-name binding keeps log
        # filtering / routing simple.
        self._log = structlog.get_logger(__name__)

    async def prune_tenant(self, *, tenant_id: UUID) -> PruneResult:
        """Delete expired ``not_yours`` observations for a single tenant.

        Args:
            tenant_id: Tenant whose graph is being pruned. The DELETE is
                tenant-scoped — never global — to honor ADR-007's tenant
                isolation contract.

        Returns:
            ``PruneResult`` with the rowcount, cutoff used, and the retention
            window applied. Returns ``deleted_count = 0`` if nothing matched
            (idempotent on repeat invocation).
        """
        now = self._clock()
        cutoff_at = now - timedelta(days=self._retention_days)

        # ``AsyncSession.execute`` is typed as ``Result[Any]`` for the general
        # case, but DML statements (INSERT/UPDATE/DELETE) always return a
        # ``CursorResult`` carrying the ``rowcount`` we need. Cast narrowly so
        # mypy --strict accepts the attribute access without an ``Any`` leak.
        result = cast(
            "CursorResult[Any]",
            await self._session.execute(
                text(_DELETE_STMT),
                {"tenant_id": tenant_id, "cutoff_at": cutoff_at},
            ),
        )
        # asyncpg/psycopg both surface ``rowcount`` for DELETE. Fall back to 0
        # if the driver ever reports ``-1`` (unknown) so callers always get a
        # non-negative count.
        deleted_count = max(result.rowcount or 0, 0)

        # Minimization contract: log the aggregate, never the identifiers.
        # Logging entity IDs we just deleted would defeat the purpose of the
        # retention window — the audit log would become the new long-term
        # storage of the very data ADR-008 §Layer 3 told us to drop.
        self._log.info(
            _LOG_EVENT_PRUNED,
            tenant_id=str(tenant_id),
            deleted_count=deleted_count,
            cutoff_at=cutoff_at.isoformat(),
            retention_days=self._retention_days,
        )

        return PruneResult(
            tenant_id=tenant_id,
            deleted_count=deleted_count,
            cutoff_at=cutoff_at,
            retention_days=self._retention_days,
        )
