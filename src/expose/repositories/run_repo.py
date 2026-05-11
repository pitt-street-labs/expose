"""Tenant-scoped repository for the ``runs`` table.

Per SPEC.md §2.2 / §10.3 each pipeline execution gets a ``runs`` row carrying
lifecycle metadata (``state``, ``started_at``, ``completed_at``,
``pipeline_version``) plus output references (``canonical_artifact_ref``,
``manifest_ref``). The actual canonical-artifact body lives in object storage
keyed by SHA-256 (per ADR-004); this row holds only the pointer.

Per ADR-007 every public method takes ``tenant_id`` as a required keyword
argument and includes it in every WHERE / INSERT clause; cross-tenant calls
return ``None`` / empty.

The ``state`` machine is the only behavioural rule enforced here — every other
field is structurally validated at the column level. The legal states match
the manifest schema's ``run.state`` enum:
``pending`` -> ``running`` -> { ``completed`` | ``failed`` | ``partial`` }.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from expose.db.models import Run
from expose.types.shared import RunId, TenantId

# Centralized so test code and other repositories can reference the canonical
# enum without re-typing it. Mirrors manifest-v1.json `pipeline.state`.
VALID_RUN_STATES: frozenset[str] = frozenset(
    {"pending", "running", "completed", "failed", "partial"}
)


class RunRepository:
    """Async tenant-scoped CRUD + state-machine for :class:`expose.db.models.Run`.

    Construct one per ``AsyncSession``. All methods are coroutines and require
    ``tenant_id``; cross-tenant reads/writes return ``None`` / raise
    ``LookupError`` (state-update path only) so a caller can never act on
    another tenant's run by mistake.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        tenant_id: TenantId,
        pipeline_version: str,
        target_count: int | None = None,
    ) -> Run:
        """Insert a new run in state ``pending``.

        ``started_at`` defaults to ``NOW()`` from the schema. The state
        transitions to ``running`` when the executor picks the row up; see
        :meth:`update_state`.
        """
        run = Run(
            id=uuid4(),
            tenant_id=tenant_id,
            pipeline_version=pipeline_version,
            state="pending",
            target_count=target_count,
        )
        self._session.add(run)
        await self._session.flush()
        return run

    async def get_by_id(
        self,
        *,
        tenant_id: TenantId,
        run_id: RunId,
    ) -> Run | None:
        """Fetch by primary key, scoped to ``tenant_id``.

        Returns ``None`` if the row does not exist OR exists under a different
        tenant.
        """
        stmt = select(Run).where(Run.id == run_id, Run.tenant_id == tenant_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_state(
        self,
        *,
        tenant_id: TenantId,
        run_id: RunId,
        new_state: str,
        completed_at: datetime | None = None,
        canonical_artifact_ref: str | None = None,
        manifest_ref: str | None = None,
    ) -> Run:
        """Advance a run's lifecycle.

        Validates ``new_state`` against :data:`VALID_RUN_STATES` and rejects
        unknown values with :class:`ValueError`. If no row matches
        ``(tenant_id, run_id)`` — including the cross-tenant case — raises
        :class:`LookupError` (a missing-or-foreign-tenant signal that callers
        upstream can convert into a 404 / "no such run").

        Optional companion fields (``completed_at``, ``canonical_artifact_ref``,
        ``manifest_ref``) are applied only when supplied; passing ``None``
        leaves the existing column value untouched. This lets the executor
        flip the state to ``running`` first, then later flip to ``completed``
        with the artifact pointers attached.
        """
        if new_state not in VALID_RUN_STATES:
            raise ValueError(
                f"Invalid run state {new_state!r}; expected one of "
                f"{sorted(VALID_RUN_STATES)}"
            )

        run = await self.get_by_id(tenant_id=tenant_id, run_id=run_id)
        if run is None:
            raise LookupError(
                f"No run found for tenant_id={tenant_id} run_id={run_id}"
            )

        run.state = new_state
        # Auto-set completed_at for terminal states when not explicitly provided.
        _terminal_states = {"completed", "partial", "failed"}
        if completed_at is not None:
            run.completed_at = completed_at
        elif new_state in _terminal_states and run.completed_at is None:
            run.completed_at = datetime.now(UTC)
        if canonical_artifact_ref is not None:
            run.canonical_artifact_ref = canonical_artifact_ref
        if manifest_ref is not None:
            run.manifest_ref = manifest_ref

        await self._session.flush()
        return run

    async def list_for_tenant(
        self,
        *,
        tenant_id: TenantId,
        state: str | None = None,
        limit: int = 50,
    ) -> Sequence[Run]:
        """List a tenant's runs, optionally filtered by ``state``.

        Ordered by ``started_at DESC`` — the dashboard / CLI ``runs list``
        path wants the most-recent execution first.
        """
        stmt = select(Run).where(Run.tenant_id == tenant_id)
        if state is not None:
            if state not in VALID_RUN_STATES:
                raise ValueError(
                    f"Invalid run state filter {state!r}; expected one of "
                    f"{sorted(VALID_RUN_STATES)}"
                )
            stmt = stmt.where(Run.state == state)
        stmt = stmt.order_by(Run.started_at.desc()).limit(limit)
        result = await self._session.execute(stmt)
        return result.scalars().all()


__all__ = ["VALID_RUN_STATES", "RunRepository"]
