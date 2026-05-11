"""Service layer for run and entity operations.

Extracts run/entity business logic from the API route handler into a
reusable service class that receives an ``AsyncSession`` via dependency
injection.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from expose.api.schemas import (
    EntityList,
    EntityResponse,
    RunList,
    RunResponse,
    RunStarted,
)
from expose.db.models import Entity, Run, Tenant


def _run_to_response(run: Run) -> RunResponse:
    return RunResponse(
        id=run.id,
        tenant_id=run.tenant_id,
        state=run.state,
        started_at=run.started_at,
        completed_at=run.completed_at,
        pipeline_version=run.pipeline_version,
    )


def _entity_to_response(entity: Entity) -> EntityResponse:
    return EntityResponse(
        id=entity.id,
        tenant_id=entity.tenant_id,
        entity_type=entity.entity_type,
        canonical_identifier=entity.canonical_identifier,
        properties=entity.properties,
        attribution_status=entity.attribution_status,
        first_observed_at=entity.first_observed_at,
        last_observed_at=entity.last_observed_at,
    )


class RunService:
    """Manages pipeline runs and entity queries.

    Handles run creation, listing, and entity queries with tenant-scoped
    data isolation per ADR-007.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_run(
        self,
        tenant_id: UUID,
        seeds: list[str],
        *,
        seed_type: str | None = None,
        organization_seeds: list[str] | None = None,
        collector_ids: list[str] | None = None,
    ) -> RunStarted | None:
        """Create a new pipeline run.

        Returns None if the tenant does not exist.  The caller (route handler)
        is responsible for mapping None to a 404 HTTP response and for
        launching the background pipeline execution.

        Seed and collector validation is performed here. If validation fails,
        a ``ValueError`` is raised with the list of error messages as the
        exception argument.
        """
        import ipaddress  # noqa: PLC0415
        import re  # noqa: PLC0415
        from datetime import UTC  # noqa: PLC0415
        from datetime import datetime as _datetime  # noqa: PLC0415
        from uuid import uuid4 as _uuid4  # noqa: PLC0415

        from expose import __version__  # noqa: PLC0415
        from expose.api.runs import _validate_collector_ids, _validate_seed  # noqa: PLC0415
        from expose.cli import detect_seed_type  # noqa: PLC0415
        from expose.collectors.base import Seed, SeedType  # noqa: PLC0415

        # 1. Verify the tenant exists
        tenant = await self._session.get(Tenant, tenant_id)
        if tenant is None:
            return None

        # 1b. Validate seed formats
        seed_errors: list[str] = []
        for raw_seed in seeds:
            err = _validate_seed(raw_seed)
            if err is not None:
                seed_errors.append(err)
        if seed_errors:
            raise ValueError(seed_errors)

        # 1c. Validate collector_ids against the registry
        if collector_ids:
            collector_errors = _validate_collector_ids(collector_ids)
            if collector_errors:
                raise ValueError(collector_errors)

        # 2. Auto-detect seed types
        seed_objects: list[Seed] = []
        for raw_seed in seeds:
            st = SeedType(seed_type) if seed_type is not None else detect_seed_type(raw_seed)
            seed_objects.append(Seed(seed_type=st, value=raw_seed))

        # 2b. Add organization seeds
        org_seeds = organization_seeds or []
        for org_seed in org_seeds:
            org_value = org_seed.strip()
            if org_value:
                seed_objects.append(Seed(seed_type=SeedType.ORGANIZATION, value=org_value))

        # 3. Default collector_ids to all Tier-1 if not specified
        from expose.api.runs import _get_tier1_collector_ids  # noqa: PLC0415

        resolved_collector_ids = collector_ids if collector_ids else _get_tier1_collector_ids()

        # 4. Create Run row in the database
        run_id = _uuid4()
        run = Run(
            id=run_id,
            tenant_id=tenant_id,
            pipeline_version=__version__,
            state="pending",
            started_at=_datetime.now(UTC),
        )
        self._session.add(run)
        await self._session.flush()
        await self._session.commit()

        return RunStarted(
            run_id=run_id,
            tenant_id=tenant_id,
            state="pending",
            seeds=seeds,
            organization_seeds=org_seeds,
            collector_ids=resolved_collector_ids,
            message=f"Run {run_id} accepted. Monitor via SSE at "
            f"/v1/tenants/{tenant_id}/runs/{run_id}/events",
        )

    async def get_run(
        self,
        tenant_id: UUID,
        run_id: UUID,
    ) -> RunResponse | None:
        """Get a specific run by ID. Returns None if not found."""
        stmt = select(Run).where(Run.id == run_id, Run.tenant_id == tenant_id)
        result = await self._session.execute(stmt)
        run = result.scalar_one_or_none()
        if run is None:
            return None
        return _run_to_response(run)

    async def list_runs(
        self,
        tenant_id: UUID,
    ) -> RunList:
        """List all runs for a tenant."""
        stmt = select(Run).where(Run.tenant_id == tenant_id).order_by(Run.started_at.desc())
        result = await self._session.execute(stmt)
        runs = list(result.scalars().all())
        return RunList(
            runs=[_run_to_response(r) for r in runs],
            total=len(runs),
        )

    async def list_entities(
        self,
        tenant_id: UUID,
    ) -> EntityList:
        """List all entities discovered for a tenant."""
        stmt = (
            select(Entity).where(Entity.tenant_id == tenant_id).order_by(Entity.last_observed_at.desc())
        )
        result = await self._session.execute(stmt)
        entities = list(result.scalars().all())
        return EntityList(
            entities=[_entity_to_response(e) for e in entities],
            total=len(entities),
        )

    async def get_entity(
        self,
        tenant_id: UUID,
        entity_id: UUID,
    ) -> EntityResponse | None:
        """Get a specific entity by ID. Returns None if not found."""
        stmt = select(Entity).where(
            Entity.id == entity_id,
            Entity.tenant_id == tenant_id,
        )
        result = await self._session.execute(stmt)
        entity = result.scalar_one_or_none()
        if entity is None:
            return None
        return _entity_to_response(entity)
