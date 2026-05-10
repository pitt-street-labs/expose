"""FastAPI router for run and entity read endpoints.

Implements the run results API described in issue #10:

* **List runs**     — ``GET /v1/tenants/{tenant_id}/runs``     → 200
* **Get run**       — ``GET /v1/tenants/{tenant_id}/runs/{run_id}`` → 200 | 404
* **List entities** — ``GET /v1/tenants/{tenant_id}/entities`` → 200
* **Get entity**    — ``GET /v1/tenants/{tenant_id}/entities/{entity_id}`` → 200 | 404

All endpoints are tenant-scoped per ADR-007. The ``get_session`` dependency
is shared with the tenants router (imported from :mod:`expose.api.tenants`).
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from expose.api.schemas import (
    EntityList,
    EntityResponse,
    RunList,
    RunResponse,
)
from expose.api.tenants import get_session
from expose.db.models import Entity, Run

# ---------------------------------------------------------------------------
# Session dependency — reuses the same placeholder as tenants.py.
# ---------------------------------------------------------------------------

SessionDep = Annotated[AsyncSession, Depends(get_session)]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
        attribution_status=entity.attribution_status,
        first_observed_at=entity.first_observed_at,
        last_observed_at=entity.last_observed_at,
    )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/v1", tags=["runs", "entities"])


@router.get("/tenants/{tenant_id}/runs", response_model=RunList)
async def list_runs(
    tenant_id: UUID,
    session: SessionDep,
) -> RunList:
    """List all runs for a tenant."""
    stmt = select(Run).where(Run.tenant_id == tenant_id).order_by(Run.started_at.desc())
    result = await session.execute(stmt)
    runs = list(result.scalars().all())
    return RunList(
        runs=[_run_to_response(r) for r in runs],
        total=len(runs),
    )


@router.get("/tenants/{tenant_id}/runs/{run_id}", response_model=RunResponse)
async def get_run(
    tenant_id: UUID,
    run_id: UUID,
    session: SessionDep,
) -> RunResponse:
    """Get a specific run by ID."""
    stmt = select(Run).where(Run.id == run_id, Run.tenant_id == tenant_id)
    result = await session.execute(stmt)
    run = result.scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return _run_to_response(run)


@router.get("/tenants/{tenant_id}/entities", response_model=EntityList)
async def list_entities(
    tenant_id: UUID,
    session: SessionDep,
) -> EntityList:
    """List all entities discovered for a tenant."""
    stmt = (
        select(Entity).where(Entity.tenant_id == tenant_id).order_by(Entity.last_observed_at.desc())
    )
    result = await session.execute(stmt)
    entities = list(result.scalars().all())
    return EntityList(
        entities=[_entity_to_response(e) for e in entities],
        total=len(entities),
    )


@router.get(
    "/tenants/{tenant_id}/entities/{entity_id}",
    response_model=EntityResponse,
)
async def get_entity(
    tenant_id: UUID,
    entity_id: UUID,
    session: SessionDep,
) -> EntityResponse:
    """Get a specific entity by ID."""
    stmt = select(Entity).where(
        Entity.id == entity_id,
        Entity.tenant_id == tenant_id,
    )
    result = await session.execute(stmt)
    entity = result.scalar_one_or_none()
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    return _entity_to_response(entity)
