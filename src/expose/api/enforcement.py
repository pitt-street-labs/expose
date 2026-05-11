"""FastAPI router for enforcement refusal audit trail (issue #100).

Provides read-only access to scope refusal events recorded during pipeline
runs.  Refusals are stored in the run's ``run_metadata`` JSONB column under
the ``enforcement_refusals`` key and exposed here as a queryable list.

* **List refusals** -- ``GET /v1/tenants/{tenant_id}/runs/{run_id}/enforcement``
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from expose.api.tenants import get_session
from expose.db.models import Run

SessionDep = Annotated[AsyncSession, Depends(get_session)]

router = APIRouter(prefix="/v1", tags=["enforcement"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class EnforcementRefusalResponse(BaseModel):
    """Single scope-refusal event returned by the enforcement endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    entity_identifier: str
    attribution_tier: str | None = None
    enforcement_mode: str
    collector_id: str
    reason: str
    timestamp: datetime


class EnforcementRefusalList(BaseModel):
    """List wrapper for enforcement refusal events."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    refusals: list[EnforcementRefusalResponse]
    total: int


# ---------------------------------------------------------------------------
# GET /tenants/{tenant_id}/runs/{run_id}/enforcement
# ---------------------------------------------------------------------------


@router.get(
    "/tenants/{tenant_id}/runs/{run_id}/enforcement",
    response_model=EnforcementRefusalList,
)
async def list_enforcement_refusals(
    tenant_id: UUID,
    run_id: UUID,
    session: SessionDep,
) -> EnforcementRefusalList:
    """List scope-enforcement refusal events for a pipeline run.

    Returns the full audit trail of dispatches denied by the enforcement
    module during the specified run.  Returns an empty list when the run
    completed with no refusals.

    * **404** -- run does not exist or belongs to another tenant.
    """
    stmt = select(Run).where(Run.id == run_id, Run.tenant_id == tenant_id)
    result = await session.execute(stmt)
    run = result.scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    meta = run.run_metadata or {}
    raw_refusals = meta.get("enforcement_refusals", [])

    refusals = [
        EnforcementRefusalResponse(
            tenant_id=r.get("tenant_id", tenant_id),
            entity_identifier=r["entity_identifier"],
            attribution_tier=r.get("attribution_tier"),
            enforcement_mode=r.get("enforcement_mode", "hard"),
            collector_id=r["collector_id"],
            reason=r["reason"],
            timestamp=r["timestamp"],
        )
        for r in raw_refusals
    ]

    return EnforcementRefusalList(refusals=refusals, total=len(refusals))
