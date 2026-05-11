"""FastAPI router for run scheduling endpoints.

Exposes CRUD operations for per-tenant cron schedules via the
:class:`~expose.pipeline.scheduler.RunScheduler`.  Schedule entries are
stored in memory (persistence deferred to Phase 3 tenant config).

Endpoints:

* **Create schedule**  -- ``POST /v1/scheduler/schedules``            -> 201
* **List schedules**    -- ``GET  /v1/scheduler/schedules``            -> 200
* **Get schedule**      -- ``GET  /v1/scheduler/schedules/{tenant_id}`` -> 200 | 404
* **Delete schedule**   -- ``DELETE /v1/scheduler/schedules/{tenant_id}`` -> 204 | 404
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from expose.pipeline.scheduler import CronExpression

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScheduleCreateRequest(BaseModel):
    """Body for ``POST /v1/scheduler/schedules``."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: UUID
    cron_expression: str = Field(
        ...,
        description="Standard 5-field cron expression (minute hour dom month dow).",
    )
    collector_ids: list[str] = Field(default_factory=list)
    seeds: list[dict[str, Any]] = Field(default_factory=list)


class ScheduleResponse(BaseModel):
    """Single schedule entry returned by schedule endpoints."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    cron_expression: str
    collector_ids: list[str]
    seeds: list[dict[str, Any]]
    last_run_at: datetime | None
    last_attempted_at: datetime | None
    next_run_at: datetime | None
    enabled: bool
    consecutive_failures: int
    last_error: str | None


class ScheduleListResponse(BaseModel):
    """List wrapper returned by ``GET /v1/scheduler/schedules``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schedules: list[ScheduleResponse]
    total: int


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/v1/scheduler", tags=["scheduler"])


def _entry_to_response(entry: Any) -> ScheduleResponse:
    """Convert a ``ScheduleEntry`` to its API response model."""
    return ScheduleResponse(
        tenant_id=entry.tenant_id,
        cron_expression=entry.cron_expression,
        collector_ids=list(entry.collector_ids),
        seeds=list(entry.seeds),
        last_run_at=entry.last_run_at,
        last_attempted_at=entry.last_attempted_at,
        next_run_at=entry.next_run_at,
        enabled=entry.enabled,
        consecutive_failures=entry.consecutive_failures,
        last_error=entry.last_error,
    )


def _get_scheduler(request: Request) -> Any:
    """Retrieve the ``RunScheduler`` from app state, or raise 503."""
    scheduler = getattr(request.app.state, "run_scheduler", None)
    if scheduler is None:
        raise HTTPException(
            status_code=503,
            detail="Run scheduler is not available",
        )
    return scheduler


# ---------------------------------------------------------------------------
# POST /schedules -- create a schedule
# ---------------------------------------------------------------------------


@router.post("/schedules", status_code=201, response_model=ScheduleResponse)
async def create_schedule(
    body: ScheduleCreateRequest,
    request: Request,
) -> ScheduleResponse:
    """Create (or replace) a cron schedule for a tenant.

    Validates the cron expression eagerly -- returns 422 if invalid.
    """
    # Validate cron expression before touching the scheduler.
    try:
        CronExpression(body.cron_expression)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    scheduler = _get_scheduler(request)

    entry = scheduler.add_schedule(
        tenant_id=body.tenant_id,
        cron_expression=body.cron_expression,
        collector_ids=body.collector_ids,
        seeds=body.seeds,
    )

    logger.info(
        "Schedule created via API: tenant_id=%s cron=%s",
        body.tenant_id,
        body.cron_expression,
    )
    return _entry_to_response(entry)


# ---------------------------------------------------------------------------
# GET /schedules -- list all schedules
# ---------------------------------------------------------------------------


@router.get("/schedules", response_model=ScheduleListResponse)
async def list_schedules(request: Request) -> ScheduleListResponse:
    """Return all registered schedules."""
    scheduler = _get_scheduler(request)
    entries = scheduler.list_schedules()
    return ScheduleListResponse(
        schedules=[_entry_to_response(e) for e in entries],
        total=len(entries),
    )


# ---------------------------------------------------------------------------
# GET /schedules/{tenant_id} -- get schedule for a tenant
# ---------------------------------------------------------------------------


@router.get("/schedules/{tenant_id}", response_model=ScheduleResponse)
async def get_schedule(
    tenant_id: UUID,
    request: Request,
) -> ScheduleResponse:
    """Return the schedule for a specific tenant, or 404."""
    scheduler = _get_scheduler(request)
    entry = scheduler.get_schedule(tenant_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return _entry_to_response(entry)


# ---------------------------------------------------------------------------
# DELETE /schedules/{tenant_id} -- remove schedule
# ---------------------------------------------------------------------------


@router.delete("/schedules/{tenant_id}", status_code=204)
async def delete_schedule(
    tenant_id: UUID,
    request: Request,
) -> None:
    """Remove the schedule for a tenant. Returns 404 if none exists."""
    scheduler = _get_scheduler(request)
    removed = scheduler.remove_schedule(tenant_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Schedule not found")
    logger.info("Schedule deleted via API: tenant_id=%s", tenant_id)
