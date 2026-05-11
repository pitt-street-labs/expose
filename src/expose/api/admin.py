"""FastAPI router for administrative endpoints.

Provides system-level operations that are not tenant-scoped:

* **Cancel run**           -- ``POST   /v1/admin/runs/{run_id}/cancel``
* **Delete run**           -- ``DELETE /v1/admin/runs/{run_id}``
* **System stats**         -- ``GET    /v1/admin/stats``
* **Bulk credential test** -- ``POST   /v1/admin/tenants/{tenant_id}/credentials/test-all``

These endpoints are intended for platform operators and internal tooling.
Phase 1 has no authentication gate; RBAC enforcement lands in Sprint 5+.
"""

from __future__ import annotations

import difflib
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from expose.api.credentials import KNOWN_SLOTS, CredentialTestResult, test_credential
from expose.api.run_log import clear_run_log
from expose.api.tenants import get_session
from expose.db.models import Entity, Relationship, Run

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class CancelResponse(BaseModel):
    """Response for run cancellation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str
    run_id: str


class SystemStats(BaseModel):
    """Response for system-wide statistics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    total_entities: int
    total_relationships: int
    total_runs: int
    runs_by_state: dict[str, int]
    registered_collectors: int
    server_started_at: str | None


class BulkCredentialTestResponse(BaseModel):
    """Response for bulk credential testing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    results: list[CredentialTestResult]


class OrgSuggestionItem(BaseModel):
    """A single organization name suggestion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    source: str
    score: float


class OrgSuggestResponse(BaseModel):
    """Response for organization name suggestions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    suggestions: list[OrgSuggestionItem]


# Terminal run states -- runs in these states cannot be cancelled.
_TERMINAL_STATES = frozenset({"completed", "partial", "failed"})

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/v1/admin", tags=["admin"])


# ---------------------------------------------------------------------------
# POST /runs/{run_id}/cancel -- cancel a running pipeline
# ---------------------------------------------------------------------------


@router.post("/runs/{run_id}/cancel", response_model=CancelResponse)
async def cancel_run(
    run_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> CancelResponse:
    """Cancel a pipeline run by cancelling its background asyncio task.

    Looks up the run in the database, verifies it is not already in a
    terminal state, cancels the asyncio.Task if one exists, and sets the
    run state to ``failed`` with ``completed_at`` stamped.

    Returns 404 if the run does not exist. Returns 409 if the run is
    already in a terminal state (completed / partial / failed).
    """
    # 1. Look up the run (not tenant-scoped -- admin endpoint)
    run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    # 2. Check for terminal state
    if run.state in _TERMINAL_STATES:
        raise HTTPException(
            status_code=409,
            detail=f"Run is already in terminal state: {run.state}",
        )

    # 3. Cancel the asyncio task if present
    bg_tasks: dict[str, Any] = getattr(request.app.state, "_bg_tasks", {})
    task_key = str(run_id)
    task = bg_tasks.get(task_key)
    if task is not None:
        task.cancel()
        bg_tasks.pop(task_key, None)

    # 4. Update run state to failed
    run.state = "failed"
    run.completed_at = datetime.now(UTC)
    await session.flush()

    logger.info("admin_cancel_run: run_id=%s cancelled", run_id)

    return CancelResponse(status="cancelled", run_id=str(run_id))


# ---------------------------------------------------------------------------
# DELETE /runs/{run_id} -- delete a run and its logs
# ---------------------------------------------------------------------------


@router.delete("/runs/{run_id}", status_code=204)
async def delete_run(
    run_id: UUID,
    session: AsyncSession = Depends(get_session),
) -> None:
    """Delete a run row and its in-memory log entries.

    Entities are NOT deleted -- they belong to the tenant, not the run.
    Returns 204 on success. Returns 404 if the run does not exist.
    """
    run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    await session.delete(run)
    await session.flush()

    # Clean up in-memory run logs
    clear_run_log(str(run_id))

    logger.info("admin_delete_run: run_id=%s deleted", run_id)


# ---------------------------------------------------------------------------
# GET /stats -- system-wide statistics
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=SystemStats)
async def system_stats(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> SystemStats:
    """Return system-wide statistics across all tenants.

    Counts entities, relationships, runs (total and by state), the number
    of registered collectors, and the server start time.
    """
    # Total entities
    entity_result = await session.execute(select(func.count(Entity.id)))
    total_entities = entity_result.scalar_one()

    # Total relationships
    rel_result = await session.execute(select(func.count(Relationship.id)))
    total_relationships = rel_result.scalar_one()

    # Total runs
    run_result = await session.execute(select(func.count(Run.id)))
    total_runs = run_result.scalar_one()

    # Runs by state
    state_result = await session.execute(
        select(Run.state, func.count(Run.id)).group_by(Run.state)
    )
    runs_by_state: dict[str, int] = {}
    for state, count in state_result.all():
        runs_by_state[state] = count

    # Registered collectors
    import expose.collectors.builtin  # noqa: F401, PLC0415

    from expose.collectors.registry import DEFAULT_REGISTRY  # noqa: PLC0415

    registered_collectors = len(DEFAULT_REGISTRY)

    # Server started_at
    server_started_at = getattr(request.app.state, "server_started_at", None)
    started_str = server_started_at.isoformat() if server_started_at else None

    return SystemStats(
        total_entities=total_entities,
        total_relationships=total_relationships,
        total_runs=total_runs,
        runs_by_state=runs_by_state,
        registered_collectors=registered_collectors,
        server_started_at=started_str,
    )


# ---------------------------------------------------------------------------
# POST /tenants/{tenant_id}/credentials/test-all -- bulk credential test
# ---------------------------------------------------------------------------


@router.post(
    "/tenants/{tenant_id}/credentials/test-all",
    response_model=BulkCredentialTestResponse,
)
async def bulk_test_credentials(tenant_id: UUID) -> BulkCredentialTestResponse:
    """Test all known credential slots for a tenant.

    Iterates every entry in ``KNOWN_SLOTS`` and calls the existing
    ``test_credential`` logic for each. Returns an array of results.
    """
    results: list[CredentialTestResult] = []
    for slot in KNOWN_SLOTS:
        result = await test_credential(tenant_id, slot.credential_id)
        results.append(result)

    return BulkCredentialTestResponse(results=results)


# ---------------------------------------------------------------------------
# GET /org-suggest -- fuzzy organization name suggestions
# ---------------------------------------------------------------------------


@router.get("/org-suggest", response_model=OrgSuggestResponse)
async def suggest_org(
    q: str = Query(..., min_length=1, description="Organization name query"),
    session: AsyncSession = Depends(get_session),
) -> OrgSuggestResponse:
    """Suggest organization names based on fuzzy matching.

    Queries previously scanned entity properties for ``registrant_org``
    values and uses ``difflib.get_close_matches()`` to find close matches
    against the input query ``q``.

    Returns up to 5 suggestions sorted by descending similarity score.
    If no entities with ``registrant_org`` exist (e.g. first scan), returns
    an empty suggestion list.
    """
    # 1. Collect all distinct registrant_org values from entity properties.
    #    The registrant_org is stored inside the JSONB ``properties`` column.
    result = await session.execute(select(Entity.properties))
    all_props = result.scalars().all()

    known_orgs: set[str] = set()
    for props in all_props:
        if isinstance(props, dict):
            org = props.get("registrant_org")
            if org and isinstance(org, str) and org.strip():
                known_orgs.add(org.strip())

    if not known_orgs:
        return OrgSuggestResponse(suggestions=[])

    # 2. Use difflib.get_close_matches for fuzzy matching.
    #    cutoff=0.4 allows reasonably loose matches (e.g. typos).
    org_list = sorted(known_orgs)
    matches = difflib.get_close_matches(q, org_list, n=5, cutoff=0.4)

    # 3. Compute similarity scores for each match.
    suggestions: list[OrgSuggestionItem] = []
    for match in matches:
        ratio = difflib.SequenceMatcher(None, q.lower(), match.lower()).ratio()
        suggestions.append(
            OrgSuggestionItem(
                name=match,
                source="local_db",
                score=round(ratio, 3),
            )
        )

    # Sort by descending score (get_close_matches already does this, but
    # our re-computed ratio may differ slightly from its internal scoring).
    suggestions.sort(key=lambda s: s.score, reverse=True)

    return OrgSuggestResponse(suggestions=suggestions)


__all__ = [
    "BulkCredentialTestResponse",
    "CancelResponse",
    "OrgSuggestResponse",
    "OrgSuggestionItem",
    "SystemStats",
    "router",
]
