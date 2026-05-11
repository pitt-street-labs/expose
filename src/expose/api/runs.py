"""FastAPI router for run and entity endpoints.

Implements the run results API described in issue #10 plus the run trigger:

* **Start run**     — ``POST /v1/tenants/{tenant_id}/runs``    → 202
* **List runs**     — ``GET /v1/tenants/{tenant_id}/runs``     → 200
* **Get run**       — ``GET /v1/tenants/{tenant_id}/runs/{run_id}`` → 200 | 404
* **List entities** — ``GET /v1/tenants/{tenant_id}/entities`` → 200
* **Get entity**    — ``GET /v1/tenants/{tenant_id}/entities/{entity_id}`` → 200 | 404

All endpoints are tenant-scoped per ADR-007. The ``get_session`` dependency
is shared with the tenants router (imported from :mod:`expose.api.tenants`).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Annotated
from uuid import UUID

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import async_sessionmaker as _async_sessionmaker

    from expose.api.events import RunEventBus
    from expose.collectors.base import Seed

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from expose.api.schemas import (
    EntityList,
    EntityResponse,
    RunCreate,
    RunList,
    RunResponse,
    RunStarted,
)
from expose.api.tenants import get_session
from expose.db.models import Entity, Run, Tenant

logger = logging.getLogger(__name__)

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
        properties=entity.properties,
        attribution_status=entity.attribution_status,
        first_observed_at=entity.first_observed_at,
        last_observed_at=entity.last_observed_at,
    )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/v1", tags=["runs", "entities"])


# ---------------------------------------------------------------------------
# POST /tenants/{tenant_id}/runs — start a new pipeline run
# ---------------------------------------------------------------------------


def _get_tier1_collector_ids() -> list[str]:
    """Return collector IDs for all registered Tier-1 collectors."""
    import expose.collectors.builtin  # noqa: F401, PLC0415  — trigger @register_collector
    from expose.collectors.registry import DEFAULT_REGISTRY  # noqa: PLC0415
    from expose.collectors.tiers import CollectorTier  # noqa: PLC0415

    return [cls.collector_id for cls in DEFAULT_REGISTRY.by_tier(CollectorTier.TIER_1)]


# Default Tor SOCKS5 proxy address used when "socks5" is in egress_fallbacks
# but no explicit socks5_proxy URL is configured.
_DEFAULT_TOR_PROXY = "socks5://localhost:9050"


def _build_socks5_fallback(
    socks5_proxy: object,
) -> list:
    """Build a SOCKS5 egress fallback profile list.

    Returns a single-element list containing a ``Socks5EgressProfile`` if the
    ``socksio`` package is installed, or an empty list (with a warning) if it
    is not.  Callers should pass the result directly as ``egress_fallbacks``
    to ``PipelineDispatcher``.

    Args:
        socks5_proxy: The configured SOCKS5 proxy URL (str or None/empty).
            Falls back to ``socks5://localhost:9050`` (default Tor) when absent.
    """
    import importlib.util  # noqa: PLC0415

    if importlib.util.find_spec("socksio") is None:
        logger.warning(
            "Tenant config requests socks5 egress fallback but the "
            "'socksio' package is not installed — skipping SOCKS5 fallback. "
            "Install with: pip install socksio"
        )
        return []

    from expose.egress.socks5 import Socks5EgressProfile  # noqa: PLC0415

    proxy_url = str(socks5_proxy) if socks5_proxy else _DEFAULT_TOR_PROXY
    logger.info(
        "SOCKS5 egress fallback configured: proxy_url=%s",
        proxy_url,
    )
    return [Socks5EgressProfile(proxy_url=proxy_url)]


async def _run_pipeline_background(
    *,
    run_id: UUID,
    tenant_id: UUID,
    seeds: list[Seed],
    collector_ids: list[str],
    session_factory: _async_sessionmaker[AsyncSession],
    event_bus: RunEventBus | None,
) -> None:
    """Execute the pipeline in the background with its own DB session.

    The request session is closed by the time this runs, so we create a
    fresh session from the factory stored on ``app.state``.
    """
    from expose.api.tenant_config import get_tenant_config_data  # noqa: PLC0415
    from expose.collectors.registry import DEFAULT_REGISTRY  # noqa: PLC0415
    from expose.collectors.tiers import TenantAuthorizationScope  # noqa: PLC0415
    from expose.egress.base import EgressProfile  # noqa: PLC0415
    from expose.egress.direct import DirectEgressProfile  # noqa: PLC0415
    from expose.llm.client import SafeLLMClient  # noqa: PLC0415
    from expose.llm.providers import create_llm_provider  # noqa: PLC0415
    from expose.pipeline.dispatcher import PipelineDispatcher  # noqa: PLC0415
    from expose.pipeline.enrichment import EnrichmentPipeline  # noqa: PLC0415
    from expose.pipeline.run_executor import RunExecutor  # noqa: PLC0415
    from expose.repositories.entity_repo import EntityRepository  # noqa: PLC0415
    from expose.repositories.relationship_repo import RelationshipRepository  # noqa: PLC0415
    from expose.repositories.run_repo import RunRepository  # noqa: PLC0415

    try:
        async with session_factory() as session:
            try:
                run_repo = RunRepository(session)
                entity_repo = EntityRepository(session)
                relationship_repo = RelationshipRepository(session)

                seed_identifiers = frozenset(s.value for s in seeds)
                scope = TenantAuthorizationScope(
                    explicit_entity_identifiers=seed_identifiers,
                )

                # --- Resolve egress fallbacks from tenant config ---
                egress_fallbacks: list[EgressProfile] = []
                tenant_cfg = get_tenant_config_data(tenant_id)
                cfg_fallbacks = tenant_cfg.get("egress_fallbacks") or []
                cfg_socks5_proxy = tenant_cfg.get("socks5_proxy")

                if "socks5" in cfg_fallbacks:
                    egress_fallbacks = _build_socks5_fallback(
                        cfg_socks5_proxy,
                    )

                dispatcher = PipelineDispatcher(
                    registry=DEFAULT_REGISTRY,
                    tenant_scope=scope,
                    tenant_id=tenant_id,
                    egress_profile=DirectEgressProfile(),
                    egress_fallbacks=egress_fallbacks,
                )

                # --- Stage 4b: LLM enrichment pipeline (opt-in per tenant) ---
                enrichment_pipeline: EnrichmentPipeline | None = None
                llm_enabled = bool(tenant_cfg.get("llm_enabled", False))
                llm_provider_id = tenant_cfg.get("llm_provider")

                if llm_enabled and llm_provider_id:
                    try:
                        llm_model = tenant_cfg.get("llm_model") or None
                        cost_ceiling = float(
                            tenant_cfg.get("llm_cost_ceiling_per_run", 10.0)
                        )

                        provider = create_llm_provider(
                            str(llm_provider_id),
                            model=str(llm_model) if llm_model else None,
                        )
                        llm_client = SafeLLMClient(
                            primary_provider=provider,
                            cost_ceiling_per_run=cost_ceiling,
                        )
                        enrichment_pipeline = EnrichmentPipeline(
                            llm_client=llm_client,
                        )
                        logger.info(
                            "LLM enrichment enabled: provider=%s model=%s "
                            "cost_ceiling=%.2f run_id=%s tenant_id=%s",
                            llm_provider_id,
                            llm_model or "(default)",
                            cost_ceiling,
                            run_id,
                            tenant_id,
                        )
                    except Exception:
                        logger.warning(
                            "Failed to initialize LLM enrichment pipeline "
                            "(run will proceed without enrichment): "
                            "provider=%s run_id=%s tenant_id=%s",
                            llm_provider_id,
                            run_id,
                            tenant_id,
                            exc_info=True,
                        )

                executor = RunExecutor(
                    dispatcher=dispatcher,  # type: ignore[arg-type]
                    run_repo=run_repo,
                    entity_repo=entity_repo,
                    relationship_repo=relationship_repo,
                    enrichment_pipeline=enrichment_pipeline,
                )

                await executor.execute(
                    run_id=run_id,
                    tenant_id=tenant_id,
                    seeds=seeds,
                    collector_ids=collector_ids,
                )

                await session.commit()
            except Exception:
                await session.rollback()
                raise
    except Exception:
        logger.exception(
            "Background pipeline run failed: run_id=%s tenant_id=%s",
            run_id,
            tenant_id,
        )


@router.post("/tenants/{tenant_id}/runs", status_code=202, response_model=RunStarted)
async def start_run(
    tenant_id: UUID,
    body: RunCreate,
    request: Request,
    session: SessionDep,
) -> RunStarted:
    """Start a new pipeline run for a tenant.

    Returns 202 Accepted with the run_id. The run executes asynchronously.
    Monitor progress via SSE at ``/v1/tenants/{tenant_id}/runs/{run_id}/events``.
    """
    from datetime import UTC  # noqa: PLC0415
    from datetime import datetime as _datetime  # noqa: PLC0415
    from uuid import uuid4 as _uuid4  # noqa: PLC0415

    from expose import __version__  # noqa: PLC0415
    from expose.cli import detect_seed_type  # noqa: PLC0415
    from expose.collectors.base import Seed, SeedType  # noqa: PLC0415

    # 1. Verify the tenant exists
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # 2. Auto-detect seed types
    seed_objects: list[Seed] = []
    for raw_seed in body.seeds:
        st = SeedType(body.seed_type) if body.seed_type is not None else detect_seed_type(raw_seed)
        seed_objects.append(Seed(seed_type=st, value=raw_seed))

    # 2b. Add organization seeds (always typed ORGANIZATION)
    for org_seed in body.organization_seeds:
        org_value = org_seed.strip()
        if org_value:
            seed_objects.append(Seed(seed_type=SeedType.ORGANIZATION, value=org_value))

    # 3. Default collector_ids to all Tier-1 if not specified
    collector_ids = body.collector_ids if body.collector_ids else _get_tier1_collector_ids()

    # 4. Create Run row in the database
    run_id = _uuid4()
    run = Run(
        id=run_id,
        tenant_id=tenant_id,
        pipeline_version=__version__,
        state="pending",
        started_at=_datetime.now(UTC),
    )
    session.add(run)
    await session.flush()
    await session.commit()

    # 5. Start background pipeline execution
    sf = getattr(request.app.state, "session_factory", None)
    if sf is not None:
        from expose.api.events import get_event_bus  # noqa: PLC0415

        event_bus: RunEventBus | None = None
        if hasattr(request.app.state, "event_bus"):
            event_bus = get_event_bus(request.app)

        # Store reference to prevent GC before completion (RUF006).
        _bg_tasks: list[asyncio.Task[None]] = getattr(request.app.state, "_bg_tasks", [])
        task = asyncio.create_task(
            _run_pipeline_background(
                run_id=run_id,
                tenant_id=tenant_id,
                seeds=seed_objects,
                collector_ids=collector_ids,
                session_factory=sf,
                event_bus=event_bus,
            )
        )
        _bg_tasks.append(task)
        task.add_done_callback(_bg_tasks.remove)
        request.app.state._bg_tasks = _bg_tasks

    # 6. Return 202 immediately
    return RunStarted(
        run_id=run_id,
        tenant_id=tenant_id,
        state="pending",
        seeds=body.seeds,
        organization_seeds=body.organization_seeds,
        collector_ids=collector_ids,
        message=f"Run {run_id} accepted. Monitor via SSE at "
        f"/v1/tenants/{tenant_id}/runs/{run_id}/events",
    )


# ---------------------------------------------------------------------------
# GET endpoints
# ---------------------------------------------------------------------------


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
