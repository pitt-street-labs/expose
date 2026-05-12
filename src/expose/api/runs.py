"""FastAPI router for run and entity endpoints.

Implements the run results API described in issue #10 plus the run trigger:

* **Start run**       — ``POST /v1/tenants/{tenant_id}/runs``    → 202
* **List runs**       — ``GET /v1/tenants/{tenant_id}/runs``     → 200
* **Get run**         — ``GET /v1/tenants/{tenant_id}/runs/{run_id}`` → 200 | 404
* **Download artifact** — ``GET /v1/tenants/{tenant_id}/runs/{run_id}/artifact`` → 200 | 404 | 409
* **List entities**   — ``GET /v1/tenants/{tenant_id}/entities`` → 200
* **Get entity**      — ``GET /v1/tenants/{tenant_id}/entities/{entity_id}`` → 200 | 404

All endpoints are tenant-scoped per ADR-007. The ``get_session`` dependency
is shared with the tenants router (imported from :mod:`expose.api.tenants`).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import async_sessionmaker as _async_sessionmaker

    from expose.api.events import RunEventBus
    from expose.collectors.base import Seed

from expose.types.shared import RunId, TenantId

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from expose.api.schemas import (
    EntityDelta,
    EntityList,
    EntityResponse,
    RunCreate,
    RunList,
    RunResponse,
    RunStarted,
    ScanDeltaResponse,
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
    meta = getattr(run, "run_metadata", None) or {}
    refusals = meta.get("enforcement_refusals")
    refusal_count = len(refusals) if refusals is not None else None
    return RunResponse(
        id=run.id,
        tenant_id=run.tenant_id,
        state=run.state,
        started_at=run.started_at,
        completed_at=run.completed_at,
        pipeline_version=run.pipeline_version,
        enforcement_refusal_count=refusal_count,
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
# Input validation helpers (issue #149)
# ---------------------------------------------------------------------------

# Domain label: letters, digits, hyphens; cannot start/end with hyphen.
# Full domain: 1+ labels separated by dots.
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
)


def _validate_seed(raw_seed: str) -> str | None:
    """Validate a single seed value (domain, IP, or CIDR).

    Returns ``None`` if valid, or an error message string if invalid.
    """
    raw_seed = raw_seed.strip()
    if not raw_seed:
        return "Seed value must not be empty."

    # Try IP address.
    try:
        ipaddress.ip_address(raw_seed)
        return None
    except ValueError:
        pass

    # Try CIDR network.
    try:
        ipaddress.ip_network(raw_seed, strict=False)
        return None
    except ValueError:
        pass

    # Try domain.
    if _DOMAIN_RE.match(raw_seed):
        return None

    return (
        f"Invalid seed format: {raw_seed!r}. "
        "Expected a domain name (e.g. example.com), "
        "IP address (e.g. 192.168.1.1), "
        "or CIDR notation (e.g. 10.0.0.0/24)."
    )


def _validate_collector_ids(collector_ids: list[str]) -> list[str]:
    """Validate collector IDs against the registry.

    Returns a list of error messages for unknown collector IDs.
    Returns an empty list if all IDs are valid.
    """
    import expose.collectors.builtin  # noqa: F401, PLC0415
    from expose.collectors.registry import DEFAULT_REGISTRY  # noqa: PLC0415

    errors: list[str] = []
    registered = set(DEFAULT_REGISTRY.all_ids())
    for cid in collector_ids:
        if cid not in registered:
            errors.append(
                f"Unknown collector_id: {cid!r}. "
                f"Registered collectors: {sorted(registered)}"
            )
    return errors


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
    from expose.api.run_log import make_log_sink  # noqa: PLC0415
    from expose.api.tenant_config import get_tenant_config_data  # noqa: PLC0415
    from expose.collectors.registry import DEFAULT_REGISTRY  # noqa: PLC0415
    from expose.collectors.tiers import TenantAuthorizationScope  # noqa: PLC0415
    from expose.egress.base import EgressProfile  # noqa: PLC0415
    from expose.egress.direct import DirectEgressProfile  # noqa: PLC0415
    from expose.llm.client import SafeLLMClient  # noqa: PLC0415
    from expose.llm.providers import create_llm_provider  # noqa: PLC0415
    from expose.pipeline.dispatcher import PipelineDispatcher  # noqa: PLC0415
    from expose.pipeline.enforcement import EnforcementLog  # noqa: PLC0415
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

                log_sink = make_log_sink(run_id)
                enforcement_log = EnforcementLog()

                # --- Wire credential resolver from secrets backend ---
                from expose.pipeline.credential_resolver import CredentialResolver  # noqa: PLC0415
                from expose.api.credentials import _backend as secrets_backend  # noqa: PLC0415

                credential_resolver = CredentialResolver(secrets_backend)

                dispatcher = PipelineDispatcher(
                    registry=DEFAULT_REGISTRY,
                    tenant_scope=scope,
                    tenant_id=tenant_id,
                    egress_profile=DirectEgressProfile(),
                    enforcement_log=enforcement_log,
                    egress_fallbacks=egress_fallbacks,
                    log_sink=log_sink,
                    credential_resolver=credential_resolver,
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

                # --- Rule pack loading (issue #96) ---
                rule_pack = None
                scope_context = None
                try:
                    import pathlib  # noqa: PLC0415
                    from expose.types.rulepack import RulePack  # noqa: PLC0415
                    from expose.types.pipeline import ScopeContext  # noqa: PLC0415

                    rule_pack_id = tenant_cfg.get("rule_pack_id")
                    rulepacks_dir = (
                        pathlib.Path(__file__).resolve().parent.parent.parent
                        / "examples"
                        / "rulepacks"
                    )

                    if rule_pack_id:
                        pack_file = rulepacks_dir / f"{rule_pack_id}.json"
                    else:
                        pack_file = rulepacks_dir / "example-baseline.json"

                    if pack_file.exists():
                        rule_pack = RulePack.model_validate_json(
                            pack_file.read_text()
                        )
                        logger.info(
                            "Loaded rule pack %s from %s",
                            rule_pack.pack_id,
                            pack_file.name,
                        )

                    # Build ScopeContext from seeds
                    seed_values_list = [s.value for s in seeds]
                    apex_domains: list[str] = []
                    for s in seeds:
                        if s.seed_type.value == "domain":
                            apex_domains.append(s.value)

                    scope_context = ScopeContext(
                        explicit_entity_identifiers=seed_values_list,
                        apex_domains=apex_domains,
                    )
                except Exception:
                    logger.warning(
                        "Failed to load rule pack (run will proceed without "
                        "rule-based attribution): run_id=%s tenant_id=%s",
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
                    log_sink=log_sink,
                    event_bus=event_bus,
                    rule_pack=rule_pack,
                    scope_context=scope_context,
                )

                await executor.execute(
                    run_id=run_id,
                    tenant_id=tenant_id,
                    seeds=seeds,
                    collector_ids=collector_ids,
                )

                # --- Serialize enforcement refusals into run log ---
                refusals_data: list[dict[str, Any]] = []
                if enforcement_log.refusal_count > 0:
                    refusals_data = [
                        r.model_dump(mode="json")
                        for r in enforcement_log.refusals
                    ]
                    logger.info(
                        "Run %s completed with %d enforcement refusal(s): %s",
                        run_id,
                        enforcement_log.refusal_count,
                        [r["entity_identifier"] for r in refusals_data],
                    )
                    if log_sink is not None:
                        log_sink(
                            "info",
                            f"Enforcement: {enforcement_log.refusal_count} "
                            f"dispatch(es) denied by scope/tier gate",
                        )

                # --- Persist enforcement refusals to run metadata ---
                run = await run_repo.get_by_id(
                    tenant_id=TenantId(tenant_id),
                    run_id=RunId(run_id),
                )
                if run is not None:
                    existing_meta = run.run_metadata or {}
                    existing_meta["enforcement_refusals"] = refusals_data
                    run.run_metadata = existing_meta
                    await session.flush()

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
        # Update run state to 'failed' so it doesn't stay 'pending' forever.
        # Use a fresh session because the original may be in a broken state.
        try:
            async with session_factory() as error_session:
                from expose.repositories.run_repo import RunRepository  # noqa: PLC0415

                error_repo = RunRepository(error_session)
                await error_repo.update_state(
                    tenant_id=TenantId(tenant_id),
                    run_id=RunId(run_id),
                    new_state="failed",
                )
                await error_session.commit()
        except Exception:
            logger.exception("Failed to update run state to 'failed'")


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

    # 1b. Validate seed formats (issue #149)
    seed_errors: list[str] = []
    for raw_seed in body.seeds:
        err = _validate_seed(raw_seed)
        if err is not None:
            seed_errors.append(err)
    if seed_errors:
        raise HTTPException(status_code=422, detail=seed_errors)

    # 1c. Validate collector_ids against the registry (issue #149)
    if body.collector_ids:
        collector_errors = _validate_collector_ids(body.collector_ids)
        if collector_errors:
            raise HTTPException(status_code=422, detail=collector_errors)

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
        run_metadata={},
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
        # Dict keyed by run_id string so admin cancel can look up tasks.
        # Mutate in-place — the dict is initialized once in lifespan startup.
        bg_tasks: dict[str, asyncio.Task[None]] = request.app.state._bg_tasks
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
        task_key = str(run_id)
        bg_tasks[task_key] = task
        task.add_done_callback(lambda _t: bg_tasks.pop(task_key, None))

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
    from expose.services.run_service import RunService  # noqa: PLC0415

    service = RunService(session)
    return await service.list_runs(tenant_id)


@router.get("/tenants/{tenant_id}/runs/{run_id}", response_model=RunResponse)
async def get_run(
    tenant_id: UUID,
    run_id: UUID,
    session: SessionDep,
) -> RunResponse:
    """Get a specific run by ID."""
    from expose.services.run_service import RunService  # noqa: PLC0415

    service = RunService(session)
    result = await service.get_run(tenant_id, run_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return result


@router.get("/tenants/{tenant_id}/runs/{run_id}/artifact")
async def download_artifact(
    tenant_id: UUID,
    run_id: UUID,
    session: SessionDep,
) -> Response:
    """Download the canonical artifact for a completed run.

    Returns the JSON artifact with ``Content-Disposition: attachment`` so
    clients receive a downloadable file.

    * **404** — run does not exist or belongs to another tenant.
    * **409** — run exists but has not reached a terminal state yet
      (still ``pending`` or ``running``).
    """
    from expose.pipeline.artifact_generator import ArtifactGenerator  # noqa: PLC0415
    from expose.repositories.entity_repo import EntityRepository  # noqa: PLC0415
    from expose.repositories.relationship_repo import RelationshipRepository  # noqa: PLC0415
    from expose.repositories.run_repo import RunRepository  # noqa: PLC0415

    # 1. Verify the run exists and belongs to the tenant
    stmt = select(Run).where(Run.id == run_id, Run.tenant_id == tenant_id)
    result = await session.execute(stmt)
    run = result.scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    # 2. Reject non-terminal runs (pending/running)
    _terminal_states = {"completed", "failed", "partial"}
    if run.state not in _terminal_states:
        raise HTTPException(
            status_code=409,
            detail=f"Run is still {run.state}; artifact is only available "
            f"for completed runs",
        )

    # 3. Generate the canonical artifact (with signing when available)
    from expose.api.signing import get_signer  # noqa: PLC0415

    run_repo = RunRepository(session)
    entity_repo = EntityRepository(session)
    relationship_repo = RelationshipRepository(session)

    generator = ArtifactGenerator(
        entity_repo=entity_repo,
        relationship_repo=relationship_repo,
        run_repo=run_repo,
        signer=get_signer(),
    )

    artifact_result = await generator.generate(
        run_id=run_id,
        tenant_id=tenant_id,
    )

    # 4. Return the JSON artifact as a downloadable file
    filename = f"expose-artifact-{run_id}.json"
    headers: dict[str, str] = {
        "Content-Disposition": f'attachment; filename="{filename}"',
    }
    # Include signature metadata in response headers when signing succeeds.
    if artifact_result.signature is not None:
        headers["X-Artifact-Signature"] = artifact_result.signature.signature_b64
        headers["X-Signature-Key-Id"] = artifact_result.signature.key_id
        headers["X-Signature-Algorithm"] = artifact_result.signature.algorithm

    return Response(
        content=artifact_result.json_bytes,
        media_type="application/json",
        headers=headers,
    )


# ---------------------------------------------------------------------------
# GET /tenants/{tenant_id}/runs/{run_id}/delta — compare two runs
# ---------------------------------------------------------------------------


@router.get(
    "/tenants/{tenant_id}/runs/{run_id}/delta",
    response_model=ScanDeltaResponse,
)
async def get_run_delta(
    tenant_id: UUID,
    run_id: UUID,
    session: SessionDep,
    baseline_run_id: UUID = Query(..., description="Run ID of the baseline to compare against"),
) -> ScanDeltaResponse:
    """Compare entities between a current run and a baseline run.

    Returns new entities, removed entities, and score changes between the
    two runs.  Entities are matched by ``(entity_type, canonical_identifier)``
    using the pure ``compute_delta`` engine from the pipeline layer.

    * **404** — either run does not exist or belongs to another tenant.
    """
    from expose.pipeline.delta import EntitySnapshot, compute_delta  # noqa: PLC0415

    # 1. Load both runs and verify they belong to this tenant
    current_run_stmt = select(Run).where(Run.id == run_id, Run.tenant_id == tenant_id)
    result = await session.execute(current_run_stmt)
    current_run = result.scalar_one_or_none()
    if current_run is None:
        raise HTTPException(status_code=404, detail="Current run not found")

    baseline_run_stmt = select(Run).where(Run.id == baseline_run_id, Run.tenant_id == tenant_id)
    result = await session.execute(baseline_run_stmt)
    baseline_run = result.scalar_one_or_none()
    if baseline_run is None:
        raise HTTPException(status_code=404, detail="Baseline run not found")

    # 2. Load entities for each run's time window
    #    "Baseline" entities: last_observed_at >= baseline.started_at
    #      AND last_observed_at < current.started_at
    #    "Current" entities: last_observed_at >= current.started_at
    #    For a simpler approach that works even when runs overlap or timestamps
    #    are coarse: use first_observed_at to identify new entities and
    #    last_observed_at to identify removed ones.

    # Current run entities: entities observed during or after the current run
    current_entity_stmt = select(Entity).where(
        Entity.tenant_id == tenant_id,
        Entity.last_observed_at >= current_run.started_at,
    )
    result = await session.execute(current_entity_stmt)
    current_entities = list(result.scalars().all())

    # Baseline run entities: entities observed during the baseline window
    # (between baseline start and current start)
    baseline_entity_stmt = select(Entity).where(
        Entity.tenant_id == tenant_id,
        Entity.last_observed_at >= baseline_run.started_at,
        Entity.last_observed_at < current_run.started_at,
    )
    result = await session.execute(baseline_entity_stmt)
    baseline_entities_exclusive = list(result.scalars().all())

    # Also include entities that span both runs (observed in both windows)
    # by combining baseline-exclusive with entities present in current that
    # existed before the current run started.
    baseline_identifiers = {
        (e.entity_type, e.canonical_identifier) for e in baseline_entities_exclusive
    }
    for e in current_entities:
        if e.first_observed_at < current_run.started_at:
            baseline_identifiers.add((e.entity_type, e.canonical_identifier))

    # Rebuild baseline snapshot list: entities in the baseline window plus
    # entities from current that existed before current run started
    baseline_entity_map: dict[tuple[str, str], Entity] = {
        (e.entity_type, e.canonical_identifier): e
        for e in baseline_entities_exclusive
    }
    for e in current_entities:
        key = (e.entity_type, e.canonical_identifier)
        if e.first_observed_at < current_run.started_at and key not in baseline_entity_map:
            baseline_entity_map[key] = e

    # 3. Build EntitySnapshot lists for the pure delta engine
    def _to_snapshot(entity: Entity) -> EntitySnapshot:
        lead_score = (entity.properties or {}).get("_lead_score", 0)
        return EntitySnapshot(
            entity_id=entity.id,
            canonical_identifier=entity.canonical_identifier,
            entity_type=entity.entity_type,
            attribution_status=entity.attribution_status,
            attribution_confidence=float(entity.attribution_confidence),
            properties=entity.properties or {},
        )

    baseline_snapshots = [_to_snapshot(e) for e in baseline_entity_map.values()]
    current_snapshots = [_to_snapshot(e) for e in current_entities]

    # 4. Compute delta
    delta = compute_delta(baseline_snapshots, current_snapshots)

    # 5. Transform to API response model
    new_entities: list[EntityDelta] = []
    for snap in delta.added:
        score = snap.properties.get("_lead_score")
        new_entities.append(
            EntityDelta(
                entity_identifier=snap.canonical_identifier,
                entity_type=snap.entity_type,
                change_type="new",
                current_score=int(score) if score is not None else None,
                details=f"First observed in run {run_id}",
            )
        )

    removed_entities: list[EntityDelta] = []
    for snap in delta.removed:
        score = snap.properties.get("_lead_score")
        removed_entities.append(
            EntityDelta(
                entity_identifier=snap.canonical_identifier,
                entity_type=snap.entity_type,
                change_type="removed",
                previous_score=int(score) if score is not None else None,
                details=f"Not observed in run {run_id}",
            )
        )

    score_changes: list[EntityDelta] = []
    for changed in delta.changed:
        # Check for score changes in properties
        prop_changes = [c for c in changed.changes if c.field == "properties"]
        old_score = None
        new_score = None
        if prop_changes:
            old_props = prop_changes[0].old_value or {}
            new_props = prop_changes[0].new_value or {}
            old_score = old_props.get("_lead_score")
            new_score = new_props.get("_lead_score")

        # Also check for attribution changes
        attr_changes = [c for c in changed.changes if c.field == "attribution_status"]
        conf_changes = [c for c in changed.changes if c.field == "attribution_confidence"]

        change_details: list[str] = []
        change_type = "properties_changed"

        if old_score is not None and new_score is not None and old_score != new_score:
            change_type = "score_changed"
            change_details.append(
                f"Score: {old_score} -> {new_score}"
            )

        if attr_changes:
            change_details.append(
                f"Attribution: {attr_changes[0].old_value} -> {attr_changes[0].new_value}"
            )

        if conf_changes:
            change_details.append(
                f"Confidence: {conf_changes[0].old_value} -> {conf_changes[0].new_value}"
            )

        if not change_details:
            change_details.append("Properties changed")

        prev_s = int(old_score) if old_score is not None else None
        curr_s = int(new_score) if new_score is not None else None
        s_delta = (curr_s - prev_s) if curr_s is not None and prev_s is not None else None

        score_changes.append(
            EntityDelta(
                entity_identifier=changed.canonical_identifier,
                entity_type=changed.entity_type,
                change_type=change_type,
                previous_score=prev_s,
                current_score=curr_s,
                score_delta=s_delta,
                details="; ".join(change_details),
            )
        )

    # 6. Build summary
    parts: list[str] = []
    if new_entities:
        parts.append(f"{len(new_entities)} new asset{'s' if len(new_entities) != 1 else ''}")
    if removed_entities:
        parts.append(f"{len(removed_entities)} removed")
    if score_changes:
        parts.append(f"{len(score_changes)} score change{'s' if len(score_changes) != 1 else ''}")
    summary = ", ".join(parts) if parts else "No changes detected"

    return ScanDeltaResponse(
        tenant_id=str(tenant_id),
        current_run_id=str(run_id),
        baseline_run_id=str(baseline_run_id),
        new_entities=new_entities,
        removed_entities=removed_entities,
        score_changes=score_changes,
        summary=summary,
    )


@router.get("/tenants/{tenant_id}/entities", response_model=EntityList)
async def list_entities(
    tenant_id: UUID,
    session: SessionDep,
) -> EntityList:
    """List all entities discovered for a tenant."""
    from expose.services.run_service import RunService  # noqa: PLC0415

    service = RunService(session)
    return await service.list_entities(tenant_id)


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
    from expose.services.run_service import RunService  # noqa: PLC0415

    service = RunService(session)
    result = await service.get_entity(tenant_id, entity_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    return result
