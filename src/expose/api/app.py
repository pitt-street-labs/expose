"""FastAPI application factory for the EXPOSE API.

Wires the tenant lifecycle router (and future resource routers) into a
runnable HTTP application with async-DB lifespan management, CORS, and
an unauthenticated health endpoint.
"""

from __future__ import annotations

import asyncio
import logging
import weakref
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

from fastapi import FastAPI

_app_weak_ref: weakref.ref[FastAPI] | None = None


def _set_app_ref(app: FastAPI) -> None:
    global _app_weak_ref  # noqa: PLW0603
    _app_weak_ref = weakref.ref(app)


def _app_ref() -> FastAPI | None:
    if _app_weak_ref is None:
        return None
    return _app_weak_ref()
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from expose import __version__
from expose.api.admin import router as admin_router
from expose.api.credentials import router as credentials_router
from expose.api.events import router as events_router
from expose.api.export import router as export_router
from expose.api.findings import router as findings_router
from expose.api.graph import router as graph_router
from expose.api.rbac import router as rbac_router
from expose.api.run_log import router as run_log_router
from expose.api.runs import router as runs_router
from expose.api.tenant_config import router as tenant_config_router
from expose.api.tenants import get_session
from expose.api.tenants import router as tenant_router
from expose.api.scheduler import router as scheduler_router
from expose.api.provenance import router as provenance_router
from expose.api.webhooks import router as webhooks_router
from expose.db.engine import (
    DatabaseSettings,
    create_async_engine_from_settings,
    create_session_factory,
)
from expose.ui.router import mount_static
from expose.ui.router import router as ui_router


logger = logging.getLogger(__name__)

# Maximum concurrent runs per tenant enforced by the scheduler trigger.
_MAX_CONCURRENT_RUNS_PER_TENANT = 1


async def _scheduler_run_trigger(
    tenant_id: UUID,
    collector_ids: list[str],
    seeds: list[dict],
) -> None:
    """Callback invoked by ``RunScheduler`` when a schedule fires.

    Checks for existing active runs before starting a new one to enforce the
    per-tenant concurrent run limit.  Delegates to the existing run-start
    logic from :mod:`expose.api.runs`.
    """
    from expose.api.runs import _run_pipeline_background  # noqa: PLC0415
    from expose.collectors.base import Seed, SeedType  # noqa: PLC0415
    from expose.db.models import Run  # noqa: PLC0415

    from sqlalchemy import select  # noqa: PLC0415

    app = _app_ref()
    if app is None:
        logger.warning("Scheduler trigger fired but app reference is gone")
        return

    session_factory = getattr(app.state, "session_factory", None)
    if session_factory is None:
        logger.warning("Scheduler trigger fired but no session_factory available")
        return

    # -- Concurrent run limit: check for active runs for this tenant ----------
    async with session_factory() as session:
        stmt = select(Run).where(
            Run.tenant_id == tenant_id,
            Run.state.in_(["pending", "running"]),
        )
        result = await session.execute(stmt)
        active_runs = list(result.scalars().all())

    if len(active_runs) >= _MAX_CONCURRENT_RUNS_PER_TENANT:
        logger.info(
            "Scheduler skipping trigger for tenant %s: %d active run(s) "
            "(limit %d)",
            tenant_id,
            len(active_runs),
            _MAX_CONCURRENT_RUNS_PER_TENANT,
        )
        return

    # -- Build seeds and start the run ----------------------------------------
    from datetime import UTC, datetime as _datetime  # noqa: PLC0415
    from uuid import uuid4 as _uuid4  # noqa: PLC0415

    from expose import __version__  # noqa: PLC0415

    seed_objects: list[Seed] = []
    for raw_seed in seeds:
        value = raw_seed.get("value", "")
        seed_type_str = raw_seed.get("seed_type", "DOMAIN")
        try:
            st = SeedType(seed_type_str)
        except ValueError:
            st = SeedType.DOMAIN
        seed_objects.append(Seed(seed_type=st, value=value))

    run_id = _uuid4()

    # Insert the Run row.
    async with session_factory() as session:
        run = Run(
            id=run_id,
            tenant_id=tenant_id,
            pipeline_version=__version__,
            state="pending",
            started_at=_datetime.now(UTC),
        )
        session.add(run)
        await session.commit()

    # Fire the background pipeline.
    from expose.api.events import get_event_bus  # noqa: PLC0415
    from expose.api.events import RunEventBus  # noqa: PLC0415

    event_bus: RunEventBus | None = None
    if hasattr(app.state, "event_bus"):
        event_bus = get_event_bus(app)

    bg_tasks: dict[str, asyncio.Task[None]] = app.state._bg_tasks
    task = asyncio.create_task(
        _run_pipeline_background(
            run_id=run_id,
            tenant_id=tenant_id,
            seeds=seed_objects,
            collector_ids=collector_ids,
            session_factory=session_factory,
            event_bus=event_bus,
        )
    )
    task_key = str(run_id)
    bg_tasks[task_key] = task
    task.add_done_callback(lambda _t: bg_tasks.pop(task_key, None))

    logger.info(
        "Scheduler triggered run %s for tenant %s",
        run_id,
        tenant_id,
    )


def _make_session_dependency(
    factory: async_sessionmaker[AsyncSession],
) -> Any:
    """Build a ``get_session`` override that yields from *factory*.

    Returns an async-generator callable suitable for
    ``app.dependency_overrides[get_session]``.
    """

    async def _get_session() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    return _get_session


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage the async engine across the application lifecycle.

    On startup the engine and session factory are created from
    ``DatabaseSettings`` (env-driven per ADR-003). On shutdown the engine
    is disposed so connection pools are drained cleanly.
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    settings: DatabaseSettings = app.state.db_settings
    engine: AsyncEngine = create_async_engine_from_settings(settings)
    factory = create_session_factory(engine)

    app.state.session_factory = factory
    app.state.server_started_at = datetime.now(UTC)
    app.state._bg_tasks: dict[str, asyncio.Task[None]] = {}
    app.dependency_overrides[get_session] = _make_session_dependency(factory)

    _set_app_ref(app)

    from expose.api.tenant_config import load_configs_from_db  # noqa: PLC0415
    await load_configs_from_db()

    # -- Run scheduler (Wave 2) -----------------------------------------------
    from expose.pipeline.scheduler import RunScheduler  # noqa: PLC0415

    scheduler = RunScheduler(on_run_trigger=_scheduler_run_trigger)
    app.state.run_scheduler = scheduler

    scheduler_shutdown = asyncio.Event()
    app.state._scheduler_shutdown = scheduler_shutdown

    scheduler_task = asyncio.create_task(scheduler.run(scheduler_shutdown))
    app.state._scheduler_task = scheduler_task

    yield

    # -- Shutdown scheduler ----------------------------------------------------
    scheduler_shutdown.set()
    try:
        await asyncio.wait_for(scheduler_task, timeout=10.0)
    except (TimeoutError, asyncio.CancelledError):
        scheduler_task.cancel()
        logger.warning("Scheduler task did not stop cleanly within timeout")

    # -- Cancel and drain background pipeline tasks ----------------------------
    bg_tasks: dict[str, asyncio.Task[None]] = app.state._bg_tasks
    if bg_tasks:
        logger.info("Shutting down %d background task(s)...", len(bg_tasks))
        # Snapshot values — done callbacks may mutate the dict during iteration.
        pending = list(bg_tasks.values())
        # Grace period: wait up to 10s for tasks to finish naturally.
        _done, still_running = await asyncio.wait(
            pending, timeout=10.0, return_when=asyncio.ALL_COMPLETED,
        )
        for task in still_running:
            task.cancel()
        if still_running:
            await asyncio.gather(*still_running, return_exceptions=True)
            logger.warning(
                "Force-cancelled %d background task(s) that did not finish "
                "within the 10s grace period",
                len(still_running),
            )
        bg_tasks.clear()

    await engine.dispose()


def create_app(
    db_settings: DatabaseSettings | None = None,
    enable_otel: bool = True,
    cors_origins: list[str] | None = None,
) -> FastAPI:
    """Build the FastAPI application with all routers and middleware.

    Args:
        db_settings: Database connection settings. When ``None`` the lifespan
            reads from ``EXPOSE_DB_*`` environment variables (the production
            path per ADR-003).
        enable_otel: Pass ``False`` to skip OpenTelemetry setup (useful for
            local development and tests).
        cors_origins: Allowed CORS origins. Defaults to ``["*"]`` for
            development; production should restrict this.
    """
    if db_settings is None:
        db_settings = DatabaseSettings()

    app = FastAPI(
        title="EXPOSE API",
        version=__version__,
        lifespan=_lifespan,
    )

    # Stash settings so the lifespan can read them.
    app.state.db_settings = db_settings

    # -- Observability ---------------------------------------------------------
    if enable_otel:
        from expose.observability import setup_observability  # noqa: PLC0415

        setup_observability(service_name="expose-api")

    # -- CORS ------------------------------------------------------------------
    origins = cors_origins if cors_origins is not None else ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -- Routers ---------------------------------------------------------------
    app.include_router(admin_router)
    app.include_router(tenant_router)
    app.include_router(runs_router)
    app.include_router(run_log_router)
    app.include_router(graph_router)
    app.include_router(events_router)
    app.include_router(tenant_config_router)
    app.include_router(credentials_router)
    app.include_router(export_router)
    app.include_router(findings_router)
    app.include_router(rbac_router)
    app.include_router(webhooks_router)

    # -- Wave 2: Scheduler router (issue #99) ----------------------------------
    app.include_router(scheduler_router)
    # -- END Wave 2 scheduler --------------------------------------------------
    app.include_router(provenance_router)

    app.include_router(ui_router)

    # -- Static files (CSS, JS for dashboard) ----------------------------------
    mount_static(app)

    # -- Health ----------------------------------------------------------------
    @app.get("/healthz", tags=["health"])
    async def healthz() -> dict[str, str]:
        """Liveness probe -- no DB dependency."""
        return {"status": "ok"}

    return app
