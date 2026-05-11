"""FastAPI application factory for the EXPOSE API.

Wires the tenant lifecycle router (and future resource routers) into a
runnable HTTP application with async-DB lifespan management, CORS, and
an unauthenticated health endpoint.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from expose import __version__
from expose.api.events import router as events_router
from expose.api.graph import router as graph_router
from expose.api.runs import router as runs_router
from expose.api.tenants import get_session
from expose.api.tenants import router as tenant_router
from expose.db.engine import (
    DatabaseSettings,
    create_async_engine_from_settings,
    create_session_factory,
)
from expose.ui.router import mount_static
from expose.ui.router import router as ui_router


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
    settings: DatabaseSettings = app.state.db_settings
    engine: AsyncEngine = create_async_engine_from_settings(settings)
    factory = create_session_factory(engine)

    app.state.session_factory = factory
    app.dependency_overrides[get_session] = _make_session_dependency(factory)

    yield

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
    app.include_router(tenant_router)
    app.include_router(runs_router)
    app.include_router(graph_router)
    app.include_router(events_router)
    app.include_router(ui_router)

    # -- Static files (CSS, JS for dashboard) ----------------------------------
    mount_static(app)

    # -- Health ----------------------------------------------------------------
    @app.get("/healthz", tags=["health"])
    async def healthz() -> dict[str, str]:
        """Liveness probe -- no DB dependency."""
        return {"status": "ok"}

    return app
