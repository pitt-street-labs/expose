"""Tests for the FastAPI application factory (``expose.api.app``).

Validates:
 1. ``create_app()`` returns a FastAPI instance
 2. ``/healthz`` returns 200 + ``{"status": "ok"}``
 3. Tenant router is mounted (``/v1/tenants`` route exists in the app)
 4. App has title and version set correctly
 5. Health endpoint works without any database connection
 6. CORS middleware is installed with configurable origins
 7. OTel is skipped when ``enable_otel=False``

All tests use the app factory with ``enable_otel=False`` to avoid
polluting the test process with OTel instrumentation side-effects.
Database-dependent behaviour is tested by overriding the lifespan
entirely -- the health endpoint specifically must work with no DB.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from expose import __version__
from expose.api.app import create_app
from expose.db.engine import DatabaseSettings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _app_no_db(
    enable_otel: bool = False,
    cors_origins: list[str] | None = None,
) -> FastAPI:
    """Build an app whose lifespan skips DB engine creation.

    We replace the real lifespan with a no-op so tests don't need a
    Postgres connection.  The health endpoint and router mounting are
    unaffected because they happen inside ``create_app`` *before* the
    lifespan runs.
    """
    app = create_app(
        db_settings=DatabaseSettings(),
        enable_otel=enable_otel,
        cors_origins=cors_origins,
    )

    @asynccontextmanager
    async def _noop_lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield

    # Swap out the lifespan so no engine is created.
    app.router.lifespan_context = _noop_lifespan  # type: ignore[assignment]
    return app


async def _client(app: FastAPI) -> AsyncClient:
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


# ---------------------------------------------------------------------------
# 1. create_app returns a FastAPI instance
# ---------------------------------------------------------------------------


def test_create_app_returns_fastapi() -> None:
    app = _app_no_db()
    assert isinstance(app, FastAPI)


# ---------------------------------------------------------------------------
# 2. /healthz returns 200 + {"status": "ok"}
# ---------------------------------------------------------------------------


async def test_healthz_returns_ok() -> None:
    app = _app_no_db()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# 3. Tenant router is mounted
# ---------------------------------------------------------------------------


def test_tenant_router_mounted() -> None:
    app = _app_no_db()
    paths = {route.path for route in app.routes}
    assert "/v1/tenants/" in paths or "/v1/tenants/{tenant_id}" in paths


# ---------------------------------------------------------------------------
# 4. App has title and version
# ---------------------------------------------------------------------------


def test_app_title_and_version() -> None:
    app = _app_no_db()
    assert app.title == "EXPOSE API"
    assert app.version == __version__


# ---------------------------------------------------------------------------
# 5. Health endpoint works without DB connection
# ---------------------------------------------------------------------------


async def test_healthz_no_db_dependency() -> None:
    """The health endpoint must succeed even if no database lifespan ran."""
    app = _app_no_db()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# 6. CORS middleware is present and configurable
# ---------------------------------------------------------------------------


async def test_cors_allows_configured_origin() -> None:
    app = _app_no_db(cors_origins=["https://dashboard.example.com"])
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.options(
            "/healthz",
            headers={
                "origin": "https://dashboard.example.com",
                "access-control-request-method": "GET",
            },
        )
    assert resp.status_code == 200
    assert "access-control-allow-origin" in resp.headers


# ---------------------------------------------------------------------------
# 7. OTel is skipped when disabled
# ---------------------------------------------------------------------------


def test_otel_disabled_flag() -> None:
    """Smoke test: creating the app with enable_otel=False does not raise."""
    app = _app_no_db(enable_otel=False)
    assert isinstance(app, FastAPI)
