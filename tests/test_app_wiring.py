"""Tests for router wiring in the EXPOSE app factory.

Validates that all expected routers -- including the new ``tenant_config``
router added in Phase 1 -- are wired into the application and that key
route paths are reachable.

Complements ``test_app.py`` (factory basics, CORS, OTel) with focused
route-existence checks for every router.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from expose.api.app import create_app
from expose.db.engine import DatabaseSettings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _app_no_db() -> FastAPI:
    """Build an app whose lifespan skips DB engine creation.

    Mirrors the helper in ``test_app.py`` -- replaces the real lifespan
    with a no-op so tests don't need a Postgres connection.
    """
    app = create_app(
        db_settings=DatabaseSettings(),
        enable_otel=False,
    )

    @asynccontextmanager
    async def _noop_lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield

    app.router.lifespan_context = _noop_lifespan  # type: ignore[assignment]
    return app


def _route_paths(app: FastAPI) -> set[str]:
    """Return the set of all route paths registered on *app*."""
    return {route.path for route in app.routes if hasattr(route, "path")}


# ---------------------------------------------------------------------------
# 1. Tenant-config router is mounted
# ---------------------------------------------------------------------------


def test_tenant_config_router_mounted() -> None:
    """The tenant_config router must register its prefix path."""
    app = _app_no_db()
    paths = _route_paths(app)
    tenant_config_paths = [p for p in paths if "/config" in p]
    assert any(
        "/v1/tenants/{tenant_id}/config" in p for p in tenant_config_paths
    ), f"Expected tenant config route in {paths}"


# ---------------------------------------------------------------------------
# 2. All expected routers are wired
# ---------------------------------------------------------------------------


# Each tuple: (router name for reporting, substring that must appear in
# at least one route path).
_EXPECTED_ROUTER_FRAGMENTS = [
    ("tenants", "/v1/tenants"),
    ("runs", "/tenants/{tenant_id}/runs"),
    ("graph", "/tenants/{tenant_id}/graph"),
    ("events", "/tenants/{tenant_id}/runs/{run_id}/events"),
    ("tenant_config", "/v1/tenants/{tenant_id}/config"),
    ("global_credentials", "/v1/credentials/global"),
    ("ui", "/runs/{run_id}"),
]


@pytest.mark.parametrize(
    ("router_name", "fragment"),
    _EXPECTED_ROUTER_FRAGMENTS,
    ids=[name for name, _ in _EXPECTED_ROUTER_FRAGMENTS],
)
def test_router_present(router_name: str, fragment: str) -> None:
    """Every expected router must contribute at least one matching route."""
    app = _app_no_db()
    paths = _route_paths(app)
    assert any(
        fragment in p for p in paths
    ), f"Router '{router_name}' missing: no route contains '{fragment}' in {paths}"


# ---------------------------------------------------------------------------
# 3. healthz endpoint works
# ---------------------------------------------------------------------------


@pytest.mark.anyio
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
# 4. Tenant-config GET route is reachable (422, not 404)
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_tenant_config_get_reachable() -> None:
    """A GET to the tenant-config endpoint with a valid-shaped UUID must
    NOT return 404 (it will 422 or 500 without a DB, but that proves the
    route is mounted).
    """
    app = _app_no_db()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            "/v1/tenants/00000000-0000-0000-0000-000000000000/config/"
        )
    # Route exists => not 404; without DB we expect 500 or similar.
    assert resp.status_code != 404, "tenant_config route returned 404 -- not mounted"


# ---------------------------------------------------------------------------
# 5. Tenant-config PUT route is reachable
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_tenant_config_put_reachable() -> None:
    """PUT to the tenant-config endpoint must not 404 or 405."""
    app = _app_no_db()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.put(
            "/v1/tenants/00000000-0000-0000-0000-000000000000/config/",
            json={},
        )
    assert resp.status_code != 404, "tenant_config PUT route returned 404"
    assert resp.status_code != 405, "tenant_config PUT route returned 405"


# ---------------------------------------------------------------------------
# 6. Tenant-config PATCH route is reachable
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_tenant_config_patch_reachable() -> None:
    """PATCH to the tenant-config endpoint must not 404 or 405."""
    app = _app_no_db()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.patch(
            "/v1/tenants/00000000-0000-0000-0000-000000000000/config/",
            json={},
        )
    assert resp.status_code != 404, "tenant_config PATCH route returned 404"
    assert resp.status_code != 405, "tenant_config PATCH route returned 405"


# ---------------------------------------------------------------------------
# 7. Route count sanity -- app has a reasonable number of routes
# ---------------------------------------------------------------------------


def test_minimum_route_count() -> None:
    """The app should have at least 10 routes (health + all routers)."""
    app = _app_no_db()
    paths = _route_paths(app)
    assert len(paths) >= 10, f"Only {len(paths)} routes found: {paths}"


# ---------------------------------------------------------------------------
# 8. No duplicate route paths
# ---------------------------------------------------------------------------


def test_no_duplicate_routes() -> None:
    """Each (method, path) pair should appear at most once."""
    app = _app_no_db()
    seen: set[tuple[str, str]] = set()
    duplicates: list[tuple[str, str]] = []
    for route in app.routes:
        if not hasattr(route, "methods") or not hasattr(route, "path"):
            continue
        for method in route.methods:
            key = (method, route.path)
            if key in seen:
                duplicates.append(key)
            seen.add(key)
    assert not duplicates, f"Duplicate routes found: {duplicates}"
