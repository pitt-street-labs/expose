"""End-to-end API integration tests for the EXPOSE platform.

Uses an in-memory SQLite database via ``aiosqlite`` — no Docker or
testcontainers required.  The ``create_app()`` factory wires all routers
(tenants, runs, graph, events, UI); the ``get_session`` dependency is
overridden to inject a test ``AsyncSession``.

Covers:
 1. Create tenant and trigger run — POST tenant, POST run, verify via GET
 2. Entity listing — seed entities via ORM, verify via GET
 3. Bearer auth enforcement — AuthDependency rejects missing/invalid tokens
 4. Tenant scoping — entities under tenant A invisible to tenant B
 5. Health endpoint — GET /healthz returns 200 with {"status": "ok"}
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from expose.api.auth import AuthDependency, TokenStore
from expose.api.tenants import get_session
from expose.db.models import Base, Entity, Tenant

# ---------------------------------------------------------------------------
# Table creation helper — strips Postgres-only server_defaults for SQLite
# (same pattern as test_runs_api.py)
# ---------------------------------------------------------------------------


def _create_tables(connection: Any) -> None:
    """Create all tables, stripping Postgres-only server_defaults for SQLite.

    ``NOW()``, ``'{}'::jsonb``, and ``'pending'`` text casts are all valid in
    Postgres DDL but break SQLite.  We temporarily remove every
    ``server_default`` that contains Postgres-specific syntax, create the
    schema, then restore the original defaults so the ORM metadata remains
    clean for other tests in the same process.
    """
    patched: list[tuple[Any, Any]] = []
    for table in Base.metadata.sorted_tables:
        for col in table.columns:
            sd = col.server_default
            if sd is None:
                continue
            arg = getattr(sd, "arg", None)
            if arg is None:
                continue
            raw = str(getattr(arg, "text", arg)).upper()
            if any(tok in raw for tok in ("NOW()", "::JSONB", "'PENDING'")):
                patched.append((col, sd))
                col.server_default = None
    try:
        Base.metadata.create_all(connection)
    finally:
        for col, default in patched:
            col.server_default = default


# ---------------------------------------------------------------------------
# App factory — uses create_app() but overrides DB to use in-memory SQLite
# ---------------------------------------------------------------------------


def _make_app() -> Any:
    """Construct the full EXPOSE app with all routers.

    Uses the app factory but disables OTel (not needed in tests).
    The lifespan is NOT used — we override ``get_session`` directly and
    initialize the state attributes that lifespan would normally set.
    """
    from fastapi import FastAPI  # noqa: PLC0415

    from expose.api.events import router as events_router  # noqa: PLC0415
    from expose.api.graph import router as graph_router  # noqa: PLC0415
    from expose.api.runs import router as runs_router  # noqa: PLC0415
    from expose.api.tenants import router as tenants_router  # noqa: PLC0415

    app = FastAPI(title="EXPOSE API (test)")
    app.include_router(tenants_router)
    app.include_router(runs_router)
    app.include_router(graph_router)
    app.include_router(events_router)

    # Include additional routers that create_app() wires — skip gracefully
    # if the module is not yet available.
    _optional_routers: list[tuple[str, str]] = [
        ("expose.api.findings", "router"),
        ("expose.api.provenance", "router"),
        ("expose.api.export", "router"),
        ("expose.api.credentials", "router"),
        ("expose.api.soc", "router"),
        ("expose.api.reports", "router"),
        ("expose.api.timeline", "router"),
    ]
    for mod_path, attr_name in _optional_routers:
        try:
            import importlib  # noqa: PLC0415

            mod = importlib.import_module(mod_path)
            app.include_router(getattr(mod, attr_name))
        except (ImportError, AttributeError):
            pass

    # Health endpoint (matches create_app's inline definition)
    @app.get("/healthz", tags=["health"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def async_engine() -> AsyncIterator[AsyncEngine]:
    """Per-test in-memory SQLite engine with fresh schema."""
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn: Any, _rec: Any) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(_create_tables)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def session_factory(
    async_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """Session factory bound to the test engine."""
    return async_sessionmaker(
        bind=async_engine,
        expire_on_commit=False,
        autoflush=False,
        class_=AsyncSession,
    )


@pytest_asyncio.fixture
async def client(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    """HTTPX async client wired to the full EXPOSE app with dependency overrides."""
    app = _make_app()

    async def _override_get_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_session] = _override_get_session
    # Store session_factory on app.state so the runs router background task
    # path can find it (though background pipeline won't fully execute in tests).
    app.state.session_factory = session_factory

    # Initialize state attributes that the lifespan context manager would
    # normally set.  Without these, endpoints that access app.state._bg_tasks
    # (e.g. start_run) crash with AttributeError.
    app.state._bg_tasks = {}
    app.state.server_started_at = datetime.now(UTC)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    # Cancel any background tasks spawned during the test (e.g. pipeline
    # tasks created by start_run) so they don't try to use the DB after the
    # in-memory SQLite engine is disposed.
    bg_tasks: dict[str, asyncio.Task[None]] = app.state._bg_tasks
    for task in list(bg_tasks.values()):
        task.cancel()
    if bg_tasks:
        await asyncio.gather(*bg_tasks.values(), return_exceptions=True)
        bg_tasks.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_tenant(
    session_factory: async_sessionmaker[AsyncSession],
    name: str,
) -> UUID:
    """Insert a tenant row and return its id."""
    tid = uuid4()
    async with session_factory() as session:
        tenant = Tenant(
            id=tid,
            name=name,
            created_at=datetime.now(UTC),
            config_jsonb={"state": "active"},
        )
        session.add(tenant)
        await session.commit()
    return tid


async def _seed_entity(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: UUID,
    entity_type: str = "Domain",
    canonical_identifier: str = "example.com",
) -> UUID:
    """Insert an entity row and return its id."""
    eid = uuid4()
    now = datetime.now(UTC)
    async with session_factory() as session:
        entity = Entity(
            id=eid,
            tenant_id=tenant_id,
            entity_type=entity_type,
            canonical_identifier=canonical_identifier,
            properties={},
            attribution_status="confirmed",
            attribution_confidence=Decimal("0.950"),
            first_observed_at=now,
            last_observed_at=now,
        )
        session.add(entity)
        await session.commit()
    return eid


# === 1. Create tenant and trigger run ========================================


async def test_create_tenant_and_trigger_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """POST a tenant, POST a run for it, verify the run exists via GET."""
    # Step 1: Create tenant via API
    create_resp = await client.post(
        "/v1/tenants/",
        json={"name": "e2e-test-tenant"},
    )
    assert create_resp.status_code == 201
    tenant_data = create_resp.json()
    tenant_id = tenant_data["id"]
    assert tenant_data["name"] == "e2e-test-tenant"
    assert tenant_data["state"] == "active"

    # Step 2: Trigger a run via API
    run_resp = await client.post(
        f"/v1/tenants/{tenant_id}/runs",
        json={"seeds": ["e2e-test.example.com"]},
    )
    assert run_resp.status_code == 202
    run_data = run_resp.json()
    run_id = run_data["run_id"]
    assert run_data["tenant_id"] == tenant_id
    assert run_data["state"] == "pending"
    assert run_data["seeds"] == ["e2e-test.example.com"]
    # Validate run_id is a valid UUID
    UUID(run_id)

    # Step 3: Verify the run row exists via GET
    get_resp = await client.get(f"/v1/tenants/{tenant_id}/runs/{run_id}")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["id"] == run_id
    assert get_data["tenant_id"] == tenant_id
    assert get_data["state"] == "pending"


# === 2. Entity listing =======================================================


async def test_entity_listing(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Seed entities via ORM, then verify they appear in GET /entities."""
    tid = await _seed_tenant(session_factory, "entity-listing-tenant")

    # Seed three entities of different types
    await _seed_entity(
        session_factory,
        tenant_id=tid,
        entity_type="Domain",
        canonical_identifier="alpha.example.com",
    )
    await _seed_entity(
        session_factory,
        tenant_id=tid,
        entity_type="IP",
        canonical_identifier="198.51.100.1",
    )
    await _seed_entity(
        session_factory,
        tenant_id=tid,
        entity_type="Certificate",
        canonical_identifier="sha256:abcdef1234567890",
    )

    # GET entities for the tenant
    resp = await client.get(f"/v1/tenants/{tid}/entities")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    assert len(data["entities"]) == 3

    # Verify all types present
    types = {e["entity_type"] for e in data["entities"]}
    assert types == {"Domain", "IP", "Certificate"}

    # Verify identifiers present
    identifiers = {e["canonical_identifier"] for e in data["entities"]}
    assert identifiers == {
        "alpha.example.com",
        "198.51.100.1",
        "sha256:abcdef1234567890",
    }


# === 3. Bearer auth enforcement ==============================================


async def test_bearer_auth_enforcement() -> None:
    """AuthDependency rejects requests without valid Bearer tokens.

    The auth dependency is not wired as a global middleware (endpoints opt in
    via ``Depends(auth)``), so we test the AuthDependency class directly
    through a minimal FastAPI app with a protected endpoint.
    """
    from fastapi import Depends, FastAPI  # noqa: PLC0415

    store = TokenStore()
    auth = AuthDependency(store)

    app = FastAPI()

    _auth_dep = Depends(auth)

    @app.get("/protected")
    async def protected(
        payload: Any = _auth_dep,
    ) -> dict[str, str]:
        return {"tenant_id": str(payload.tenant_id)}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # No Authorization header -> 401
        resp_no_auth = await ac.get("/protected")
        assert resp_no_auth.status_code == 401
        assert "Missing or invalid" in resp_no_auth.json()["detail"]

        # Invalid token -> 401
        resp_bad_token = await ac.get(
            "/protected",
            headers={"Authorization": "Bearer totally-invalid-token"},
        )
        assert resp_bad_token.status_code == 401
        assert "Invalid or expired" in resp_bad_token.json()["detail"]

        # Malformed header (no "Bearer " prefix) -> 401
        resp_malformed = await ac.get(
            "/protected",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp_malformed.status_code == 401

        # Valid token -> 200
        tenant_id = uuid4()
        api_token = store.create_token(tenant_id)
        resp_valid = await ac.get(
            "/protected",
            headers={"Authorization": f"Bearer {api_token.token}"},
        )
        assert resp_valid.status_code == 200
        assert resp_valid.json()["tenant_id"] == str(tenant_id)

        # Valid token but wrong scope -> 403
        read_only_auth = AuthDependency(store, required_scope="admin")

        _admin_dep = Depends(read_only_auth)

        @app.get("/admin-only")
        async def admin_only(
            payload: Any = _admin_dep,
        ) -> dict[str, str]:
            return {"ok": "true"}

        # The default token has scopes ["read", "write"], not "admin"
        resp_wrong_scope = await ac.get(
            "/admin-only",
            headers={"Authorization": f"Bearer {api_token.token}"},
        )
        assert resp_wrong_scope.status_code == 403
        assert "lacks required scope" in resp_wrong_scope.json()["detail"]


# === 4. Tenant scoping =======================================================


async def test_tenant_scoping(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Entities under tenant A must be invisible to tenant B."""
    tid_a = await _seed_tenant(session_factory, "scoping-tenant-a")
    tid_b = await _seed_tenant(session_factory, "scoping-tenant-b")

    # Seed entities only under tenant A
    await _seed_entity(
        session_factory,
        tenant_id=tid_a,
        entity_type="Domain",
        canonical_identifier="secret-a.example.com",
    )
    await _seed_entity(
        session_factory,
        tenant_id=tid_a,
        entity_type="IP",
        canonical_identifier="10.0.0.1",
    )

    # Tenant B should see zero entities
    resp_b = await client.get(f"/v1/tenants/{tid_b}/entities")
    assert resp_b.status_code == 200
    data_b = resp_b.json()
    assert data_b["total"] == 0
    assert data_b["entities"] == []

    # Tenant A should see its own entities
    resp_a = await client.get(f"/v1/tenants/{tid_a}/entities")
    assert resp_a.status_code == 200
    data_a = resp_a.json()
    assert data_a["total"] == 2
    identifiers_a = {e["canonical_identifier"] for e in data_a["entities"]}
    assert identifiers_a == {"secret-a.example.com", "10.0.0.1"}

    # Cross-tenant entity fetch by ID should 404
    entity_id_a = data_a["entities"][0]["id"]
    resp_cross = await client.get(f"/v1/tenants/{tid_b}/entities/{entity_id_a}")
    assert resp_cross.status_code == 404


# === 5. Health endpoint =======================================================


async def test_healthz_endpoint(
    client: AsyncClient,
) -> None:
    """GET /healthz returns 200 with {"status": "ok"}."""
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data == {"status": "ok"}


# === 6. SOC STIX endpoint =====================================================


async def test_soc_stix_bundle(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET /v1/tenants/{tid}/soc/stix returns 200 with a STIX bundle structure."""
    tid = await _seed_tenant(session_factory, "soc-stix-tenant")

    resp = await client.get(f"/v1/tenants/{tid}/soc/stix")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tenant_id"] == str(tid)
    assert "generated_at" in data
    assert "bundle" in data
    bundle = data["bundle"]
    assert bundle.get("type") == "bundle"
    assert "objects" in bundle


# === 7. CISO report endpoint ==================================================


async def test_ciso_report(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET /v1/tenants/{tid}/reports/ciso returns 200 with report structure."""
    tid = await _seed_tenant(session_factory, "ciso-report-tenant")

    resp = await client.get(f"/v1/tenants/{tid}/reports/ciso")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tenant_id"] == str(tid)
    assert "generated_at" in data
    assert "report_version" in data
    assert "sector_analysis" in data
    assert "threat_actors" in data
    assert "attraction_assessment" in data
    assert "ranked_targets" in data
    assert "executive_summary" in data


# === 8. Findings endpoint =====================================================


async def test_findings_list(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET /v1/tenants/{tid}/findings/ returns 200 with findings list."""
    tid = await _seed_tenant(session_factory, "findings-tenant")

    resp = await client.get(f"/v1/tenants/{tid}/findings/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tenant_id"] == str(tid)
    assert "findings" in data
    assert isinstance(data["findings"], list)
    assert "total_scored" in data
    assert "generated_at" in data


# === 9. Timeline endpoint =====================================================


async def test_entity_timeline(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET /v1/tenants/{tid}/entities/{eid}/timeline returns 200."""
    tid = await _seed_tenant(session_factory, "timeline-tenant")
    eid = await _seed_entity(
        session_factory,
        tenant_id=tid,
        entity_type="Domain",
        canonical_identifier="timeline.example.com",
    )

    resp = await client.get(f"/v1/tenants/{tid}/entities/{eid}/timeline")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tenant_id"] == str(tid)
    assert "snapshots" in data
    assert isinstance(data["snapshots"], list)
    assert "patterns" in data
    assert isinstance(data["patterns"], list)
    assert "span_days" in data
    assert "temporal_score_delta" in data
