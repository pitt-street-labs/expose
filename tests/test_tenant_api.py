"""Tests for the tenant lifecycle API (issue #23).

Uses an in-memory SQLite database via ``aiosqlite`` for speed — no Docker or
testcontainers required.  The FastAPI ``get_session`` dependency is overridden
to inject a test ``AsyncSession``.

Covers:
 1. Create tenant → 201
 2. Get tenant → 200
 3. Get nonexistent tenant → 404
 4. List tenants → returns all
 5. Update name → 200
 6. Suspend tenant → state changes to suspended
 7. Resume suspended tenant → state changes to active
 8. Delete tenant → 204, state becomes pending_deletion
 9. Invalid state transition (active → pending_deletion via PATCH) → 422
10. Create with empty name → 422
11. Update tenant that is pending_deletion → 422
12. Delete nonexistent tenant → 404
"""

from __future__ import annotations

from collections.abc import AsyncIterator
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

from expose.api.tenants import get_session, router
from expose.db.models import Base

# SQLite does not support ``NOW()`` — intercept DDL and swap the server_default
# to a no-op for columns that use it.  We handle this by providing values
# explicitly at insert time in the API layer (``datetime.now(UTC)``).


def _make_app() -> Any:
    """Construct a minimal FastAPI app with the tenants router."""
    from fastapi import FastAPI  # noqa: PLC0415

    app = FastAPI()
    app.include_router(router)
    return app


@pytest_asyncio.fixture
async def async_engine() -> AsyncIterator[AsyncEngine]:
    """Per-test in-memory SQLite engine with fresh schema."""
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)

    # SQLite needs ``NOW()`` replaced — listen for DDL and patch.
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
            # Detect Postgres-specific server_defaults by inspecting the text
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
    """HTTPX async client wired to the FastAPI app with dependency overrides."""
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

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# === 1. Create tenant → 201, returns id + name + state=active =============


async def test_create_tenant(client: AsyncClient) -> None:
    resp = await client.post("/v1/tenants/", json={"name": "acme-corp"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "acme-corp"
    assert data["state"] == "active"
    # id is a valid UUID
    UUID(data["id"])
    assert "created_at" in data


# === 2. Get tenant → 200 ==================================================


async def test_get_tenant(client: AsyncClient) -> None:
    create_resp = await client.post("/v1/tenants/", json={"name": "get-me"})
    tenant_id = create_resp.json()["id"]

    resp = await client.get(f"/v1/tenants/{tenant_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == tenant_id
    assert resp.json()["name"] == "get-me"


# === 3. Get nonexistent → 404 =============================================


async def test_get_nonexistent_tenant(client: AsyncClient) -> None:
    fake_id = str(uuid4())
    resp = await client.get(f"/v1/tenants/{fake_id}")
    assert resp.status_code == 404


# === 4. List tenants → returns all ========================================


async def test_list_tenants(client: AsyncClient) -> None:
    await client.post("/v1/tenants/", json={"name": "tenant-a"})
    await client.post("/v1/tenants/", json={"name": "tenant-b"})

    resp = await client.get("/v1/tenants/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 2
    names = {t["name"] for t in data["tenants"]}
    assert "tenant-a" in names
    assert "tenant-b" in names


# === 5. Update name → 200 =================================================


async def test_update_tenant_name(client: AsyncClient) -> None:
    create_resp = await client.post("/v1/tenants/", json={"name": "old-name"})
    tenant_id = create_resp.json()["id"]

    resp = await client.patch(f"/v1/tenants/{tenant_id}", json={"name": "new-name"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "new-name"


# === 6. Suspend tenant → state changes to suspended =======================


async def test_suspend_tenant(client: AsyncClient) -> None:
    create_resp = await client.post("/v1/tenants/", json={"name": "suspendable"})
    tenant_id = create_resp.json()["id"]

    resp = await client.patch(f"/v1/tenants/{tenant_id}", json={"state": "suspended"})
    assert resp.status_code == 200
    assert resp.json()["state"] == "suspended"


# === 7. Resume suspended tenant → state changes to active =================


async def test_resume_suspended_tenant(client: AsyncClient) -> None:
    create_resp = await client.post("/v1/tenants/", json={"name": "resumable"})
    tenant_id = create_resp.json()["id"]

    # Suspend first
    await client.patch(f"/v1/tenants/{tenant_id}", json={"state": "suspended"})

    # Resume
    resp = await client.patch(f"/v1/tenants/{tenant_id}", json={"state": "active"})
    assert resp.status_code == 200
    assert resp.json()["state"] == "active"


# === 8. Delete tenant → 204, state becomes pending_deletion ===============


async def test_delete_tenant(client: AsyncClient) -> None:
    create_resp = await client.post("/v1/tenants/", json={"name": "deletable"})
    tenant_id = create_resp.json()["id"]

    resp = await client.delete(f"/v1/tenants/{tenant_id}")
    assert resp.status_code == 204

    # Verify state changed to pending_deletion
    get_resp = await client.get(f"/v1/tenants/{tenant_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["state"] == "pending_deletion"


# === 9. Invalid state transition → 422 ====================================


async def test_invalid_state_transition(client: AsyncClient) -> None:
    create_resp = await client.post("/v1/tenants/", json={"name": "no-direct-delete"})
    tenant_id = create_resp.json()["id"]

    resp = await client.patch(f"/v1/tenants/{tenant_id}", json={"state": "pending_deletion"})
    assert resp.status_code == 422


# === 10. Create with empty name → 422 =====================================


async def test_create_empty_name(client: AsyncClient) -> None:
    resp = await client.post("/v1/tenants/", json={"name": ""})
    assert resp.status_code == 422


# === 11. Update tenant in pending_deletion state → 422 ====================


async def test_update_pending_deletion_tenant(client: AsyncClient) -> None:
    create_resp = await client.post("/v1/tenants/", json={"name": "already-deleted"})
    tenant_id = create_resp.json()["id"]

    # Delete first
    await client.delete(f"/v1/tenants/{tenant_id}")

    # Try to resume — should fail
    resp = await client.patch(f"/v1/tenants/{tenant_id}", json={"state": "active"})
    assert resp.status_code == 422


# === 12. Delete nonexistent tenant → 404 ==================================


async def test_delete_nonexistent_tenant(client: AsyncClient) -> None:
    fake_id = str(uuid4())
    resp = await client.delete(f"/v1/tenants/{fake_id}")
    assert resp.status_code == 404
