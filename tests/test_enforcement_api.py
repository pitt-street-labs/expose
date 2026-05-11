"""Tests for the enforcement refusal audit trail API (issue #100).

Covers:
 1. Enforcement endpoint returns empty list for run with no refusals
 2. Enforcement endpoint returns stored refusals
 3. Enforcement endpoint returns 404 for nonexistent run
 4. Enforcement endpoint returns 404 for wrong tenant (cross-tenant)
 5. RunResponse includes enforcement_refusal_count when refusals present
 6. RunResponse has null enforcement_refusal_count when no refusals stored
 7. Refusals are persisted after run (unit test for storage logic)
"""

from __future__ import annotations

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

from expose.api.enforcement import router as enforcement_router
from expose.api.runs import router as runs_router
from expose.api.tenants import get_session
from expose.api.tenants import router as tenants_router
from expose.db.models import Base, Run, Tenant


def _make_app() -> Any:
    """Construct a minimal FastAPI app with tenants + runs + enforcement."""
    from fastapi import FastAPI  # noqa: PLC0415

    app = FastAPI()
    app.include_router(tenants_router)
    app.include_router(runs_router)
    app.include_router(enforcement_router)
    return app


def _create_tables(connection: Any) -> None:
    """Create all tables, stripping Postgres-only server_defaults for SQLite."""
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


async def _seed_run(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: UUID,
    state: str = "completed",
    run_metadata: dict[str, Any] | None = None,
) -> UUID:
    """Insert a run row and return its id."""
    rid = uuid4()
    async with session_factory() as session:
        run = Run(
            id=rid,
            tenant_id=tenant_id,
            pipeline_version="1.0.0",
            state=state,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC) if state == "completed" else None,
            target_count=None,
            run_metadata=run_metadata or {},
        )
        session.add(run)
        await session.commit()
    return rid


def _make_refusal_data(
    tenant_id: UUID,
    entity_identifier: str = "unknown.example.com",
    collector_id: str = "tls-prober",
    reason: str = "Entity not in authorization scope",
) -> dict[str, Any]:
    """Build a single refusal dict matching ScopeRefusalEvent.model_dump(mode='json')."""
    return {
        "tenant_id": str(tenant_id),
        "entity_identifier": entity_identifier,
        "attribution_tier": None,
        "enforcement_mode": "hard",
        "collector_id": collector_id,
        "reason": reason,
        "timestamp": datetime.now(UTC).isoformat(),
    }


# === 1. Enforcement endpoint returns empty list for run with no refusals ====


async def test_enforcement_empty_refusals(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Run with no enforcement refusals returns an empty list."""
    tid = await _seed_tenant(session_factory, "enforcement-empty-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid)

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/enforcement")
    assert resp.status_code == 200
    data = resp.json()
    assert data["refusals"] == []
    assert data["total"] == 0


# === 2. Enforcement endpoint returns stored refusals ========================


async def test_enforcement_returns_refusals(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Run with stored refusals returns them correctly."""
    tid = await _seed_tenant(session_factory, "enforcement-refusals-tenant")

    refusals = [
        _make_refusal_data(tid, "rogue1.example.com", "tls-prober"),
        _make_refusal_data(tid, "rogue2.example.com", "dns-brute"),
    ]
    rid = await _seed_run(
        session_factory,
        tenant_id=tid,
        run_metadata={"enforcement_refusals": refusals},
    )

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/enforcement")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["refusals"]) == 2

    identifiers = {r["entity_identifier"] for r in data["refusals"]}
    assert identifiers == {"rogue1.example.com", "rogue2.example.com"}

    # Verify structure of each refusal
    for r in data["refusals"]:
        assert "tenant_id" in r
        assert "entity_identifier" in r
        assert "collector_id" in r
        assert "reason" in r
        assert "timestamp" in r
        assert "enforcement_mode" in r


# === 3. Enforcement endpoint returns 404 for nonexistent run ================


async def test_enforcement_nonexistent_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Requesting enforcement for a nonexistent run returns 404."""
    tid = await _seed_tenant(session_factory, "enforcement-404-tenant")
    fake_rid = uuid4()
    resp = await client.get(f"/v1/tenants/{tid}/runs/{fake_rid}/enforcement")
    assert resp.status_code == 404


# === 4. Enforcement endpoint cross-tenant returns 404 ======================


async def test_enforcement_cross_tenant(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Requesting another tenant's run enforcement returns 404."""
    tid_a = await _seed_tenant(session_factory, "enforcement-cross-a")
    tid_b = await _seed_tenant(session_factory, "enforcement-cross-b")

    refusals = [_make_refusal_data(tid_a, "secret.example.com")]
    rid = await _seed_run(
        session_factory,
        tenant_id=tid_a,
        run_metadata={"enforcement_refusals": refusals},
    )

    # Tenant B tries to access tenant A's enforcement data
    resp = await client.get(f"/v1/tenants/{tid_b}/runs/{rid}/enforcement")
    assert resp.status_code == 404


# === 5. RunResponse includes enforcement_refusal_count ======================


async def test_run_response_includes_refusal_count(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET /runs/{run_id} includes enforcement_refusal_count when refusals present."""
    tid = await _seed_tenant(session_factory, "refusal-count-tenant")
    refusals = [
        _make_refusal_data(tid, "a.example.com"),
        _make_refusal_data(tid, "b.example.com"),
        _make_refusal_data(tid, "c.example.com"),
    ]
    rid = await _seed_run(
        session_factory,
        tenant_id=tid,
        run_metadata={"enforcement_refusals": refusals},
    )

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enforcement_refusal_count"] == 3


# === 6. RunResponse has null refusal count when no refusals =================


async def test_run_response_null_refusal_count(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET /runs/{run_id} has null enforcement_refusal_count when no refusals stored."""
    tid = await _seed_tenant(session_factory, "null-refusal-count-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid)

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enforcement_refusal_count"] is None


# === 7. Refusal count is zero (not null) when run has empty refusals list ===


async def test_run_response_zero_refusal_count(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """GET /runs/{run_id} has 0 enforcement_refusal_count when refusals list is empty."""
    tid = await _seed_tenant(session_factory, "zero-refusal-count-tenant")
    rid = await _seed_run(
        session_factory,
        tenant_id=tid,
        run_metadata={"enforcement_refusals": []},
    )

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enforcement_refusal_count"] == 0
