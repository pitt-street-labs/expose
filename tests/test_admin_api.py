"""Tests for the admin API endpoints.

Uses an in-memory SQLite database via ``aiosqlite`` for speed -- no Docker or
testcontainers required.  The FastAPI ``get_session`` dependency is overridden
to inject a test ``AsyncSession``.

Covers:
 1. Cancel a pending run -> state becomes failed
 2. Cancel an already-completed run -> 409 Conflict
 3. Cancel a nonexistent run -> 404
 4. Delete a run -> 204
 5. Delete a nonexistent run -> 404
 6. System stats -> correct counts
 7. Bulk credential test -> returns array of results
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from expose.api.admin import router as admin_router
from expose.api.credentials import router as credentials_router
from expose.api.runs import router as runs_router
from expose.api.tenants import get_session
from expose.api.tenants import router as tenants_router
from expose.db.models import Base, Entity, Relationship, Run, Tenant


def _make_app() -> Any:
    """Construct a minimal FastAPI app with required routers."""
    from fastapi import FastAPI  # noqa: PLC0415

    app = FastAPI()
    app.include_router(admin_router)
    app.include_router(tenants_router)
    app.include_router(runs_router)
    app.include_router(credentials_router)
    # Set server_started_at for stats endpoint
    app.state.server_started_at = datetime.now(UTC)
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
    # Initialize background tasks dict on app state
    app.state._bg_tasks = {}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Helpers -- seed test data via ORM, not the API, for isolation
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
    state: str = "pending",
    run_id: UUID | None = None,
    completed_at: datetime | None = None,
) -> UUID:
    """Insert a run row and return its id."""
    rid = run_id or uuid4()
    async with session_factory() as session:
        run = Run(
            id=rid,
            tenant_id=tenant_id,
            pipeline_version="1.0.0",
            state=state,
            started_at=datetime.now(UTC),
            completed_at=completed_at,
            target_count=None,
        )
        session.add(run)
        await session.commit()
    return rid


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


async def _seed_relationship(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: UUID,
    from_entity_id: UUID,
    to_entity_id: UUID,
    edge_type: str = "resolves_to",
) -> UUID:
    """Insert a relationship row and return its id."""
    rid = uuid4()
    now = datetime.now(UTC)
    async with session_factory() as session:
        rel = Relationship(
            id=rid,
            tenant_id=tenant_id,
            from_entity_id=from_entity_id,
            to_entity_id=to_entity_id,
            edge_type=edge_type,
            confidence=Decimal("0.900"),
            observed_at=now,
            collector_id="test-collector",
            evidence_ref=None,
            properties={},
        )
        session.add(rel)
        await session.commit()
    return rid


# === 1. Cancel a pending run -> state becomes failed =========================


async def test_cancel_pending_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "cancel-pending-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid, state="pending")

    resp = await client.post(f"/v1/admin/runs/{rid}/cancel")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "cancelled"
    assert data["run_id"] == str(rid)

    # Verify run state in database via API
    # (The run should now be "failed" with a completed_at timestamp)
    # Re-read the run directly from the DB to confirm
    async with session_factory() as session:
        run = await session.get(Run, rid)
        assert run is not None
        assert run.state == "failed"
        assert run.completed_at is not None


# === 2. Cancel a running run with a background task ==========================


async def test_cancel_running_run_with_task(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Cancel a running run that has an associated asyncio.Task."""
    tid = await _seed_tenant(session_factory, "cancel-task-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid, state="running")

    # Simulate a background task stored on the app
    # The client fixture's transport gives access to the app via the transport
    app = client._transport.app  # type: ignore[union-attr]

    async def _fake_pipeline() -> None:
        await asyncio.sleep(3600)  # Block forever (until cancelled)

    task = asyncio.create_task(_fake_pipeline())
    app.state._bg_tasks[str(rid)] = task

    resp = await client.post(f"/v1/admin/runs/{rid}/cancel")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "cancelled"

    # The asyncio task should have been cancelled
    assert task.cancelled()

    # Task should be removed from _bg_tasks
    assert str(rid) not in app.state._bg_tasks


# === 3. Cancel an already-completed run -> 409 Conflict ======================


async def test_cancel_completed_run_conflict(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "cancel-completed-tenant")
    rid = await _seed_run(
        session_factory,
        tenant_id=tid,
        state="completed",
        completed_at=datetime.now(UTC),
    )

    resp = await client.post(f"/v1/admin/runs/{rid}/cancel")
    assert resp.status_code == 409
    data = resp.json()
    assert "terminal state" in data["detail"]


async def test_cancel_failed_run_conflict(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "cancel-failed-tenant")
    rid = await _seed_run(
        session_factory,
        tenant_id=tid,
        state="failed",
        completed_at=datetime.now(UTC),
    )

    resp = await client.post(f"/v1/admin/runs/{rid}/cancel")
    assert resp.status_code == 409


# === 4. Cancel nonexistent run -> 404 ========================================


async def test_cancel_nonexistent_run(
    client: AsyncClient,
) -> None:
    fake_id = uuid4()
    resp = await client.post(f"/v1/admin/runs/{fake_id}/cancel")
    assert resp.status_code == 404


# === 5. Delete a run -> 204 ==================================================


async def test_delete_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "delete-run-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid, state="completed")

    resp = await client.delete(f"/v1/admin/runs/{rid}")
    assert resp.status_code == 204

    # Verify it's gone from the database
    async with session_factory() as session:
        run = await session.get(Run, rid)
        assert run is None


async def test_delete_run_clears_logs(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Deleting a run also clears its in-memory log entries."""
    from expose.api.run_log import emit_log, get_run_log_entries  # noqa: PLC0415

    tid = await _seed_tenant(session_factory, "delete-run-logs-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid, state="completed")

    # Emit some log entries for the run
    emit_log(str(rid), "info", "Starting collection")
    emit_log(str(rid), "info", "Collection complete")
    entries, total = get_run_log_entries(str(rid))
    assert total == 2

    # Delete the run
    resp = await client.delete(f"/v1/admin/runs/{rid}")
    assert resp.status_code == 204

    # Log entries should be cleared
    entries, total = get_run_log_entries(str(rid))
    assert total == 0


# === 6. Delete nonexistent run -> 404 ========================================


async def test_delete_nonexistent_run(
    client: AsyncClient,
) -> None:
    fake_id = uuid4()
    resp = await client.delete(f"/v1/admin/runs/{fake_id}")
    assert resp.status_code == 404


# === 7. System stats -> correct counts =======================================


async def test_system_stats_empty(
    client: AsyncClient,
) -> None:
    """Stats on an empty database return all zeroes."""
    resp = await client.get("/v1/admin/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_entities"] == 0
    assert data["total_relationships"] == 0
    assert data["total_runs"] == 0
    assert data["runs_by_state"] == {}
    assert isinstance(data["registered_collectors"], int)
    assert data["registered_collectors"] > 0  # builtins are always registered
    assert data["server_started_at"] is not None


async def test_system_stats_with_data(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Stats reflect seeded data accurately."""
    tid = await _seed_tenant(session_factory, "stats-tenant")

    # Seed some entities
    eid1 = await _seed_entity(
        session_factory, tenant_id=tid, canonical_identifier="stats-a.example.com"
    )
    eid2 = await _seed_entity(
        session_factory,
        tenant_id=tid,
        entity_type="IP",
        canonical_identifier="10.0.0.1",
    )

    # Seed a relationship
    await _seed_relationship(
        session_factory,
        tenant_id=tid,
        from_entity_id=eid1,
        to_entity_id=eid2,
    )

    # Seed runs in various states
    await _seed_run(session_factory, tenant_id=tid, state="completed")
    await _seed_run(session_factory, tenant_id=tid, state="completed")
    await _seed_run(session_factory, tenant_id=tid, state="pending")
    await _seed_run(session_factory, tenant_id=tid, state="failed")

    resp = await client.get("/v1/admin/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_entities"] == 2
    assert data["total_relationships"] == 1
    assert data["total_runs"] == 4
    assert data["runs_by_state"]["completed"] == 2
    assert data["runs_by_state"]["pending"] == 1
    assert data["runs_by_state"]["failed"] == 1


# === 8. Bulk credential test -> returns array ================================


async def test_bulk_credential_test(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Bulk test returns a result for every known credential slot."""
    tid = await _seed_tenant(session_factory, "bulk-cred-tenant")

    resp = await client.post(f"/v1/admin/tenants/{tid}/credentials/test-all")
    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data
    results = data["results"]

    # Should have one result per known slot
    from expose.api.credentials import KNOWN_SLOTS  # noqa: PLC0415

    assert len(results) == len(KNOWN_SLOTS)

    # Each result should have the expected shape
    for result in results:
        assert "credential_id" in result
        assert "status" in result
        assert "message" in result

    # All should be "not_configured" since we haven't stored any creds
    statuses = {r["status"] for r in results}
    assert statuses == {"not_configured"}


async def test_bulk_credential_test_with_configured(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Bulk test correctly reports configured credentials."""
    from expose.api.credentials import set_backend  # noqa: PLC0415
    from expose.secrets.memory_backend import InMemoryBackend  # noqa: PLC0415

    tid = await _seed_tenant(session_factory, "bulk-cred-configured-tenant")

    # Store a credential in the backend
    backend = InMemoryBackend()
    set_backend(backend)
    await backend.set(
        tenant_id=tid,
        key="collector.shodan-iwide.api_key",
        value="test-api-key-12345",
    )

    resp = await client.post(f"/v1/admin/tenants/{tid}/credentials/test-all")
    assert resp.status_code == 200
    data = resp.json()
    results = data["results"]

    # Find the Shodan result
    shodan_results = [r for r in results if r["credential_id"] == "shodan_api_key"]
    assert len(shodan_results) == 1
    # It should be "ok" or "failed" (health check may fail in test), but NOT "not_configured"
    assert shodan_results[0]["status"] != "not_configured"
