"""Tests for the run scheduling API (issue #99).

Uses an in-memory SQLite database via ``aiosqlite`` for speed -- no Docker or
testcontainers required.  The FastAPI ``get_session`` dependency is overridden
to inject a test ``AsyncSession``.

Covers:
 1. Create a schedule -> 201 with valid response
 2. Create with invalid cron expression -> 422
 3. List schedules (empty) -> 200 with empty list
 4. List schedules (with data) -> returns all schedules
 5. Get schedule by tenant_id -> 200
 6. Get nonexistent schedule -> 404
 7. Delete schedule -> 204
 8. Delete nonexistent schedule -> 404
 9. Create replaces existing schedule for same tenant
10. Concurrent run limit blocks duplicate runs for same tenant
11. Scheduler background task starts and stops cleanly
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
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

from expose.api.scheduler import router as scheduler_router
from expose.api.tenants import get_session
from expose.api.tenants import router as tenants_router
from expose.db.models import Base, Run, Tenant
from expose.pipeline.scheduler import RunScheduler


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _make_app(scheduler: RunScheduler | None = None) -> Any:
    """Construct a minimal FastAPI app with required routers."""
    from fastapi import FastAPI  # noqa: PLC0415

    app = FastAPI()
    app.include_router(tenants_router)
    app.include_router(scheduler_router)
    app.state.server_started_at = datetime.now(UTC)
    app.state._bg_tasks = {}

    if scheduler is not None:
        app.state.run_scheduler = scheduler

    return app


# ---------------------------------------------------------------------------
# SQLite fixtures (mirrors test_admin_api pattern)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Scheduler + trigger tracking
# ---------------------------------------------------------------------------

_trigger_calls: list[tuple[UUID, list[str], list[dict]]] = []


async def _tracking_trigger(
    tenant_id: UUID,
    collector_ids: list[str],
    seeds: list[dict],
) -> None:
    """Test trigger callback that records invocations."""
    _trigger_calls.append((tenant_id, collector_ids, seeds))


@pytest_asyncio.fixture(autouse=True)
async def _clear_trigger_calls() -> AsyncIterator[None]:
    """Reset the tracking list before each test."""
    _trigger_calls.clear()
    yield
    _trigger_calls.clear()


@pytest_asyncio.fixture
async def scheduler() -> RunScheduler:
    """A ``RunScheduler`` with a no-op trigger for API tests."""
    return RunScheduler(on_run_trigger=_tracking_trigger)


# ---------------------------------------------------------------------------
# HTTPX client
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def client(
    session_factory: async_sessionmaker[AsyncSession],
    scheduler: RunScheduler,
) -> AsyncIterator[AsyncClient]:
    """HTTPX async client wired to the FastAPI app."""
    app = _make_app(scheduler=scheduler)

    async def _override_get_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_session] = _override_get_session
    app.state.session_factory = session_factory

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    # Cancel any background tasks spawned during the test to prevent them
    # from racing against engine disposal.
    bg_tasks: dict[str, asyncio.Task[None]] = getattr(app.state, "_bg_tasks", {})
    for task in bg_tasks.values():
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


async def _seed_run(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: UUID,
    state: str = "pending",
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
            target_count=None,
        )
        session.add(run)
        await session.commit()
    return rid


# ===================================================================
# 1. Create a schedule -> 201
# ===================================================================


async def test_create_schedule(
    client: AsyncClient,
) -> None:
    tid = uuid4()
    resp = await client.post(
        "/v1/scheduler/schedules",
        json={
            "tenant_id": str(tid),
            "cron_expression": "0 2 * * *",
            "collector_ids": ["dns-basic", "whois"],
            "seeds": [{"value": "example.com", "seed_type": "DOMAIN"}],
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["tenant_id"] == str(tid)
    assert data["cron_expression"] == "0 2 * * *"
    assert data["collector_ids"] == ["dns-basic", "whois"]
    assert data["enabled"] is True
    assert data["consecutive_failures"] == 0
    assert data["next_run_at"] is not None


# ===================================================================
# 2. Create with invalid cron expression -> 422
# ===================================================================


async def test_create_schedule_invalid_cron(
    client: AsyncClient,
) -> None:
    tid = uuid4()
    resp = await client.post(
        "/v1/scheduler/schedules",
        json={
            "tenant_id": str(tid),
            "cron_expression": "not a cron",
        },
    )
    assert resp.status_code == 422


async def test_create_schedule_wrong_field_count(
    client: AsyncClient,
) -> None:
    tid = uuid4()
    resp = await client.post(
        "/v1/scheduler/schedules",
        json={
            "tenant_id": str(tid),
            "cron_expression": "* * *",
        },
    )
    assert resp.status_code == 422
    assert "5 fields" in resp.json()["detail"]


async def test_create_schedule_out_of_range(
    client: AsyncClient,
) -> None:
    tid = uuid4()
    resp = await client.post(
        "/v1/scheduler/schedules",
        json={
            "tenant_id": str(tid),
            "cron_expression": "99 2 * * *",
        },
    )
    assert resp.status_code == 422
    assert "out of bounds" in resp.json()["detail"]


# ===================================================================
# 3. List schedules (empty) -> 200
# ===================================================================


async def test_list_schedules_empty(
    client: AsyncClient,
) -> None:
    resp = await client.get("/v1/scheduler/schedules")
    assert resp.status_code == 200
    data = resp.json()
    assert data["schedules"] == []
    assert data["total"] == 0


# ===================================================================
# 4. List schedules (with data) -> returns all
# ===================================================================


async def test_list_schedules_with_data(
    client: AsyncClient,
) -> None:
    tid1 = uuid4()
    tid2 = uuid4()

    await client.post(
        "/v1/scheduler/schedules",
        json={"tenant_id": str(tid1), "cron_expression": "0 * * * *"},
    )
    await client.post(
        "/v1/scheduler/schedules",
        json={"tenant_id": str(tid2), "cron_expression": "30 6 * * 1"},
    )

    resp = await client.get("/v1/scheduler/schedules")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["schedules"]) == 2

    tenant_ids = {s["tenant_id"] for s in data["schedules"]}
    assert str(tid1) in tenant_ids
    assert str(tid2) in tenant_ids


# ===================================================================
# 5. Get schedule by tenant_id -> 200
# ===================================================================


async def test_get_schedule(
    client: AsyncClient,
) -> None:
    tid = uuid4()
    await client.post(
        "/v1/scheduler/schedules",
        json={
            "tenant_id": str(tid),
            "cron_expression": "*/15 * * * *",
            "collector_ids": ["ct-crtsh"],
        },
    )

    resp = await client.get(f"/v1/scheduler/schedules/{tid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tenant_id"] == str(tid)
    assert data["cron_expression"] == "*/15 * * * *"
    assert data["collector_ids"] == ["ct-crtsh"]


# ===================================================================
# 6. Get nonexistent schedule -> 404
# ===================================================================


async def test_get_schedule_not_found(
    client: AsyncClient,
) -> None:
    fake_id = uuid4()
    resp = await client.get(f"/v1/scheduler/schedules/{fake_id}")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ===================================================================
# 7. Delete schedule -> 204
# ===================================================================


async def test_delete_schedule(
    client: AsyncClient,
) -> None:
    tid = uuid4()
    await client.post(
        "/v1/scheduler/schedules",
        json={"tenant_id": str(tid), "cron_expression": "0 0 * * *"},
    )

    resp = await client.delete(f"/v1/scheduler/schedules/{tid}")
    assert resp.status_code == 204

    # Confirm it's gone.
    resp = await client.get(f"/v1/scheduler/schedules/{tid}")
    assert resp.status_code == 404


# ===================================================================
# 8. Delete nonexistent schedule -> 404
# ===================================================================


async def test_delete_schedule_not_found(
    client: AsyncClient,
) -> None:
    fake_id = uuid4()
    resp = await client.delete(f"/v1/scheduler/schedules/{fake_id}")
    assert resp.status_code == 404


# ===================================================================
# 9. Create replaces existing schedule for same tenant
# ===================================================================


async def test_create_replaces_existing(
    client: AsyncClient,
) -> None:
    tid = uuid4()

    # First schedule.
    resp1 = await client.post(
        "/v1/scheduler/schedules",
        json={
            "tenant_id": str(tid),
            "cron_expression": "0 2 * * *",
            "collector_ids": ["dns-basic"],
        },
    )
    assert resp1.status_code == 201

    # Replace with different cron + collector.
    resp2 = await client.post(
        "/v1/scheduler/schedules",
        json={
            "tenant_id": str(tid),
            "cron_expression": "0 4 * * *",
            "collector_ids": ["whois"],
        },
    )
    assert resp2.status_code == 201

    # Only one schedule for this tenant.
    resp = await client.get(f"/v1/scheduler/schedules/{tid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["cron_expression"] == "0 4 * * *"
    assert data["collector_ids"] == ["whois"]

    # Total count should be 1, not 2.
    list_resp = await client.get("/v1/scheduler/schedules")
    assert list_resp.json()["total"] == 1


# ===================================================================
# 10. Concurrent run limit blocks duplicate runs for same tenant
# ===================================================================


async def test_concurrent_run_limit(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """The scheduler trigger callback skips if a run is already active."""
    from expose.api.app import _scheduler_run_trigger  # noqa: PLC0415

    tid = await _seed_tenant(session_factory, "concurrent-limit-tenant")

    # Insert an active (pending) run for this tenant.
    await _seed_run(session_factory, tenant_id=tid, state="pending")

    # Wire a temporary app ref so the trigger can find session_factory.
    from expose.api.app import _set_app_ref  # noqa: PLC0415

    app = client._transport.app  # type: ignore[union-attr]
    _set_app_ref(app)

    # Call the trigger directly -- it should skip due to the active run.
    await _scheduler_run_trigger(
        tenant_id=tid,
        collector_ids=["dns-basic"],
        seeds=[{"value": "example.com", "seed_type": "DOMAIN"}],
    )

    # Verify no new run was created (only the one we seeded).
    async with session_factory() as session:
        from sqlalchemy import select  # noqa: PLC0415

        result = await session.execute(
            select(Run).where(Run.tenant_id == tid)
        )
        runs = list(result.scalars().all())

    assert len(runs) == 1, f"Expected 1 run (the seeded one), got {len(runs)}"


async def test_concurrent_run_limit_allows_after_completion(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """The scheduler trigger proceeds when no active runs exist."""
    from expose.api.app import _scheduler_run_trigger  # noqa: PLC0415

    tid = await _seed_tenant(session_factory, "limit-allows-tenant")

    # Insert a completed run -- should not block.
    await _seed_run(session_factory, tenant_id=tid, state="completed")

    from expose.api.app import _set_app_ref  # noqa: PLC0415

    app = client._transport.app  # type: ignore[union-attr]
    _set_app_ref(app)

    # The trigger will attempt to create a Run row and launch a background
    # pipeline.  The pipeline will fail (no real collectors), but the Run
    # row creation proves the limit check passed.
    await _scheduler_run_trigger(
        tenant_id=tid,
        collector_ids=["dns-basic"],
        seeds=[{"value": "example.com", "seed_type": "DOMAIN"}],
    )

    # Should have 2 runs now: the completed one + the newly created one.
    async with session_factory() as session:
        from sqlalchemy import select  # noqa: PLC0415

        result = await session.execute(
            select(Run).where(Run.tenant_id == tid)
        )
        runs = list(result.scalars().all())

    assert len(runs) == 2, f"Expected 2 runs, got {len(runs)}"


# ===================================================================
# 11. Scheduler background task starts and stops cleanly
# ===================================================================


async def test_scheduler_starts_and_stops() -> None:
    """The scheduler loop runs and exits when the shutdown event is set."""
    triggered: list[UUID] = []

    async def _trigger(
        tenant_id: UUID,
        collector_ids: list[str],
        seeds: list[dict],
    ) -> None:
        triggered.append(tenant_id)

    scheduler = RunScheduler(on_run_trigger=_trigger)
    shutdown = asyncio.Event()

    task = asyncio.create_task(scheduler.run(shutdown))

    # Let it run briefly.
    await asyncio.sleep(0.05)
    assert not task.done(), "Scheduler should still be running"

    # Signal shutdown.
    shutdown.set()
    await asyncio.wait_for(task, timeout=5.0)
    assert task.done()
    assert not task.cancelled()


async def test_scheduler_no_run_without_app_ref(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Trigger gracefully does nothing when app ref is cleared."""
    from expose.api.app import _scheduler_run_trigger  # noqa: PLC0415
    import expose.api.app as app_module  # noqa: PLC0415

    # Clear the weak ref.
    app_module._app_weak_ref = None

    tid = uuid4()
    # Should not raise -- just logs and returns.
    await _scheduler_run_trigger(
        tenant_id=tid,
        collector_ids=["dns-basic"],
        seeds=[],
    )


# ===================================================================
# 12. Scheduler not wired -> 503
# ===================================================================


async def test_scheduler_not_wired_returns_503(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Endpoints return 503 when no scheduler is on app.state."""
    app = _make_app(scheduler=None)

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
        resp = await ac.get("/v1/scheduler/schedules")
        assert resp.status_code == 503

        resp = await ac.post(
            "/v1/scheduler/schedules",
            json={
                "tenant_id": str(uuid4()),
                "cron_expression": "0 0 * * *",
            },
        )
        assert resp.status_code == 503
