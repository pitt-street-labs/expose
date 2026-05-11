"""Tests for the run results API (issue #10) and artifact download (issue #112).

Uses an in-memory SQLite database via ``aiosqlite`` for speed — no Docker or
testcontainers required.  The FastAPI ``get_session`` dependency is overridden
to inject a test ``AsyncSession``.

Covers:
 1. List runs (empty) → 200, empty list
 2. List runs with data → returns runs
 3. Get run → 200
 4. Get nonexistent run → 404
 5. List entities (empty) → 200, empty list
 6. List entities with data → returns entities
 7. Get entity → 200
 8. Get nonexistent entity → 404
 9. Runs are tenant-scoped (tenant A can't see tenant B's runs)
10. Entities are tenant-scoped (tenant A can't see tenant B's entities)
11. Get run with wrong tenant → 404 (cross-tenant invisibility)
12. Get entity with wrong tenant → 404 (cross-tenant invisibility)
20. Download artifact for completed run → 200
21. Download artifact for nonexistent run → 404
22. Download artifact for pending run → 409
23. Download artifact for running run → 409
24. Download artifact for failed run → 200 (failed is terminal)
25. Download artifact for wrong tenant → 404 (cross-tenant invisibility)
26. Downloaded artifact contains valid JSON with expected schema fields
"""

from __future__ import annotations

import json
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

from expose.api.runs import router as runs_router
from expose.api.tenants import get_session
from expose.api.tenants import router as tenants_router
from expose.db.models import Base, Entity, Run, Tenant


def _make_app() -> Any:
    """Construct a minimal FastAPI app with tenants + runs routers."""
    from fastapi import FastAPI  # noqa: PLC0415

    app = FastAPI()
    app.include_router(tenants_router)
    app.include_router(runs_router)
    return app


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
# Helpers — seed test data via ORM, not the API, for isolation
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
    pipeline_version: str = "1.0.0",
) -> UUID:
    """Insert a run row and return its id."""
    rid = uuid4()
    async with session_factory() as session:
        run = Run(
            id=rid,
            tenant_id=tenant_id,
            pipeline_version=pipeline_version,
            state=state,
            started_at=datetime.now(UTC),
            completed_at=None,
            target_count=None,
            run_metadata={},
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


# === 1. List runs (empty) → 200, empty list =================================


async def test_list_runs_empty(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "empty-runs-tenant")
    resp = await client.get(f"/v1/tenants/{tid}/runs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["runs"] == []
    assert data["total"] == 0


# === 2. List runs with data → returns runs ===================================


async def test_list_runs_with_data(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "runs-data-tenant")
    await _seed_run(session_factory, tenant_id=tid, state="completed")
    await _seed_run(session_factory, tenant_id=tid, state="pending")

    resp = await client.get(f"/v1/tenants/{tid}/runs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["runs"]) == 2
    states = {r["state"] for r in data["runs"]}
    assert states == {"completed", "pending"}


# === 3. Get run → 200 ========================================================


async def test_get_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "get-run-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid, state="running")

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == str(rid)
    assert data["tenant_id"] == str(tid)
    assert data["state"] == "running"
    assert data["pipeline_version"] == "1.0.0"


# === 4. Get nonexistent run → 404 ============================================


async def test_get_nonexistent_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "no-run-tenant")
    fake_id = uuid4()
    resp = await client.get(f"/v1/tenants/{tid}/runs/{fake_id}")
    assert resp.status_code == 404


# === 5. List entities (empty) → 200, empty list ==============================


async def test_list_entities_empty(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "empty-entities-tenant")
    resp = await client.get(f"/v1/tenants/{tid}/entities")
    assert resp.status_code == 200
    data = resp.json()
    assert data["entities"] == []
    assert data["total"] == 0


# === 6. List entities with data → returns entities ============================


async def test_list_entities_with_data(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "entities-data-tenant")
    await _seed_entity(session_factory, tenant_id=tid, canonical_identifier="a.example.com")
    await _seed_entity(
        session_factory,
        tenant_id=tid,
        entity_type="IP",
        canonical_identifier="192.0.2.1",
    )

    resp = await client.get(f"/v1/tenants/{tid}/entities")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["entities"]) == 2
    types = {e["entity_type"] for e in data["entities"]}
    assert types == {"Domain", "IP"}


# === 7. Get entity → 200 =====================================================


async def test_get_entity(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "get-entity-tenant")
    eid = await _seed_entity(
        session_factory, tenant_id=tid, canonical_identifier="get-me.example.com"
    )

    resp = await client.get(f"/v1/tenants/{tid}/entities/{eid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == str(eid)
    assert data["tenant_id"] == str(tid)
    assert data["entity_type"] == "Domain"
    assert data["canonical_identifier"] == "get-me.example.com"
    assert data["attribution_status"] == "confirmed"


# === 8. Get nonexistent entity → 404 =========================================


async def test_get_nonexistent_entity(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "no-entity-tenant")
    fake_id = uuid4()
    resp = await client.get(f"/v1/tenants/{tid}/entities/{fake_id}")
    assert resp.status_code == 404


# === 9. Runs are tenant-scoped ================================================


async def test_runs_tenant_scoped(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid_a = await _seed_tenant(session_factory, "scope-runs-a")
    tid_b = await _seed_tenant(session_factory, "scope-runs-b")
    await _seed_run(session_factory, tenant_id=tid_a, state="completed")
    await _seed_run(session_factory, tenant_id=tid_b, state="pending")

    # Tenant A should only see its own run
    resp_a = await client.get(f"/v1/tenants/{tid_a}/runs")
    assert resp_a.status_code == 200
    data_a = resp_a.json()
    assert data_a["total"] == 1
    assert data_a["runs"][0]["state"] == "completed"

    # Tenant B should only see its own run
    resp_b = await client.get(f"/v1/tenants/{tid_b}/runs")
    assert resp_b.status_code == 200
    data_b = resp_b.json()
    assert data_b["total"] == 1
    assert data_b["runs"][0]["state"] == "pending"


# === 10. Entities are tenant-scoped ===========================================


async def test_entities_tenant_scoped(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid_a = await _seed_tenant(session_factory, "scope-entities-a")
    tid_b = await _seed_tenant(session_factory, "scope-entities-b")
    await _seed_entity(session_factory, tenant_id=tid_a, canonical_identifier="a.example.com")
    await _seed_entity(session_factory, tenant_id=tid_b, canonical_identifier="b.example.com")

    # Tenant A should only see its own entity
    resp_a = await client.get(f"/v1/tenants/{tid_a}/entities")
    assert resp_a.status_code == 200
    data_a = resp_a.json()
    assert data_a["total"] == 1
    assert data_a["entities"][0]["canonical_identifier"] == "a.example.com"

    # Tenant B should only see its own entity
    resp_b = await client.get(f"/v1/tenants/{tid_b}/entities")
    assert resp_b.status_code == 200
    data_b = resp_b.json()
    assert data_b["total"] == 1
    assert data_b["entities"][0]["canonical_identifier"] == "b.example.com"


# === 11. Get run with wrong tenant → 404 (cross-tenant invisibility) =========


async def test_get_run_wrong_tenant(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid_a = await _seed_tenant(session_factory, "run-wrong-tenant-a")
    tid_b = await _seed_tenant(session_factory, "run-wrong-tenant-b")
    rid = await _seed_run(session_factory, tenant_id=tid_a)

    # Trying to fetch tenant A's run via tenant B's path → 404
    resp = await client.get(f"/v1/tenants/{tid_b}/runs/{rid}")
    assert resp.status_code == 404


# === 12. Get entity with wrong tenant → 404 (cross-tenant invisibility) ======


async def test_get_entity_wrong_tenant(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid_a = await _seed_tenant(session_factory, "entity-wrong-tenant-a")
    tid_b = await _seed_tenant(session_factory, "entity-wrong-tenant-b")
    eid = await _seed_entity(
        session_factory, tenant_id=tid_a, canonical_identifier="private.example.com"
    )

    # Trying to fetch tenant A's entity via tenant B's path → 404
    resp = await client.get(f"/v1/tenants/{tid_b}/entities/{eid}")
    assert resp.status_code == 404


# === 13. POST with valid seeds → 202, returns run_id =========================


async def test_start_run_valid_seeds(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "start-run-tenant")
    resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={"seeds": ["example.com"]},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert "run_id" in data
    # Validate it is a valid UUID
    UUID(data["run_id"])
    assert data["tenant_id"] == str(tid)
    assert data["state"] == "pending"
    assert data["seeds"] == ["example.com"]
    assert isinstance(data["collector_ids"], list)
    assert isinstance(data["message"], str)
    assert str(data["run_id"]) in data["message"]


# === 14. POST with empty seeds list → 422 ====================================


async def test_start_run_empty_seeds(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "empty-seeds-tenant")
    resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={"seeds": []},
    )
    assert resp.status_code == 422


# === 15. POST to nonexistent tenant → 404 ====================================


async def test_start_run_nonexistent_tenant(
    client: AsyncClient,
) -> None:
    fake_tid = uuid4()
    resp = await client.post(
        f"/v1/tenants/{fake_tid}/runs",
        json={"seeds": ["example.com"]},
    )
    assert resp.status_code == 404


# === 16. POST with specific collector_ids → accepted ==========================


async def test_start_run_specific_collectors(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "specific-collectors-tenant")
    resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={
            "seeds": ["example.com"],
            "collector_ids": ["ct-crtsh", "cloud-ranges"],
        },
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["collector_ids"] == ["ct-crtsh", "cloud-ranges"]


# === 17. POST with auto-detected seed types (domain + IP mix) =================


async def test_start_run_mixed_seed_types(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "mixed-seeds-tenant")
    resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={"seeds": ["example.com", "192.168.1.1", "10.0.0.0/24"]},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["seeds"] == ["example.com", "192.168.1.1", "10.0.0.0/24"]
    assert data["state"] == "pending"
    # Verify a run_id was generated
    UUID(data["run_id"])


# === 18. RunStarted response has correct fields ==============================


async def test_run_started_response_fields(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "response-fields-tenant")
    resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={"seeds": ["test.example.org"]},
    )
    assert resp.status_code == 202
    data = resp.json()

    # Verify all required fields are present
    expected_keys = {"run_id", "tenant_id", "state", "seeds", "organization_seeds", "collector_ids", "message"}
    assert set(data.keys()) == expected_keys

    # Type checks
    UUID(data["run_id"])
    UUID(data["tenant_id"])
    assert isinstance(data["state"], str)
    assert isinstance(data["seeds"], list)
    assert isinstance(data["collector_ids"], list)
    assert isinstance(data["message"], str)

    # Frozen model rejects extra fields — verify by POST with extra body fields
    resp_extra = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={"seeds": ["a.com"], "unknown_field": "bad"},
    )
    assert resp_extra.status_code == 422


# === 19. POST creates a Run row visible via GET ==============================


async def test_start_run_creates_db_row(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "db-row-tenant")
    post_resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={"seeds": ["db-row.example.com"]},
    )
    assert post_resp.status_code == 202
    run_id = post_resp.json()["run_id"]

    # The run should now appear in GET /runs
    get_resp = await client.get(f"/v1/tenants/{tid}/runs/{run_id}")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["id"] == run_id
    assert data["tenant_id"] == str(tid)
    assert data["state"] == "pending"


# === 20. Download artifact for completed run → 200 ==========================


async def test_download_artifact_completed_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "artifact-completed-tenant")
    rid = await _seed_run(
        session_factory, tenant_id=tid, state="completed", pipeline_version="1.0.0"
    )
    # Seed an entity so the artifact has content
    await _seed_entity(
        session_factory, tenant_id=tid, canonical_identifier="artifact-test.example.com"
    )

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/artifact")
    assert resp.status_code == 200

    # Verify response headers
    assert resp.headers["content-type"] == "application/json"
    content_disp = resp.headers["content-disposition"]
    assert "attachment" in content_disp
    assert f"expose-artifact-{rid}.json" in content_disp

    # Verify response body is valid JSON with expected top-level keys
    body = json.loads(resp.content)
    assert "schema_version" in body
    assert body["schema_version"] == "expose/v1"
    assert "run" in body
    assert "tenant" in body
    assert "targets" in body
    assert body["run"]["run_id"] == str(rid)
    assert body["tenant"]["tenant_id"] == str(tid)
    # The seeded entity should appear as a target
    assert len(body["targets"]) >= 1


# === 21. Download artifact for nonexistent run → 404 ========================


async def test_download_artifact_nonexistent_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "artifact-no-run-tenant")
    fake_id = uuid4()
    resp = await client.get(f"/v1/tenants/{tid}/runs/{fake_id}/artifact")
    assert resp.status_code == 404


# === 22. Download artifact for pending run → 409 ============================


async def test_download_artifact_pending_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "artifact-pending-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid, state="pending")

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/artifact")
    assert resp.status_code == 409
    data = resp.json()
    assert "pending" in data["detail"]


# === 23. Download artifact for running run → 409 ============================


async def test_download_artifact_running_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "artifact-running-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid, state="running")

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/artifact")
    assert resp.status_code == 409
    data = resp.json()
    assert "running" in data["detail"]


# === 24. Download artifact for failed run → 200 (failed is terminal) ========


async def test_download_artifact_failed_run(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "artifact-failed-tenant")
    rid = await _seed_run(session_factory, tenant_id=tid, state="failed")

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/artifact")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"
    body = json.loads(resp.content)
    assert body["schema_version"] == "expose/v1"


# === 25. Download artifact for wrong tenant → 404 (cross-tenant) ============


async def test_download_artifact_wrong_tenant(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid_a = await _seed_tenant(session_factory, "artifact-cross-a")
    tid_b = await _seed_tenant(session_factory, "artifact-cross-b")
    rid = await _seed_run(session_factory, tenant_id=tid_a, state="completed")

    # Trying to download tenant A's artifact via tenant B's path → 404
    resp = await client.get(f"/v1/tenants/{tid_b}/runs/{rid}/artifact")
    assert resp.status_code == 404


# === 26. Downloaded artifact contains valid JSON with schema fields ==========


async def test_download_artifact_json_structure(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "artifact-structure-tenant")
    rid = await _seed_run(
        session_factory, tenant_id=tid, state="completed", pipeline_version="1.0.0"
    )
    # Seed two entities for a richer artifact
    await _seed_entity(
        session_factory, tenant_id=tid, canonical_identifier="alpha.example.com"
    )
    await _seed_entity(
        session_factory,
        tenant_id=tid,
        entity_type="IP",
        canonical_identifier="192.0.2.42",
    )

    resp = await client.get(f"/v1/tenants/{tid}/runs/{rid}/artifact")
    assert resp.status_code == 200

    body = json.loads(resp.content)

    # Verify full structure
    assert body["schema_version"] == "expose/v1"

    # Run metadata
    run_data = body["run"]
    assert run_data["run_id"] == str(rid)
    assert "started_at" in run_data
    assert "completed_at" in run_data
    assert "pipeline_version" in run_data

    # Tenant metadata
    tenant_data = body["tenant"]
    assert tenant_data["tenant_id"] == str(tid)

    # Targets — should have both seeded entities
    assert len(body["targets"]) == 2
    target_identifiers = {t["primary_identifier"]["value"] for t in body["targets"]}
    assert "alpha.example.com" in target_identifiers
    assert "192.0.2.42" in target_identifiers

    # Each target should have required fields
    for target in body["targets"]:
        assert "target_id" in target
        assert "primary_identifier" in target
        assert "attribution" in target
        assert "provenance" in target
        assert "lead_score" in target

    # Delta and collector health are present
    assert "delta_from_previous_run" in body
    assert "collector_health" in body


# === 27. POST with invalid seed format → 422 =================================


async def test_start_run_invalid_seed_format(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Seeds that are not valid domains, IPs, or CIDRs are rejected with 422."""
    tid = await _seed_tenant(session_factory, "invalid-seed-tenant")
    resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={"seeds": ["not a valid seed!!"]},
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert isinstance(detail, list)
    assert any("Invalid seed format" in err for err in detail)


# === 28. POST with multiple invalid seeds → 422 with all errors ==============


async def test_start_run_multiple_invalid_seeds(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Multiple invalid seeds produce multiple error messages."""
    tid = await _seed_tenant(session_factory, "multi-invalid-seed-tenant")
    resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={"seeds": ["bad seed 1!", "bad seed @#$"]},
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert len(detail) == 2


# === 29. POST with valid domain seed → 202 ===================================


async def test_start_run_valid_domain_seed(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A valid domain seed is accepted."""
    tid = await _seed_tenant(session_factory, "valid-domain-seed-tenant")
    resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={"seeds": ["sub.example.com"]},
    )
    assert resp.status_code == 202


# === 30. POST with valid IP seed → 202 =======================================


async def test_start_run_valid_ip_seed(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A valid IPv4 address seed is accepted."""
    tid = await _seed_tenant(session_factory, "valid-ip-seed-tenant")
    resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={"seeds": ["192.168.1.1"]},
    )
    assert resp.status_code == 202


# === 31. POST with valid CIDR seed → 202 =====================================


async def test_start_run_valid_cidr_seed(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A valid CIDR notation seed is accepted."""
    tid = await _seed_tenant(session_factory, "valid-cidr-seed-tenant")
    resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={"seeds": ["10.0.0.0/24"]},
    )
    assert resp.status_code == 202


# === 32. POST with valid IPv6 seed → 202 =====================================


async def test_start_run_valid_ipv6_seed(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """A valid IPv6 address seed is accepted."""
    tid = await _seed_tenant(session_factory, "valid-ipv6-seed-tenant")
    resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={"seeds": ["2001:db8::1"]},
    )
    assert resp.status_code == 202


# === 33. POST with unknown collector_ids → 422 ===============================


async def test_start_run_unknown_collector_ids(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Unknown collector IDs are rejected with 422."""
    tid = await _seed_tenant(session_factory, "unknown-collector-tenant")
    resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={
            "seeds": ["example.com"],
            "collector_ids": ["nonexistent-collector-xyz"],
        },
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert isinstance(detail, list)
    assert any("Unknown collector_id" in err for err in detail)


# === 34. POST with no collector_ids (default) → 202 ==========================


async def test_start_run_no_collector_ids_defaults(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """When collector_ids is not provided, Tier-1 defaults are used (no 422)."""
    tid = await _seed_tenant(session_factory, "default-collectors-tenant")
    resp = await client.post(
        f"/v1/tenants/{tid}/runs",
        json={"seeds": ["example.com"]},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert isinstance(data["collector_ids"], list)
    assert len(data["collector_ids"]) > 0
