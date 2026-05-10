"""Tests for the observation graph data endpoint (``GET /v1/tenants/{tid}/graph``).

Uses an in-memory SQLite database via ``aiosqlite`` for speed — no Docker or
testcontainers required.  The FastAPI ``get_session`` dependency is overridden
to inject a test ``AsyncSession``.

Covers:
 1. Empty graph → 200, empty nodes/edges
 2. Graph with entities → nodes populated correctly
 3. Graph with relationships → edges populated
 4. Tenant scoping → tenant B can't see tenant A's graph
 5. Node label matches canonical_identifier
 6. GraphNode model validates correctly
 7. GraphEdge model validates correctly
 8. attribution_confidence defaults when missing from entity
 9. collector_count aggregates distinct collector_ids
10. Node first_observed is populated from entity
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from expose.api.graph import GraphEdge, GraphNode
from expose.api.graph import router as graph_router
from expose.api.tenants import get_session
from expose.api.tenants import router as tenants_router
from expose.db.models import Base, Entity, Relationship, Tenant


def _make_app() -> Any:
    """Construct a minimal FastAPI app with tenants + graph routers."""
    from fastapi import FastAPI  # noqa: PLC0415

    app = FastAPI()
    app.include_router(tenants_router)
    app.include_router(graph_router)
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


async def _seed_entity(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: UUID,
    entity_type: str = "Domain",
    canonical_identifier: str = "example.com",
    attribution_status: str = "confirmed",
    attribution_confidence: Decimal = Decimal("0.950"),
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
            attribution_status=attribution_status,
            attribution_confidence=attribution_confidence,
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
    collector_id: str = "active-dns",
) -> UUID:
    """Insert a relationship row and return its id."""
    rid = uuid4()
    async with session_factory() as session:
        rel = Relationship(
            id=rid,
            tenant_id=tenant_id,
            from_entity_id=from_entity_id,
            to_entity_id=to_entity_id,
            edge_type=edge_type,
            confidence=Decimal("0.900"),
            observed_at=datetime.now(UTC),
            collector_id=collector_id,
            properties={},
        )
        session.add(rel)
        await session.commit()
    return rid


# === 1. Empty graph → 200, empty nodes/edges =================================


async def test_empty_graph(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "empty-graph-tenant")
    resp = await client.get(f"/v1/tenants/{tid}/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert data["nodes"] == []
    assert data["edges"] == []


# === 2. Graph with entities → nodes populated correctly =======================


async def test_graph_with_entities(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "entities-graph-tenant")
    await _seed_entity(
        session_factory,
        tenant_id=tid,
        canonical_identifier="a.example.com",
    )
    await _seed_entity(
        session_factory,
        tenant_id=tid,
        entity_type="IP",
        canonical_identifier="192.0.2.1",
    )

    resp = await client.get(f"/v1/tenants/{tid}/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["nodes"]) == 2
    types = {n["entity_type"] for n in data["nodes"]}
    assert types == {"Domain", "IP"}
    # No relationships → collector_count should be 0 for all nodes
    for node in data["nodes"]:
        assert node["collector_count"] == 0


# === 3. Graph with relationships → edges populated ============================


async def test_graph_with_relationships(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "edges-graph-tenant")
    eid_domain = await _seed_entity(
        session_factory,
        tenant_id=tid,
        canonical_identifier="edge.example.com",
    )
    eid_ip = await _seed_entity(
        session_factory,
        tenant_id=tid,
        entity_type="IP",
        canonical_identifier="198.51.100.1",
    )
    await _seed_relationship(
        session_factory,
        tenant_id=tid,
        from_entity_id=eid_domain,
        to_entity_id=eid_ip,
        edge_type="resolves_to",
        collector_id="active-dns",
    )

    resp = await client.get(f"/v1/tenants/{tid}/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["edges"]) == 1
    edge = data["edges"][0]
    assert edge["source"] == str(eid_domain)
    assert edge["target"] == str(eid_ip)
    assert edge["relationship_type"] == "resolves_to"
    assert edge["collector_id"] == "active-dns"


# === 4. Tenant scoping → tenant B can't see tenant A's graph =================


async def test_graph_tenant_scoping(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid_a = await _seed_tenant(session_factory, "scope-graph-a")
    tid_b = await _seed_tenant(session_factory, "scope-graph-b")
    await _seed_entity(
        session_factory,
        tenant_id=tid_a,
        canonical_identifier="private-a.example.com",
    )
    await _seed_entity(
        session_factory,
        tenant_id=tid_b,
        canonical_identifier="private-b.example.com",
    )

    resp_a = await client.get(f"/v1/tenants/{tid_a}/graph")
    assert resp_a.status_code == 200
    data_a = resp_a.json()
    assert len(data_a["nodes"]) == 1
    assert data_a["nodes"][0]["label"] == "private-a.example.com"

    resp_b = await client.get(f"/v1/tenants/{tid_b}/graph")
    assert resp_b.status_code == 200
    data_b = resp_b.json()
    assert len(data_b["nodes"]) == 1
    assert data_b["nodes"][0]["label"] == "private-b.example.com"


# === 5. Node label matches canonical_identifier ==============================


async def test_node_label_matches_canonical_identifier(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "label-test-tenant")
    await _seed_entity(
        session_factory,
        tenant_id=tid,
        canonical_identifier="label-check.example.com",
    )

    resp = await client.get(f"/v1/tenants/{tid}/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["nodes"]) == 1
    assert data["nodes"][0]["label"] == "label-check.example.com"


# === 6. GraphNode model validates correctly ===================================


async def test_graph_node_model_validation() -> None:
    node = GraphNode(
        id="abc-123",
        label="example.com",
        entity_type="Domain",
        attribution_status="confirmed",
        attribution_confidence=0.95,
        collector_count=3,
        first_observed=datetime.now(UTC),
    )
    assert node.id == "abc-123"
    assert node.label == "example.com"
    assert node.attribution_confidence == 0.95
    assert node.collector_count == 3

    # Frozen — assignment should raise
    with pytest.raises(ValidationError):
        node.id = "changed"  # type: ignore[misc]

    # Extra fields rejected
    with pytest.raises(ValidationError):
        GraphNode(
            id="x",
            label="x",
            entity_type="Domain",
            attribution_status="confirmed",
            attribution_confidence=0.5,
            collector_count=1,
            bogus_field="nope",  # type: ignore[call-arg]
        )


# === 7. GraphEdge model validates correctly ===================================


async def test_graph_edge_model_validation() -> None:
    edge = GraphEdge(
        source="uuid1",
        target="uuid2",
        relationship_type="resolves_to",
        collector_id="active-dns",
    )
    assert edge.source == "uuid1"
    assert edge.target == "uuid2"
    assert edge.relationship_type == "resolves_to"

    # Frozen — assignment should raise
    with pytest.raises(ValidationError):
        edge.source = "changed"  # type: ignore[misc]

    # Extra fields rejected
    with pytest.raises(ValidationError):
        GraphEdge(
            source="a",
            target="b",
            relationship_type="hosts",
            extra_thing="bad",  # type: ignore[call-arg]
        )

    # collector_id is optional — None is valid
    edge_no_collector = GraphEdge(
        source="a",
        target="b",
        relationship_type="hosts",
    )
    assert edge_no_collector.collector_id is None


# === 8. attribution_confidence defaults when missing ==========================


async def test_attribution_confidence_default(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "confidence-default-tenant")
    # Seed entity with zero confidence
    await _seed_entity(
        session_factory,
        tenant_id=tid,
        canonical_identifier="zero-conf.example.com",
        attribution_status="unattributed",
        attribution_confidence=Decimal("0.000"),
    )

    resp = await client.get(f"/v1/tenants/{tid}/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["nodes"]) == 1
    assert data["nodes"][0]["attribution_confidence"] == 0.0
    assert data["nodes"][0]["attribution_status"] == "unattributed"


# === 9. collector_count aggregates distinct collector_ids =====================


async def test_collector_count_distinct(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "collector-count-tenant")
    eid_domain = await _seed_entity(
        session_factory,
        tenant_id=tid,
        canonical_identifier="multi.example.com",
    )
    eid_ip1 = await _seed_entity(
        session_factory,
        tenant_id=tid,
        entity_type="IP",
        canonical_identifier="203.0.113.1",
    )
    eid_ip2 = await _seed_entity(
        session_factory,
        tenant_id=tid,
        entity_type="IP",
        canonical_identifier="203.0.113.2",
    )

    # Three relationships from the domain, but only two distinct collector_ids
    await _seed_relationship(
        session_factory,
        tenant_id=tid,
        from_entity_id=eid_domain,
        to_entity_id=eid_ip1,
        collector_id="active-dns",
    )
    await _seed_relationship(
        session_factory,
        tenant_id=tid,
        from_entity_id=eid_domain,
        to_entity_id=eid_ip2,
        collector_id="ct-crtsh",
    )
    await _seed_relationship(
        session_factory,
        tenant_id=tid,
        from_entity_id=eid_domain,
        to_entity_id=eid_ip1,
        edge_type="hosts",
        collector_id="active-dns",  # duplicate — should not double-count
    )

    resp = await client.get(f"/v1/tenants/{tid}/graph")
    assert resp.status_code == 200
    data = resp.json()

    domain_node = next(n for n in data["nodes"] if n["label"] == "multi.example.com")
    # 2 distinct collectors (active-dns, ct-crtsh) across outgoing relationships
    assert domain_node["collector_count"] == 2

    # IP nodes appear as targets — they should count collectors from incoming edges
    ip1_node = next(n for n in data["nodes"] if n["label"] == "203.0.113.1")
    # active-dns appears on two relationships to this IP, but only 1 distinct collector
    assert ip1_node["collector_count"] == 1

    ip2_node = next(n for n in data["nodes"] if n["label"] == "203.0.113.2")
    assert ip2_node["collector_count"] == 1


# === 10. Node first_observed is populated from entity =========================


async def test_node_first_observed_populated(
    client: AsyncClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    tid = await _seed_tenant(session_factory, "first-observed-tenant")
    await _seed_entity(
        session_factory,
        tenant_id=tid,
        canonical_identifier="observed.example.com",
    )

    resp = await client.get(f"/v1/tenants/{tid}/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["nodes"]) == 1
    # first_observed should be a non-null ISO datetime string
    assert data["nodes"][0]["first_observed"] is not None
    # Verify it parses as a valid datetime
    datetime.fromisoformat(data["nodes"][0]["first_observed"])
