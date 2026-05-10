"""Integration tests for the async tenant-scoped repository layer.

Covers ADR-002 (Postgres normalized graph) and ADR-007 (multi-tenancy
logical-only — every public method takes ``tenant_id`` and cross-tenant
calls return empty).

All tests use the session-scoped ``pg_container`` fixture from
``tests/conftest.py`` (testcontainers Postgres). Each test gets a fresh
schema via ``Base.metadata.create_all`` (we deliberately skip Alembic for
test setup to keep the schema-bootstrap path inside the test itself —
upgrade/downgrade fidelity is covered by Alembic's own offline tests).

Per the EXPOSE marker conventions in ``pyproject.toml`` these are tagged
``@pytest.mark.integration`` and skipped under ``-m "not integration"``.
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
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from expose.db.models import Base, Tenant
from expose.repositories import (
    EntityRepository,
    RelationshipRepository,
    RunRepository,
)
from expose.types.shared import EntityId, RunId, TenantId

pytestmark = pytest.mark.integration


# === Fixtures ===============================================================


def _asyncpg_url(sync_url: str) -> str:
    """Translate testcontainers' SQLAlchemy URL to an asyncpg DSN.

    testcontainers returns either ``postgresql+psycopg2://...`` (older versions)
    or ``postgresql+psycopg://...`` (newer); both use the synchronous driver,
    while our repository layer requires asyncpg.
    """
    for prefix in ("postgresql+psycopg2://", "postgresql+psycopg://", "postgresql://"):
        if sync_url.startswith(prefix):
            return "postgresql+asyncpg://" + sync_url[len(prefix):]
    return sync_url


@pytest_asyncio.fixture
async def async_engine(pg_container: Any) -> AsyncIterator[AsyncEngine]:
    """Per-test engine bound to the session-scoped Postgres container.

    Schema is created and torn down inside this fixture so each test gets a
    clean DB without paying the price of a fresh container per test.
    """
    url = _asyncpg_url(pg_container.get_connection_url())
    engine = create_async_engine(url, echo=False, future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield engine
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()


@pytest_asyncio.fixture
async def session_factory(
    async_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=async_engine, expire_on_commit=False, autoflush=False
    )


@pytest_asyncio.fixture
async def tenant_a_id(
    session_factory: async_sessionmaker[AsyncSession],
) -> TenantId:
    """Insert tenant A and return its id (TenantId-typed for the repos)."""
    tid = TenantId(uuid4())
    async with session_factory() as session:
        session.add(Tenant(id=tid, name="tenant-a"))
        await session.commit()
    return tid


@pytest_asyncio.fixture
async def tenant_b_id(
    session_factory: async_sessionmaker[AsyncSession],
) -> TenantId:
    """Insert tenant B and return its id (TenantId-typed for the repos)."""
    tid = TenantId(uuid4())
    async with session_factory() as session:
        session.add(Tenant(id=tid, name="tenant-b"))
        await session.commit()
    return tid


# === Helpers ================================================================


def _props(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    base: dict[str, Any] = {"source": "test"}
    if extra:
        base.update(extra)
    return base


# === Entity tests ===========================================================


async def test_entity_create_then_find_by_canonical(
    session_factory: async_sessionmaker[AsyncSession],
    tenant_a_id: TenantId,
) -> None:
    """Happy-path: upsert a new entity, then read it back via the canonical key."""
    async with session_factory() as session:
        repo = EntityRepository(session)
        created = await repo.create_or_update(
            tenant_id=tenant_a_id,
            entity_type="Domain",
            canonical_identifier="example.com",
            properties=_props({"registrar": "example-rar"}),
            attribution_status="confirmed",
            attribution_confidence=Decimal("0.950"),
        )
        await session.commit()
        assert created.canonical_identifier == "example.com"
        assert created.tenant_id == tenant_a_id
        assert created.properties["registrar"] == "example-rar"

    async with session_factory() as session:
        repo = EntityRepository(session)
        found = await repo.find_by_canonical(
            tenant_id=tenant_a_id,
            entity_type="Domain",
            canonical_identifier="example.com",
        )
        assert found is not None
        assert found.id == created.id
        assert found.attribution_status == "confirmed"


async def test_entity_upsert_is_idempotent(
    session_factory: async_sessionmaker[AsyncSession],
    tenant_a_id: TenantId,
) -> None:
    """Calling create_or_update twice with the same canonical key yields one row,
    and ``last_observed_at`` advances on the second call."""
    async with session_factory() as session:
        repo = EntityRepository(session)
        first = await repo.create_or_update(
            tenant_id=tenant_a_id,
            entity_type="Domain",
            canonical_identifier="dup.example.com",
            properties=_props({"v": 1}),
            attribution_status="hypothesized",
            attribution_confidence=Decimal("0.500"),
        )
        await session.commit()

    first_id = first.id
    first_first_observed = first.first_observed_at
    first_last_observed = first.last_observed_at

    # Brief sleep so NOW() can advance — Postgres TIMESTAMPTZ resolution is
    # microseconds, so even a few ms is plenty.
    await asyncio.sleep(0.05)

    async with session_factory() as session:
        repo = EntityRepository(session)
        second = await repo.create_or_update(
            tenant_id=tenant_a_id,
            entity_type="Domain",
            canonical_identifier="dup.example.com",
            properties=_props({"v": 2, "extra": "added"}),
            attribution_status="confirmed",
            attribution_confidence=Decimal("0.900"),
        )
        await session.commit()

    assert second.id == first_id, "upsert must collapse onto same row id"
    assert second.first_observed_at == first_first_observed, (
        "first_observed_at must be preserved across upserts"
    )
    assert second.last_observed_at > first_last_observed, (
        "last_observed_at must advance on re-observation"
    )
    assert second.properties == _props({"v": 2, "extra": "added"})
    assert second.attribution_status == "confirmed"
    assert second.attribution_confidence == Decimal("0.900")

    # Belt-and-braces: scan the table to confirm exactly one row.
    async with session_factory() as session:
        repo = EntityRepository(session)
        rows = await repo.list_for_tenant(
            tenant_id=tenant_a_id, entity_type="Domain", limit=1000
        )
        assert sum(1 for r in rows if r.canonical_identifier == "dup.example.com") == 1


async def test_entity_tenant_isolation_get_by_id(
    session_factory: async_sessionmaker[AsyncSession],
    tenant_a_id: TenantId,
    tenant_b_id: TenantId,
) -> None:
    """Tenant A creates an entity X; tenant B's get_by_id(X.id) returns None.

    This is the core ADR-007 invariant for the entity repository — an attacker
    holding a guessed UUID cannot reach across tenant boundaries.
    """
    async with session_factory() as session:
        repo_a = EntityRepository(session)
        ent = await repo_a.create_or_update(
            tenant_id=tenant_a_id,
            entity_type="Domain",
            canonical_identifier="a-only.example.com",
            properties=_props(),
            attribution_status="confirmed",
            attribution_confidence=Decimal("0.900"),
        )
        await session.commit()

    async with session_factory() as session:
        repo_b = EntityRepository(session)
        leaked = await repo_b.get_by_id(
            tenant_id=tenant_b_id, entity_id=EntityId(ent.id)
        )
        assert leaked is None, "tenant B must not be able to read tenant A's entity"

        # Sanity: tenant A still sees it.
        repo_a = EntityRepository(session)
        own = await repo_a.get_by_id(
            tenant_id=tenant_a_id, entity_id=EntityId(ent.id)
        )
        assert own is not None
        assert own.id == ent.id


async def test_entity_tenant_isolation_list(
    session_factory: async_sessionmaker[AsyncSession],
    tenant_a_id: TenantId,
    tenant_b_id: TenantId,
) -> None:
    """Tenant A inserts 5 entities, tenant B inserts 3; each list returns only
    its own rows."""
    async with session_factory() as session:
        repo = EntityRepository(session)
        for i in range(5):
            await repo.create_or_update(
                tenant_id=tenant_a_id,
                entity_type="Domain",
                canonical_identifier=f"a-{i}.example.com",
                properties=_props({"i": i}),
                attribution_status="confirmed",
                attribution_confidence=Decimal("0.900"),
            )
        for i in range(3):
            await repo.create_or_update(
                tenant_id=tenant_b_id,
                entity_type="Domain",
                canonical_identifier=f"b-{i}.example.com",
                properties=_props({"i": i}),
                attribution_status="confirmed",
                attribution_confidence=Decimal("0.900"),
            )
        await session.commit()

    async with session_factory() as session:
        repo = EntityRepository(session)
        a_rows = await repo.list_for_tenant(tenant_id=tenant_a_id, limit=100)
        b_rows = await repo.list_for_tenant(tenant_id=tenant_b_id, limit=100)
        assert len(a_rows) == 5
        assert len(b_rows) == 3
        assert all(r.tenant_id == tenant_a_id for r in a_rows)
        assert all(r.tenant_id == tenant_b_id for r in b_rows)


# === Relationship tests =====================================================


async def _make_entity(
    session: AsyncSession,
    *,
    tenant_id: TenantId,
    canonical: str,
) -> EntityId:
    repo = EntityRepository(session)
    ent = await repo.create_or_update(
        tenant_id=tenant_id,
        entity_type="Domain",
        canonical_identifier=canonical,
        properties=_props(),
        attribution_status="confirmed",
        attribution_confidence=Decimal("0.900"),
    )
    return EntityId(ent.id)


async def test_relationship_create_and_find_directional(
    session_factory: async_sessionmaker[AsyncSession],
    tenant_a_id: TenantId,
) -> None:
    """Create A->B; find_for_entity correctly classifies out vs in vs both."""
    async with session_factory() as session:
        a_id = await _make_entity(
            session, tenant_id=tenant_a_id, canonical="from.example.com"
        )
        b_id = await _make_entity(
            session, tenant_id=tenant_a_id, canonical="to.example.com"
        )
        await session.commit()

    async with session_factory() as session:
        rels = RelationshipRepository(session)
        edge = await rels.create(
            tenant_id=tenant_a_id,
            from_entity_id=a_id,
            to_entity_id=b_id,
            edge_type="resolves_to",
            confidence=Decimal("0.950"),
            observed_at=datetime.now(UTC),
            collector_id="test:dns-resolver",
            evidence_ref=None,
            properties=_props({"hop": 1}),
        )
        await session.commit()
        assert edge.from_entity_id == a_id
        assert edge.to_entity_id == b_id

    async with session_factory() as session:
        rels = RelationshipRepository(session)

        # From A's perspective: outgoing has 1, incoming has 0.
        out_a = await rels.find_for_entity(
            tenant_id=tenant_a_id, entity_id=a_id, direction="out"
        )
        in_a = await rels.find_for_entity(
            tenant_id=tenant_a_id, entity_id=a_id, direction="in"
        )
        both_a = await rels.find_for_entity(
            tenant_id=tenant_a_id, entity_id=a_id, direction="both"
        )
        assert len(out_a) == 1
        assert len(in_a) == 0
        assert len(both_a) == 1

        # From B's perspective: outgoing has 0, incoming has 1.
        out_b = await rels.find_for_entity(
            tenant_id=tenant_a_id, entity_id=b_id, direction="out"
        )
        in_b = await rels.find_for_entity(
            tenant_id=tenant_a_id, entity_id=b_id, direction="in"
        )
        both_b = await rels.find_for_entity(
            tenant_id=tenant_a_id, entity_id=b_id, direction="both"
        )
        assert len(out_b) == 0
        assert len(in_b) == 1
        assert len(both_b) == 1

        # edge_type filter: matching returns the row, mismatching returns empty.
        match = await rels.find_for_entity(
            tenant_id=tenant_a_id,
            entity_id=a_id,
            direction="out",
            edge_type="resolves_to",
        )
        miss = await rels.find_for_entity(
            tenant_id=tenant_a_id,
            entity_id=a_id,
            direction="out",
            edge_type="cname_of",
        )
        assert len(match) == 1
        assert len(miss) == 0


async def test_relationship_tenant_isolation(
    session_factory: async_sessionmaker[AsyncSession],
    tenant_a_id: TenantId,
    tenant_b_id: TenantId,
) -> None:
    """Tenant A's edge is invisible to tenant B's RelationshipRepository
    queries — even when B happens to own entities with the same UUIDs is
    impossible (UUIDs are unique), but more importantly, B querying for A's
    entity ids returns empty."""
    async with session_factory() as session:
        a_from = await _make_entity(
            session, tenant_id=tenant_a_id, canonical="iso-from.example.com"
        )
        a_to = await _make_entity(
            session, tenant_id=tenant_a_id, canonical="iso-to.example.com"
        )
        await session.commit()

        rels = RelationshipRepository(session)
        await rels.create(
            tenant_id=tenant_a_id,
            from_entity_id=a_from,
            to_entity_id=a_to,
            edge_type="resolves_to",
            confidence=Decimal("0.900"),
            observed_at=datetime.now(UTC),
            collector_id="test:iso-test",
        )
        await session.commit()

    async with session_factory() as session:
        rels = RelationshipRepository(session)
        # Tenant B asks about tenant A's entity ids — must return empty.
        leaked_out = await rels.find_for_entity(
            tenant_id=tenant_b_id, entity_id=a_from, direction="both"
        )
        leaked_in = await rels.find_for_entity(
            tenant_id=tenant_b_id, entity_id=a_to, direction="both"
        )
        assert len(leaked_out) == 0
        assert len(leaked_in) == 0

        # Sanity: tenant A still sees it.
        own = await rels.find_for_entity(
            tenant_id=tenant_a_id, entity_id=a_from, direction="out"
        )
        assert len(own) == 1


# === Run tests ==============================================================


async def test_run_state_transitions(
    session_factory: async_sessionmaker[AsyncSession],
    tenant_a_id: TenantId,
) -> None:
    """pending -> running -> completed walks the legal state machine; an
    illegal state name raises ``ValueError``; a missing run_id raises
    ``LookupError``."""
    async with session_factory() as session:
        runs = RunRepository(session)
        created = await runs.create(
            tenant_id=tenant_a_id, pipeline_version="v0.1.0", target_count=5
        )
        await session.commit()
        assert created.state == "pending"

    run_id = RunId(created.id)

    # pending -> running
    async with session_factory() as session:
        runs = RunRepository(session)
        running = await runs.update_state(
            tenant_id=tenant_a_id, run_id=run_id, new_state="running"
        )
        await session.commit()
        assert running.state == "running"
        assert running.completed_at is None

    # running -> completed (with completion fields)
    completed_at = datetime.now(UTC)
    async with session_factory() as session:
        runs = RunRepository(session)
        completed = await runs.update_state(
            tenant_id=tenant_a_id,
            run_id=run_id,
            new_state="completed",
            completed_at=completed_at,
            canonical_artifact_ref="sha256:" + "0" * 64,
            manifest_ref="sha256:" + "1" * 64,
        )
        await session.commit()
        assert completed.state == "completed"
        assert completed.completed_at is not None
        assert completed.canonical_artifact_ref == "sha256:" + "0" * 64
        assert completed.manifest_ref == "sha256:" + "1" * 64

    # Invalid state name -> ValueError
    async with session_factory() as session:
        runs = RunRepository(session)
        with pytest.raises(ValueError, match="Invalid run state"):
            await runs.update_state(
                tenant_id=tenant_a_id,
                run_id=run_id,
                new_state="quantum-superposition",
            )

    # Missing run_id -> LookupError
    async with session_factory() as session:
        runs = RunRepository(session)
        with pytest.raises(LookupError):
            await runs.update_state(
                tenant_id=tenant_a_id,
                run_id=RunId(uuid4()),
                new_state="running",
            )


async def test_run_tenant_isolation(
    session_factory: async_sessionmaker[AsyncSession],
    tenant_a_id: TenantId,
    tenant_b_id: TenantId,
) -> None:
    """Tenant A creates a run; tenant B's get_by_id and update_state cannot
    see or mutate it.

    Cross-tenant ``update_state`` raises ``LookupError`` (the same signal as
    "no such run") rather than ``PermissionError`` — both because the
    repository deliberately treats foreign tenant rows as nonexistent
    (ADR-007 §When to revisit) and because leaking 'this row exists but is
    not yours' is itself information disclosure.
    """
    async with session_factory() as session:
        runs = RunRepository(session)
        a_run = await runs.create(tenant_id=tenant_a_id, pipeline_version="v0.1.0")
        await session.commit()

    a_run_id = RunId(a_run.id)

    async with session_factory() as session:
        runs = RunRepository(session)
        leaked = await runs.get_by_id(tenant_id=tenant_b_id, run_id=a_run_id)
        assert leaked is None

        with pytest.raises(LookupError):
            await runs.update_state(
                tenant_id=tenant_b_id, run_id=a_run_id, new_state="running"
            )

        # Sanity: tenant A still sees it AND it is still in 'pending'
        own = await runs.get_by_id(tenant_id=tenant_a_id, run_id=a_run_id)
        assert own is not None
        assert own.state == "pending"


# Forward-compat: keep these imported references so ruff doesn't strip them.
_ = (UUID,)
