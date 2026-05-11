"""Tests for the provenance chain API endpoint.

Validates:
 1. Provenance endpoint returns correct response structure
 2. Provenance includes collector observations from entity properties
 3. Provenance includes relationships with resolved target entities
 4. Returns 404 for non-existent entity
 5. Provenance includes rules_applied from entity properties
 6. Entity with empty properties returns sparse provenance
 7. Cross-tenant invisibility (returns 404 for entity under wrong tenant)

Uses an in-memory SQLite database via ``aiosqlite`` for speed -- no Docker or
testcontainers required.  The FastAPI ``get_session`` dependency is overridden
to inject a test ``AsyncSession``.
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
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from expose.api.provenance import router as provenance_router
from expose.api.tenants import get_session
from expose.api.tenants import router as tenants_router
from expose.db.models import Base, Entity, Relationship, Tenant


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TENANT_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
ENTITY_A_ID = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
ENTITY_B_ID = UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
NONEXISTENT_ID = UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
OTHER_TENANT_ID = UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_app() -> Any:
    """Construct a minimal FastAPI app with tenants + provenance routers."""
    from fastapi import FastAPI  # noqa: PLC0415

    app = FastAPI()
    app.include_router(tenants_router)
    app.include_router(provenance_router)
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
    """Async HTTP client with seeded test data."""
    app = _make_app()

    async def _override_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_session] = _override_session

    # Seed data
    now = datetime(2026, 5, 11, 12, 0, 0, tzinfo=UTC)
    async with session_factory() as session:
        tenant = Tenant(
            id=TENANT_ID,
            name="test-tenant",
            created_at=now,
            config_jsonb={"state": "active"},
        )
        session.add(tenant)

        entity_a = Entity(
            id=ENTITY_A_ID,
            tenant_id=TENANT_ID,
            entity_type="domain",
            canonical_identifier="example.com",
            properties={
                "_collector_id": "dns-brute",
                "_observed_at": "2026-05-11T12:00:00Z",
                "_observation_type": "dns_resolution",
                "_rules_applied": [
                    {
                        "rule_id": "scope-match-apex",
                        "outcome": "match",
                        "confidence_delta": 0.3,
                    },
                    {
                        "rule_id": "whois-org-match",
                        "outcome": "partial",
                        "confidence_delta": 0.1,
                    },
                ],
                "nameservers": ["ns1.example.com", "ns2.example.com"],
            },
            attribution_status="high",
            attribution_confidence=Decimal("0.700"),
            first_observed_at=now,
            last_observed_at=now,
        )
        session.add(entity_a)

        entity_b = Entity(
            id=ENTITY_B_ID,
            tenant_id=TENANT_ID,
            entity_type="ip_address",
            canonical_identifier="93.184.216.34",
            properties={},
            attribution_status="unattributed",
            attribution_confidence=Decimal("0.000"),
            first_observed_at=now,
            last_observed_at=now,
        )
        session.add(entity_b)
        await session.flush()

        relationship = Relationship(
            id=uuid4(),
            tenant_id=TENANT_ID,
            from_entity_id=ENTITY_A_ID,
            to_entity_id=ENTITY_B_ID,
            edge_type="resolves_to",
            confidence=Decimal("0.900"),
            observed_at=datetime(2026, 5, 11, 12, 0, 30, tzinfo=UTC),
            collector_id="active-dns",
            evidence_ref=None,
            properties={},
        )
        session.add(relationship)
        await session.commit()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# 1. Provenance endpoint returns correct structure
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_provenance_response_structure(client: AsyncClient) -> None:
    """The provenance response must include all required top-level keys."""
    resp = await client.get(
        f"/v1/tenants/{TENANT_ID}/entities/{ENTITY_A_ID}/provenance"
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["entity_id"] == str(ENTITY_A_ID)
    assert data["entity_identifier"] == "example.com"
    assert data["entity_type"] == "domain"
    assert data["attribution_status"] == "high"
    assert data["attribution_confidence"] == pytest.approx(0.7, abs=0.01)
    assert isinstance(data["observations"], list)
    assert isinstance(data["rules_applied"], list)
    assert isinstance(data["relationships"], list)


# ---------------------------------------------------------------------------
# 2. Provenance includes collector observations
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_provenance_includes_observations(client: AsyncClient) -> None:
    """Observations should include the entity's own collector metadata
    AND relationship-derived collector observations."""
    resp = await client.get(
        f"/v1/tenants/{TENANT_ID}/entities/{ENTITY_A_ID}/provenance"
    )
    assert resp.status_code == 200
    data = resp.json()

    observations = data["observations"]
    assert len(observations) >= 1

    # The entity's own collector observation
    collector_ids = [obs["collector_id"] for obs in observations]
    assert "dns-brute" in collector_ids

    # The relationship's collector observation
    assert "active-dns" in collector_ids

    # Verify observation fields
    dns_brute_obs = next(o for o in observations if o["collector_id"] == "dns-brute")
    assert dns_brute_obs["observed_at"] == "2026-05-11T12:00:00Z"
    assert dns_brute_obs["observation_type"] == "dns_resolution"


# ---------------------------------------------------------------------------
# 3. Provenance includes relationships
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_provenance_includes_relationships(client: AsyncClient) -> None:
    """Relationships should include the resolves_to edge to entity B."""
    resp = await client.get(
        f"/v1/tenants/{TENANT_ID}/entities/{ENTITY_A_ID}/provenance"
    )
    assert resp.status_code == 200
    data = resp.json()

    relationships = data["relationships"]
    assert len(relationships) >= 1

    # Find the resolves_to edge
    resolves = [r for r in relationships if r["edge_type"] == "resolves_to"]
    assert len(resolves) == 1
    assert resolves[0]["target_identifier"] == "93.184.216.34"
    assert resolves[0]["target_type"] == "ip_address"


# ---------------------------------------------------------------------------
# 4. Returns 404 for non-existent entity
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_provenance_not_found(client: AsyncClient) -> None:
    """Requesting provenance for a non-existent entity returns 404."""
    resp = await client.get(
        f"/v1/tenants/{TENANT_ID}/entities/{NONEXISTENT_ID}/provenance"
    )
    assert resp.status_code == 404
    data = resp.json()
    assert "not found" in data["detail"].lower()


# ---------------------------------------------------------------------------
# 5. Provenance includes rules applied
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_provenance_includes_rules(client: AsyncClient) -> None:
    """Rules applied should be extracted from the entity's properties."""
    resp = await client.get(
        f"/v1/tenants/{TENANT_ID}/entities/{ENTITY_A_ID}/provenance"
    )
    assert resp.status_code == 200
    data = resp.json()

    rules = data["rules_applied"]
    assert len(rules) == 2

    rule_ids = [r["rule_id"] for r in rules]
    assert "scope-match-apex" in rule_ids
    assert "whois-org-match" in rule_ids

    # Check the match rule's details
    scope_rule = next(r for r in rules if r["rule_id"] == "scope-match-apex")
    assert scope_rule["outcome"] == "match"
    assert scope_rule["confidence_delta"] == pytest.approx(0.3)


# ---------------------------------------------------------------------------
# 6. Entity with no properties returns empty observations/rules
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_provenance_empty_properties(client: AsyncClient) -> None:
    """An entity with empty properties should return empty lists
    for observations (from properties) and rules, but may include
    relationship-derived observations."""
    resp = await client.get(
        f"/v1/tenants/{TENANT_ID}/entities/{ENTITY_B_ID}/provenance"
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["entity_identifier"] == "93.184.216.34"
    assert data["entity_type"] == "ip_address"
    assert data["rules_applied"] == []

    # Entity B has a relationship (incoming from A), so it should have
    # at least one relationship-derived observation
    assert len(data["relationships"]) >= 1
    rel = data["relationships"][0]
    assert rel["edge_type"] == "resolves_to"
    assert rel["target_identifier"] == "example.com"
    assert rel["target_type"] == "domain"


# ---------------------------------------------------------------------------
# 7. Cross-tenant invisibility
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_provenance_cross_tenant_404(client: AsyncClient) -> None:
    """Requesting provenance under a different tenant returns 404
    (cross-tenant invisibility per ADR-007)."""
    resp = await client.get(
        f"/v1/tenants/{OTHER_TENANT_ID}/entities/{ENTITY_A_ID}/provenance"
    )
    assert resp.status_code == 404
