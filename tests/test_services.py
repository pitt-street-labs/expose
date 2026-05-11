"""Tests for the service layer (``expose.services``).

Tests each service class independently with mock sessions, verifying that
business logic is correctly extracted from the API route handlers.

Covers:
 - ProvenanceService: entity fetch, relationship query, observation
   extraction, rule extraction, correlation building, not-found case
 - FindingsService: scored findings, takeover findings, placeholder
   fallback, filtering, sorting, ranking
 - RunService: run creation, listing, entity queries, not-found cases

Uses in-memory SQLite (``aiosqlite``) for ProvenanceService and RunService
tests that need real DB queries. FindingsService tests use mock session
factories (matching the existing test_findings_api.py pattern).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

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
# SQLite helpers (shared with test_provenance_api.py / test_runs_api.py)
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
# Seed helpers
# ---------------------------------------------------------------------------


async def _seed_provenance_data(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Insert tenant, two entities, and a relationship for provenance tests."""
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


async def _seed_tenant(
    session_factory: async_sessionmaker[AsyncSession],
    name: str,
    tenant_id: UUID | None = None,
) -> UUID:
    """Insert a tenant row and return its id."""
    tid = tenant_id or uuid4()
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


# ============================================================================
# ProvenanceService tests
# ============================================================================


class TestProvenanceService:
    """Tests for ProvenanceService with real SQLite sessions."""

    @pytest.mark.anyio
    async def test_get_provenance_returns_full_chain(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Happy path: entity with rules, observations, and relationships."""
        from expose.services.provenance_service import ProvenanceService

        await _seed_provenance_data(session_factory)

        async with session_factory() as session:
            service = ProvenanceService(session)
            result = await service.get_provenance(TENANT_ID, ENTITY_A_ID)

        assert result is not None
        assert result.entity_id == str(ENTITY_A_ID)
        assert result.entity_identifier == "example.com"
        assert result.entity_type == "domain"
        assert result.attribution_status == "high"
        assert result.attribution_confidence == pytest.approx(0.7, abs=0.01)

        # Observations
        collector_ids = [obs.collector_id for obs in result.observations]
        assert "dns-brute" in collector_ids
        assert "active-dns" in collector_ids

        # Rules
        assert len(result.rules_applied) == 2
        rule_ids = [r.rule_id for r in result.rules_applied]
        assert "scope-match-apex" in rule_ids
        assert "whois-org-match" in rule_ids

        # Relationships
        assert len(result.relationships) >= 1
        resolves = [r for r in result.relationships if r.edge_type == "resolves_to"]
        assert len(resolves) == 1
        assert resolves[0].target_identifier == "93.184.216.34"

        # Correlation
        assert result.correlation is not None
        assert len(result.correlation.evidence) >= 2
        assert result.correlation.pivot_dimensions_checked == 12

    @pytest.mark.anyio
    async def test_get_provenance_returns_none_for_missing_entity(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Entity not found returns None (caller handles 404)."""
        from expose.services.provenance_service import ProvenanceService

        await _seed_provenance_data(session_factory)

        async with session_factory() as session:
            service = ProvenanceService(session)
            result = await service.get_provenance(TENANT_ID, NONEXISTENT_ID)

        assert result is None

    @pytest.mark.anyio
    async def test_get_provenance_cross_tenant_returns_none(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Cross-tenant request returns None (ADR-007 invisibility)."""
        from expose.services.provenance_service import ProvenanceService

        await _seed_provenance_data(session_factory)

        async with session_factory() as session:
            service = ProvenanceService(session)
            result = await service.get_provenance(OTHER_TENANT_ID, ENTITY_A_ID)

        assert result is None

    @pytest.mark.anyio
    async def test_get_provenance_empty_properties(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Entity with empty properties returns sparse provenance (no rules)."""
        from expose.services.provenance_service import ProvenanceService

        await _seed_provenance_data(session_factory)

        async with session_factory() as session:
            service = ProvenanceService(session)
            result = await service.get_provenance(TENANT_ID, ENTITY_B_ID)

        assert result is not None
        assert result.entity_identifier == "93.184.216.34"
        assert result.rules_applied == []
        # Entity B has an incoming relationship from A
        assert len(result.relationships) >= 1

    @pytest.mark.anyio
    async def test_correlation_evidence_from_rules(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Correlation evidence should be built from rules_applied."""
        from expose.services.provenance_service import ProvenanceService

        await _seed_provenance_data(session_factory)

        async with session_factory() as session:
            service = ProvenanceService(session)
            result = await service.get_provenance(TENANT_ID, ENTITY_A_ID)

        assert result is not None
        assert result.correlation is not None
        # Entity A has 2 rules + observation count evidence (2 collectors)
        assert len(result.correlation.evidence) >= 2
        assert isinstance(result.correlation.total_confidence, float)

    @pytest.mark.anyio
    async def test_correlation_evidence_from_relationships(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Entity with no rules falls back to relationship-derived evidence."""
        from expose.services.provenance_service import ProvenanceService

        await _seed_provenance_data(session_factory)

        async with session_factory() as session:
            service = ProvenanceService(session)
            result = await service.get_provenance(TENANT_ID, ENTITY_B_ID)

        assert result is not None
        assert result.correlation is not None
        dimensions = [ev.dimension for ev in result.correlation.evidence]
        assert "dns" in dimensions


# ============================================================================
# FindingsService tests
# ============================================================================


def _make_entity_row(
    canonical_identifier: str,
    entity_type: str = "domain",
    properties: dict[str, Any] | None = None,
) -> MagicMock:
    """Build a mock Entity ORM row."""
    entity = MagicMock()
    entity.id = uuid4()
    entity.tenant_id = TENANT_ID
    entity.entity_type = entity_type
    entity.canonical_identifier = canonical_identifier
    entity.properties = properties or {}
    entity.attribution_status = "unattributed"
    entity.attribution_confidence = Decimal("0.000")
    entity.last_observed_at = datetime.now(tz=UTC)
    return entity


def _make_scored_entity(
    canonical_identifier: str,
    score: int,
    tier: str = "low",
) -> MagicMock:
    """Build a mock Entity with _lead_score and _priority_tier."""
    return _make_entity_row(
        canonical_identifier=canonical_identifier,
        properties={
            "_lead_score": score,
            "_priority_tier": tier,
            "_collector_id": "test-collector",
        },
    )


def _make_takeover_entity(
    canonical_identifier: str,
    risk_level: str = "high",
    provider: str = "aws-s3",
    cname_target: str = "myapp.s3.amazonaws.com",
) -> MagicMock:
    """Build a mock Entity with _takeover_risk property."""
    return _make_entity_row(
        canonical_identifier=canonical_identifier,
        properties={
            "_takeover_risk": {
                "risk_level": risk_level,
                "provider": provider,
                "cname_target": cname_target,
            },
        },
    )


def _mock_session_factory(entities: list[Any]):
    """Build a mock async session factory that returns the given entities."""
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = entities
    mock_result.scalars.return_value = mock_scalars

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    @asynccontextmanager
    async def factory():
        yield mock_session

    return factory


class TestFindingsService:
    """Tests for FindingsService with mock session factories."""

    @pytest.mark.anyio
    async def test_get_scored_findings_returns_scored_entities(self) -> None:
        """Entities with _lead_score are returned as scored findings."""
        from expose.services.findings_service import FindingsService

        entities = [
            _make_scored_entity("critical.example.com", 90, "critical"),
            _make_scored_entity("high.example.com", 55, "high"),
            _make_entity_row("unscored.example.com"),  # no _lead_score
        ]
        service = FindingsService(_mock_session_factory(entities))
        findings = await service.get_scored_findings(TENANT_ID)

        assert len(findings) == 2
        # Sorted by score descending
        assert findings[0].score == 90
        assert findings[1].score == 55

    @pytest.mark.anyio
    async def test_get_scored_findings_empty_when_no_factory(self) -> None:
        """Returns empty list when session_factory is None."""
        from expose.services.findings_service import FindingsService

        service = FindingsService(None)
        findings = await service.get_scored_findings(TENANT_ID)
        assert findings == []

    @pytest.mark.anyio
    async def test_get_scored_findings_skips_invalid_scores(self) -> None:
        """Entities with non-numeric _lead_score are skipped."""
        from expose.services.findings_service import FindingsService

        entities = [
            _make_entity_row("bad.example.com", properties={"_lead_score": "not_a_number"}),
            _make_scored_entity("good.example.com", 42, "medium"),
        ]
        service = FindingsService(_mock_session_factory(entities))
        findings = await service.get_scored_findings(TENANT_ID)

        assert len(findings) == 1
        assert findings[0].entity_identifier == "good.example.com"

    @pytest.mark.anyio
    async def test_get_takeover_findings_returns_takeover_entities(self) -> None:
        """Entities with _takeover_risk are returned as takeover findings."""
        from expose.services.findings_service import FindingsService

        entities = [
            _make_takeover_entity("vuln.example.com", "critical", "aws-s3"),
            _make_entity_row("safe.example.com"),  # no _takeover_risk
        ]
        service = FindingsService(_mock_session_factory(entities))
        findings = await service.get_takeover_findings(TENANT_ID)

        assert len(findings) == 1
        assert findings[0].entity_identifier == "vuln.example.com"
        assert findings[0].score == 98  # critical risk_level
        assert "dangling_cname" in [s.signal for s in findings[0].signals]

    @pytest.mark.anyio
    async def test_get_takeover_findings_empty_when_no_factory(self) -> None:
        """Returns empty list when session_factory is None."""
        from expose.services.findings_service import FindingsService

        service = FindingsService(None)
        findings = await service.get_takeover_findings(TENANT_ID)
        assert findings == []

    @pytest.mark.anyio
    async def test_get_all_findings_real_data(self) -> None:
        """get_all_findings returns real data with is_placeholder=False."""
        from expose.services.findings_service import FindingsService

        entities = [
            _make_scored_entity("a.example.com", 90, "critical"),
            _make_scored_entity("b.example.com", 60, "high"),
        ]
        service = FindingsService(_mock_session_factory(entities))
        result = await service.get_all_findings(TENANT_ID, limit=20, min_score=0)

        assert result.is_placeholder is False
        assert len(result.findings) == 2
        assert result.findings[0].score == 90
        assert result.findings[0].rank == 1
        assert result.findings[1].rank == 2

    @pytest.mark.anyio
    async def test_get_all_findings_placeholder_fallback(self) -> None:
        """Falls back to placeholder when no scored entities exist."""
        from expose.services.findings_service import FindingsService

        entities = [_make_entity_row("unscored.example.com")]
        service = FindingsService(_mock_session_factory(entities))
        result = await service.get_all_findings(TENANT_ID, limit=20, min_score=0)

        assert result.is_placeholder is True
        assert len(result.findings) > 0

    @pytest.mark.anyio
    async def test_get_all_findings_no_session_factory(self) -> None:
        """Falls back to placeholder when session_factory is None."""
        from expose.services.findings_service import FindingsService

        service = FindingsService(None)
        result = await service.get_all_findings(TENANT_ID, limit=20, min_score=0)

        assert result.is_placeholder is True
        assert len(result.findings) > 0

    @pytest.mark.anyio
    async def test_get_all_findings_min_score_filter(self) -> None:
        """min_score filters out low-scoring findings."""
        from expose.services.findings_service import FindingsService

        entities = [
            _make_scored_entity("high.example.com", 90, "critical"),
            _make_scored_entity("low.example.com", 15, "low"),
        ]
        service = FindingsService(_mock_session_factory(entities))
        result = await service.get_all_findings(TENANT_ID, limit=20, min_score=50)

        assert len(result.findings) == 1
        assert result.findings[0].score >= 50

    @pytest.mark.anyio
    async def test_get_all_findings_limit_applied(self) -> None:
        """limit caps the number of returned findings."""
        from expose.services.findings_service import FindingsService

        entities = [
            _make_scored_entity("a.example.com", 90, "critical"),
            _make_scored_entity("b.example.com", 80, "critical"),
            _make_scored_entity("c.example.com", 70, "high"),
        ]
        service = FindingsService(_mock_session_factory(entities))
        result = await service.get_all_findings(TENANT_ID, limit=2, min_score=0)

        assert len(result.findings) == 2
        assert result.total_scored == 3

    @pytest.mark.anyio
    async def test_get_all_findings_combines_takeover_and_scored(self) -> None:
        """Both takeover and scored findings are combined."""
        from expose.services.findings_service import FindingsService

        entities = [
            _make_scored_entity("scored.example.com", 55, "high"),
            _make_takeover_entity("takeover.example.com", "critical"),
        ]
        service = FindingsService(_mock_session_factory(entities))
        result = await service.get_all_findings(TENANT_ID, limit=20, min_score=0)

        assert result.is_placeholder is False
        identifiers = [f.entity_identifier for f in result.findings]
        assert "scored.example.com" in identifiers
        assert "takeover.example.com" in identifiers

    @pytest.mark.anyio
    async def test_get_all_findings_ranks_sequential(self) -> None:
        """Ranks should be sequential starting at 1."""
        from expose.services.findings_service import FindingsService

        entities = [
            _make_scored_entity("a.example.com", 90, "critical"),
            _make_scored_entity("b.example.com", 60, "high"),
            _make_scored_entity("c.example.com", 30, "low"),
        ]
        service = FindingsService(_mock_session_factory(entities))
        result = await service.get_all_findings(TENANT_ID, limit=20, min_score=0)

        ranks = [f.rank for f in result.findings]
        assert ranks == [1, 2, 3]


# ============================================================================
# RunService tests
# ============================================================================


class TestRunService:
    """Tests for RunService with real SQLite sessions."""

    @pytest.mark.anyio
    async def test_list_runs_empty(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Empty tenant returns empty run list."""
        from expose.services.run_service import RunService

        tid = await _seed_tenant(session_factory, "empty-runs-svc")

        async with session_factory() as session:
            service = RunService(session)
            result = await service.list_runs(tid)

        assert result.runs == []
        assert result.total == 0

    @pytest.mark.anyio
    async def test_list_runs_with_data(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Returns seeded runs for the tenant."""
        from expose.db.models import Run
        from expose.services.run_service import RunService

        tid = await _seed_tenant(session_factory, "runs-data-svc")

        # Seed runs directly
        async with session_factory() as session:
            run1 = Run(
                id=uuid4(),
                tenant_id=tid,
                pipeline_version="1.0.0",
                state="completed",
                started_at=datetime.now(UTC),
            )
            run2 = Run(
                id=uuid4(),
                tenant_id=tid,
                pipeline_version="1.0.0",
                state="pending",
                started_at=datetime.now(UTC),
            )
            session.add(run1)
            session.add(run2)
            await session.commit()

        async with session_factory() as session:
            service = RunService(session)
            result = await service.list_runs(tid)

        assert result.total == 2
        states = {r.state for r in result.runs}
        assert states == {"completed", "pending"}

    @pytest.mark.anyio
    async def test_get_run_found(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Existing run is returned."""
        from expose.db.models import Run
        from expose.services.run_service import RunService

        tid = await _seed_tenant(session_factory, "get-run-svc")
        rid = uuid4()

        async with session_factory() as session:
            run = Run(
                id=rid,
                tenant_id=tid,
                pipeline_version="1.0.0",
                state="running",
                started_at=datetime.now(UTC),
            )
            session.add(run)
            await session.commit()

        async with session_factory() as session:
            service = RunService(session)
            result = await service.get_run(tid, rid)

        assert result is not None
        assert result.id == rid
        assert result.state == "running"

    @pytest.mark.anyio
    async def test_get_run_not_found(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Non-existent run returns None."""
        from expose.services.run_service import RunService

        tid = await _seed_tenant(session_factory, "no-run-svc")

        async with session_factory() as session:
            service = RunService(session)
            result = await service.get_run(tid, NONEXISTENT_ID)

        assert result is None

    @pytest.mark.anyio
    async def test_get_run_cross_tenant_returns_none(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Cross-tenant run query returns None."""
        from expose.db.models import Run
        from expose.services.run_service import RunService

        tid_a = await _seed_tenant(session_factory, "run-cross-a-svc")
        tid_b = await _seed_tenant(session_factory, "run-cross-b-svc")
        rid = uuid4()

        async with session_factory() as session:
            run = Run(
                id=rid,
                tenant_id=tid_a,
                pipeline_version="1.0.0",
                state="completed",
                started_at=datetime.now(UTC),
            )
            session.add(run)
            await session.commit()

        async with session_factory() as session:
            service = RunService(session)
            result = await service.get_run(tid_b, rid)

        assert result is None

    @pytest.mark.anyio
    async def test_list_entities_empty(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Empty tenant returns empty entity list."""
        from expose.services.run_service import RunService

        tid = await _seed_tenant(session_factory, "empty-entities-svc")

        async with session_factory() as session:
            service = RunService(session)
            result = await service.list_entities(tid)

        assert result.entities == []
        assert result.total == 0

    @pytest.mark.anyio
    async def test_list_entities_with_data(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Returns seeded entities for the tenant."""
        from expose.services.run_service import RunService

        tid = await _seed_tenant(session_factory, "entities-data-svc")

        async with session_factory() as session:
            now = datetime.now(UTC)
            e1 = Entity(
                id=uuid4(),
                tenant_id=tid,
                entity_type="domain",
                canonical_identifier="svc-a.example.com",
                properties={},
                attribution_status="confirmed",
                attribution_confidence=Decimal("0.950"),
                first_observed_at=now,
                last_observed_at=now,
            )
            e2 = Entity(
                id=uuid4(),
                tenant_id=tid,
                entity_type="ip_address",
                canonical_identifier="192.0.2.1",
                properties={},
                attribution_status="unattributed",
                attribution_confidence=Decimal("0.000"),
                first_observed_at=now,
                last_observed_at=now,
            )
            session.add(e1)
            session.add(e2)
            await session.commit()

        async with session_factory() as session:
            service = RunService(session)
            result = await service.list_entities(tid)

        assert result.total == 2
        types = {e.entity_type for e in result.entities}
        assert types == {"domain", "ip_address"}

    @pytest.mark.anyio
    async def test_get_entity_found(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Existing entity is returned."""
        from expose.services.run_service import RunService

        tid = await _seed_tenant(session_factory, "get-entity-svc")
        eid = uuid4()

        async with session_factory() as session:
            now = datetime.now(UTC)
            entity = Entity(
                id=eid,
                tenant_id=tid,
                entity_type="domain",
                canonical_identifier="get-me.example.com",
                properties={},
                attribution_status="confirmed",
                attribution_confidence=Decimal("0.950"),
                first_observed_at=now,
                last_observed_at=now,
            )
            session.add(entity)
            await session.commit()

        async with session_factory() as session:
            service = RunService(session)
            result = await service.get_entity(tid, eid)

        assert result is not None
        assert result.id == eid
        assert result.canonical_identifier == "get-me.example.com"

    @pytest.mark.anyio
    async def test_get_entity_not_found(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Non-existent entity returns None."""
        from expose.services.run_service import RunService

        tid = await _seed_tenant(session_factory, "no-entity-svc")

        async with session_factory() as session:
            service = RunService(session)
            result = await service.get_entity(tid, NONEXISTENT_ID)

        assert result is None

    @pytest.mark.anyio
    async def test_get_entity_cross_tenant_returns_none(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Cross-tenant entity query returns None."""
        from expose.services.run_service import RunService

        tid_a = await _seed_tenant(session_factory, "entity-cross-a-svc")
        tid_b = await _seed_tenant(session_factory, "entity-cross-b-svc")
        eid = uuid4()

        async with session_factory() as session:
            now = datetime.now(UTC)
            entity = Entity(
                id=eid,
                tenant_id=tid_a,
                entity_type="domain",
                canonical_identifier="private.example.com",
                properties={},
                attribution_status="confirmed",
                attribution_confidence=Decimal("0.950"),
                first_observed_at=now,
                last_observed_at=now,
            )
            session.add(entity)
            await session.commit()

        async with session_factory() as session:
            service = RunService(session)
            result = await service.get_entity(tid_b, eid)

        assert result is None

    @pytest.mark.anyio
    async def test_list_runs_tenant_scoped(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Runs are scoped to the requesting tenant."""
        from expose.db.models import Run
        from expose.services.run_service import RunService

        tid_a = await _seed_tenant(session_factory, "scope-runs-a-svc")
        tid_b = await _seed_tenant(session_factory, "scope-runs-b-svc")

        async with session_factory() as session:
            session.add(Run(
                id=uuid4(), tenant_id=tid_a, pipeline_version="1.0.0",
                state="completed", started_at=datetime.now(UTC),
            ))
            session.add(Run(
                id=uuid4(), tenant_id=tid_b, pipeline_version="1.0.0",
                state="pending", started_at=datetime.now(UTC),
            ))
            await session.commit()

        async with session_factory() as session:
            service = RunService(session)
            result_a = await service.list_runs(tid_a)

        assert result_a.total == 1
        assert result_a.runs[0].state == "completed"

        async with session_factory() as session:
            service = RunService(session)
            result_b = await service.list_runs(tid_b)

        assert result_b.total == 1
        assert result_b.runs[0].state == "pending"
