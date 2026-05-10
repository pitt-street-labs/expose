"""Integration tests for ``IncidentalDataPruner`` (closes v1 deliverable #31).

Each test runs against a real Postgres via the ``pg_container`` fixture from
``tests/conftest.py``. We pay the testcontainers tax instead of mocking
because the contract under test is *the SQL DELETE* — its scoping, its
predicate, its rowcount semantics — none of which a mock would faithfully
reproduce.

The schema is created via ``Base.metadata.create_all`` per test (function
scope) so each test gets an empty graph; the testcontainer itself is
session-scoped so we only pay container startup once.

All tests are marked ``@pytest.mark.integration`` so the unit-only loop
(``pytest -m "not integration"``) skips past them when Docker isn't
available.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

import pytest
import structlog
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from structlog.testing import LogCapture

from expose.db.models import Base, Entity, Tenant
from expose.maintenance import (
    DEFAULT_RETENTION_DAYS,
    IncidentalDataPruner,
    PruneResult,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _async_dsn(sync_url: str) -> str:
    """Convert testcontainers' sync DSN to an asyncpg DSN.

    ``PostgresContainer.get_connection_url()`` returns
    ``postgresql+psycopg2://...``; SQLAlchemy's async engine wants
    ``postgresql+asyncpg://...``. Both reach the same socket; only the driver
    differs.
    """
    for prefix in ("postgresql+psycopg2://", "postgresql+psycopg://", "postgresql://"):
        if sync_url.startswith(prefix):
            return "postgresql+asyncpg://" + sync_url[len(prefix) :]
    return sync_url


def _make_entity(
    *,
    tenant_id: UUID,
    attribution_status: str,
    last_observed_at: datetime,
    canonical_identifier: str | None = None,
) -> Entity:
    """Build an ``Entity`` row with the minimum-viable required fields.

    Tests vary only the three fields the pruner actually inspects
    (``tenant_id``, ``attribution_status``, ``last_observed_at``); everything
    else is held constant so failures point at the predicate, not at fixture
    drift.
    """
    return Entity(
        id=uuid4(),
        tenant_id=tenant_id,
        entity_type="Domain",
        canonical_identifier=canonical_identifier or f"example-{uuid4().hex[:8]}.test",
        properties={},
        attribution_status=attribution_status,
        attribution_confidence=Decimal("0.500"),
        first_observed_at=last_observed_at,
        last_observed_at=last_observed_at,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def session_factory(
    pg_container: Any,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Build a fresh schema in the testcontainer and yield an async session
    factory bound to it.

    Function-scoped so each test starts with an empty graph; we drop and
    recreate ``Base.metadata`` between runs rather than running per-test
    DELETEs (cheap because the schema is small and entirely in-memory pages
    for the testcontainer's lifetime).
    """
    dsn = _async_dsn(pg_container.get_connection_url())
    engine = create_async_engine(dsn, echo=False, future=True)

    # Reset between tests for hermetic state.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    try:
        yield factory
    finally:
        await engine.dispose()


@pytest.fixture
async def session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Yield a session committed at exit so seed data is durable for assertion
    queries inside the same test."""
    async with session_factory() as s:
        yield s
        await s.commit()


@pytest.fixture
def log_capture() -> Iterator[LogCapture]:
    """Capture structlog events emitted during the test, then restore the
    previous configuration.

    structlog config is process-global, so we save and restore around each
    test to avoid cross-test bleed.
    """
    cap = LogCapture()
    structlog.configure(processors=[cap])
    try:
        yield cap
    finally:
        structlog.reset_defaults()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_prune_removes_old_not_yours(
    session: AsyncSession,
) -> None:
    """Only ``not_yours`` rows past the cutoff are deleted; everything else stays.

    Seeds three entities for one tenant:
      (a) ``not_yours``, observed 35 days ago — should delete
      (b) ``not_yours``, observed 15 days ago — too recent, should remain
      (c) ``confirmed``, observed 35 days ago — wrong status, should remain
    """
    tenant_id = uuid4()
    now = datetime.now(tz=UTC)

    session.add(Tenant(id=tenant_id, name="t-only-not-yours"))
    a = _make_entity(
        tenant_id=tenant_id,
        attribution_status="not_yours",
        last_observed_at=now - timedelta(days=35),
    )
    b = _make_entity(
        tenant_id=tenant_id,
        attribution_status="not_yours",
        last_observed_at=now - timedelta(days=15),
    )
    c = _make_entity(
        tenant_id=tenant_id,
        attribution_status="confirmed",
        last_observed_at=now - timedelta(days=35),
    )
    session.add_all([a, b, c])
    await session.flush()
    a_id, b_id, c_id = a.id, b.id, c.id

    pruner = IncidentalDataPruner(session)
    result = await pruner.prune_tenant(tenant_id=tenant_id)
    await session.commit()
    # Raw ``text()`` DELETE bypasses the ORM identity map; expire so
    # subsequent ``session.get`` re-reads the database state.
    session.expire_all()

    assert result.deleted_count == 1
    assert result.retention_days == DEFAULT_RETENTION_DAYS
    assert result.tenant_id == tenant_id

    # (a) gone, (b) and (c) survive.
    assert (await session.get(Entity, a_id)) is None
    assert (await session.get(Entity, b_id)) is not None
    assert (await session.get(Entity, c_id)) is not None


@pytest.mark.asyncio
async def test_prune_idempotent(session: AsyncSession) -> None:
    """A second prune immediately after the first deletes zero rows.

    Idempotency is the central operational property — schedulers may double-fire,
    operators may re-run by hand, and the contract must hold either way.
    """
    tenant_id = uuid4()
    now = datetime.now(tz=UTC)

    session.add(Tenant(id=tenant_id, name="t-idempotent"))
    session.add_all(
        _make_entity(
            tenant_id=tenant_id,
            attribution_status="not_yours",
            last_observed_at=now - timedelta(days=40),
        )
        for _ in range(3)
    )
    await session.flush()

    pruner = IncidentalDataPruner(session)
    first = await pruner.prune_tenant(tenant_id=tenant_id)
    await session.commit()

    second = await pruner.prune_tenant(tenant_id=tenant_id)
    await session.commit()

    assert first.deleted_count == 3
    assert second.deleted_count == 0


@pytest.mark.asyncio
async def test_prune_per_tenant(session: AsyncSession) -> None:
    """Pruning tenant A leaves tenant B's expired ``not_yours`` rows untouched.

    This is the ADR-007 isolation contract restated for the pruning code path:
    no global sweeps, ever. A regression here would silently leak across
    tenants — exactly the failure mode the test catches.
    """
    tenant_a, tenant_b = uuid4(), uuid4()
    now = datetime.now(tz=UTC)
    old = now - timedelta(days=60)

    session.add(Tenant(id=tenant_a, name="t-a"))
    session.add(Tenant(id=tenant_b, name="t-b"))
    session.add_all(
        _make_entity(
            tenant_id=tenant_a,
            attribution_status="not_yours",
            last_observed_at=old,
        )
        for _ in range(5)
    )
    session.add_all(
        _make_entity(
            tenant_id=tenant_b,
            attribution_status="not_yours",
            last_observed_at=old,
        )
        for _ in range(3)
    )
    await session.flush()

    pruner = IncidentalDataPruner(session)
    result = await pruner.prune_tenant(tenant_id=tenant_a)
    await session.commit()

    assert result.deleted_count == 5

    # Tenant B's count must be unchanged.
    from sqlalchemy import select  # noqa: PLC0415

    rows_b = (
        await session.execute(select(Entity).where(Entity.tenant_id == tenant_b))
    ).scalars().all()
    assert len(rows_b) == 3


@pytest.mark.asyncio
async def test_prune_with_custom_retention(session: AsyncSession) -> None:
    """A 7-day retention prunes entities ``>= 7`` days old; younger ones survive.

    Verifies the constructor parameter is honored end-to-end (cutoff
    arithmetic + DELETE predicate + structured-log payload).
    """
    tenant_id = uuid4()
    now = datetime.now(tz=UTC)

    session.add(Tenant(id=tenant_id, name="t-7d"))
    too_old = _make_entity(
        tenant_id=tenant_id,
        attribution_status="not_yours",
        last_observed_at=now - timedelta(days=10),
    )
    too_young = _make_entity(
        tenant_id=tenant_id,
        attribution_status="not_yours",
        last_observed_at=now - timedelta(days=3),
    )
    session.add_all([too_old, too_young])
    await session.flush()
    too_old_id, too_young_id = too_old.id, too_young.id

    pruner = IncidentalDataPruner(session, retention_days=7)
    result = await pruner.prune_tenant(tenant_id=tenant_id)
    await session.commit()
    session.expire_all()  # raw DELETE bypasses identity map

    assert result.deleted_count == 1
    assert result.retention_days == 7
    assert (await session.get(Entity, too_old_id)) is None
    assert (await session.get(Entity, too_young_id)) is not None


@pytest.mark.asyncio
async def test_prune_emits_structured_log(
    session: AsyncSession,
    log_capture: LogCapture,
) -> None:
    """Pruning emits exactly one ``incidental_data_pruned`` event with the
    documented fields and **no entity identifiers** in the payload.

    Logging entity IDs we just deleted would re-create the very record
    ADR-008 §Layer 3 told us to drop. This test is the regression guard for
    that minimization contract.
    """
    tenant_id = uuid4()
    now = datetime.now(tz=UTC)

    session.add(Tenant(id=tenant_id, name="t-log"))
    seeded_ids: list[UUID] = []
    for _ in range(2):
        e = _make_entity(
            tenant_id=tenant_id,
            attribution_status="not_yours",
            last_observed_at=now - timedelta(days=45),
        )
        session.add(e)
        seeded_ids.append(e.id)
    await session.flush()

    pruner = IncidentalDataPruner(session)
    await pruner.prune_tenant(tenant_id=tenant_id)
    await session.commit()

    # Exactly one matching event.
    matching = [e for e in log_capture.entries if e.get("event") == "incidental_data_pruned"]
    assert len(matching) == 1, log_capture.entries
    event = matching[0]

    # Required fields are present and correct.
    assert event["tenant_id"] == str(tenant_id)
    assert event["deleted_count"] == 2
    assert event["retention_days"] == DEFAULT_RETENTION_DAYS
    assert "cutoff_at" in event

    # Minimization: NO entity identifiers leak into the audit payload.
    payload_text = repr(event)
    for entity_id in seeded_ids:
        # Both raw UUID hex and dashed forms must be absent.
        assert str(entity_id) not in payload_text
        assert entity_id.hex not in payload_text


@pytest.mark.asyncio
async def test_prune_clock_injection(session: AsyncSession) -> None:
    """A frozen clock causes the cutoff to be computed from the injected time
    (not wall-clock ``now``).

    The clock parameter exists exactly for deterministic testing and replay
    scenarios; a regression here would silently break CI determinism.
    """
    tenant_id = uuid4()
    # Pin "now" to a known instant; cutoff at default 30d should be
    # 2026-04-10 12:00:00+00:00.
    fixed_now = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)
    expected_cutoff = fixed_now - timedelta(days=DEFAULT_RETENTION_DAYS)

    session.add(Tenant(id=tenant_id, name="t-clock"))
    # One row dated 1 second before the cutoff (must delete) and one 1 second
    # after (must survive).
    e_old = _make_entity(
        tenant_id=tenant_id,
        attribution_status="not_yours",
        last_observed_at=expected_cutoff - timedelta(seconds=1),
    )
    e_young = _make_entity(
        tenant_id=tenant_id,
        attribution_status="not_yours",
        last_observed_at=expected_cutoff + timedelta(seconds=1),
    )
    session.add_all([e_old, e_young])
    await session.flush()
    e_old_id, e_young_id = e_old.id, e_young.id

    pruner = IncidentalDataPruner(session, clock=lambda: fixed_now)
    result = await pruner.prune_tenant(tenant_id=tenant_id)
    await session.commit()
    session.expire_all()  # raw DELETE bypasses identity map

    assert result.cutoff_at == expected_cutoff
    assert result.deleted_count == 1
    assert (await session.get(Entity, e_old_id)) is None
    assert (await session.get(Entity, e_young_id)) is not None


def test_prune_result_is_frozen() -> None:
    """``PruneResult`` is immutable — defensive guard against callers mutating
    audit-log records after the fact."""
    pr = PruneResult(
        tenant_id=uuid4(),
        deleted_count=0,
        cutoff_at=datetime.now(tz=UTC),
        retention_days=DEFAULT_RETENTION_DAYS,
    )
    with pytest.raises((AttributeError, TypeError)):
        pr.deleted_count = 99  # type: ignore[misc]


def test_prune_rejects_non_positive_retention() -> None:
    """``retention_days <= 0`` would delete every ``not_yours`` row — almost
    certainly a misconfiguration. The constructor refuses it loudly so the
    error surfaces at startup, not in production."""
    # The session arg is irrelevant here — validation runs before any DB call.
    fake_session: Any = object()
    with pytest.raises(ValueError, match="retention_days must be positive"):
        IncidentalDataPruner(fake_session, retention_days=0)
    with pytest.raises(ValueError, match="retention_days must be positive"):
        IncidentalDataPruner(fake_session, retention_days=-1)
