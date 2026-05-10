"""Cross-tenant isolation tests (per ADR-007; closes issue #28).

Validates that tenant A cannot access tenant B's data through any path in the
data layer, collector framework, secrets backend, or broker message types.
These tests replace the 7 placeholder (skipped) tests with real implementations
while preserving the sanity fixture and marker conventions.

CI MUST run any test marked ``isolation`` regardless of PR scope; failures block merge.
"""
from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.tiers import (
    EntityAttributionView,
    TenantAuthorizationScope,
    is_tier_3_dispatch_allowed,
)
from expose.db.models import Base, Tenant
from expose.repositories import (
    EntityRepository,
    RelationshipRepository,
    RunRepository,
)
from expose.secrets.backend import SecretNotFoundError
from expose.secrets.memory_backend import InMemoryBackend
from expose.types.canonical import AttributionTier, CollectorStatus
from expose.types.shared import EntityId, RunId, TenantId

pytestmark = pytest.mark.isolation


# Synthetic tenants used across isolation tests. Real tenants get their UUIDs
# from the lifecycle API (Sprint 3+); these are stable test fixtures.
TENANT_A = TenantId(UUID("018f1f00-0000-7000-8000-00000000A001"))
TENANT_B = TenantId(UUID("018f1f00-0000-7000-8000-00000000B002"))


@pytest.fixture
def tenant_a() -> TenantId:
    return TENANT_A


@pytest.fixture
def tenant_b() -> TenantId:
    return TENANT_B


def test_synthetic_tenant_ids_are_distinct(tenant_a: TenantId, tenant_b: TenantId) -> None:
    """Sanity: the test fixtures themselves don't accidentally collide."""
    assert tenant_a != tenant_b


# === Database fixture helpers (shared by integration tests 1-3) ==============


def _asyncpg_url(sync_url: str) -> str:
    """Translate testcontainers' sync SQLAlchemy URL to an asyncpg DSN."""
    for prefix in ("postgresql+psycopg2://", "postgresql+psycopg://", "postgresql://"):
        if sync_url.startswith(prefix):
            return "postgresql+asyncpg://" + sync_url[len(prefix) :]
    return sync_url


@pytest_asyncio.fixture
async def iso_engine(pg_container: Any) -> AsyncEngine:
    """Per-test engine bound to the session-scoped Postgres container.

    Schema is created and torn down so each test gets a clean DB without
    paying the price of a fresh container per test.
    """
    url = _asyncpg_url(pg_container.get_connection_url())
    engine = create_async_engine(url, echo=False, future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield engine  # type: ignore[misc]
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()


@pytest_asyncio.fixture
async def iso_session_factory(
    iso_engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=iso_engine, expire_on_commit=False, autoflush=False
    )


@pytest_asyncio.fixture
async def iso_tenant_a(
    iso_session_factory: async_sessionmaker[AsyncSession],
) -> TenantId:
    """Insert tenant A into the DB and return its id."""
    async with iso_session_factory() as session:
        session.add(Tenant(id=TENANT_A, name="iso-tenant-a"))
        await session.commit()
    return TENANT_A


@pytest_asyncio.fixture
async def iso_tenant_b(
    iso_session_factory: async_sessionmaker[AsyncSession],
) -> TenantId:
    """Insert tenant B into the DB and return its id."""
    async with iso_session_factory() as session:
        session.add(Tenant(id=TENANT_B, name="iso-tenant-b"))
        await session.commit()
    return TENANT_B


def _props(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    base: dict[str, Any] = {"source": "isolation-test"}
    if extra:
        base.update(extra)
    return base


# === Test 1: Entity repository tenant isolation =============================


@pytest.mark.integration
async def test_entity_repo_tenant_isolation(
    iso_session_factory: async_sessionmaker[AsyncSession],
    iso_tenant_a: TenantId,
    iso_tenant_b: TenantId,
) -> None:
    """ADR-007 core invariant: an entity written under tenant A is invisible
    to tenant B across get_by_id, find_by_canonical, and list_for_tenant."""

    # Write an entity under tenant A.
    async with iso_session_factory() as session:
        repo = EntityRepository(session)
        entity_a = await repo.create_or_update(
            tenant_id=iso_tenant_a,
            entity_type="Domain",
            canonical_identifier="isolated.example.com",
            properties=_props({"owner": "tenant-a"}),
            attribution_status="confirmed",
            attribution_confidence=Decimal("0.950"),
        )
        await session.commit()

    entity_a_id = EntityId(entity_a.id)

    # Tenant B: get_by_id with the exact UUID must return None.
    async with iso_session_factory() as session:
        repo_b = EntityRepository(session)
        leaked_by_id = await repo_b.get_by_id(
            tenant_id=iso_tenant_b, entity_id=entity_a_id
        )
        assert leaked_by_id is None, (
            "tenant B must not read tenant A's entity via get_by_id"
        )

    # Tenant B: find_by_canonical with the same type+identifier must return None.
    async with iso_session_factory() as session:
        repo_b = EntityRepository(session)
        leaked_by_canonical = await repo_b.find_by_canonical(
            tenant_id=iso_tenant_b,
            entity_type="Domain",
            canonical_identifier="isolated.example.com",
        )
        assert leaked_by_canonical is None, (
            "tenant B must not read tenant A's entity via find_by_canonical"
        )

    # Tenant B: list_for_tenant must return empty.
    async with iso_session_factory() as session:
        repo_b = EntityRepository(session)
        b_entities = await repo_b.list_for_tenant(tenant_id=iso_tenant_b)
        assert len(b_entities) == 0, (
            "tenant B's list must be empty when only tenant A has data"
        )

    # Sanity: tenant A still sees its own entity through all three paths.
    async with iso_session_factory() as session:
        repo_a = EntityRepository(session)

        own_by_id = await repo_a.get_by_id(
            tenant_id=iso_tenant_a, entity_id=entity_a_id
        )
        assert own_by_id is not None, "tenant A must see its own entity"
        assert own_by_id.canonical_identifier == "isolated.example.com"

        own_by_canonical = await repo_a.find_by_canonical(
            tenant_id=iso_tenant_a,
            entity_type="Domain",
            canonical_identifier="isolated.example.com",
        )
        assert own_by_canonical is not None

        own_list = await repo_a.list_for_tenant(tenant_id=iso_tenant_a)
        assert len(own_list) == 1


# === Test 2: Relationship repository tenant isolation =======================


@pytest.mark.integration
async def test_relationship_repo_tenant_isolation(
    iso_session_factory: async_sessionmaker[AsyncSession],
    iso_tenant_a: TenantId,
    iso_tenant_b: TenantId,
) -> None:
    """ADR-007: relationships written under tenant A are invisible to tenant B,
    even when querying by the same entity UUIDs."""

    # Create two entities under tenant A to serve as edge endpoints.
    async with iso_session_factory() as session:
        ent_repo = EntityRepository(session)
        from_ent = await ent_repo.create_or_update(
            tenant_id=iso_tenant_a,
            entity_type="Domain",
            canonical_identifier="rel-from.example.com",
            properties=_props(),
            attribution_status="confirmed",
            attribution_confidence=Decimal("0.900"),
        )
        to_ent = await ent_repo.create_or_update(
            tenant_id=iso_tenant_a,
            entity_type="IP",
            canonical_identifier="192.0.2.1",
            properties=_props(),
            attribution_status="confirmed",
            attribution_confidence=Decimal("0.900"),
        )
        await session.commit()

    from_id = EntityId(from_ent.id)
    to_id = EntityId(to_ent.id)

    # Create a relationship under tenant A.
    async with iso_session_factory() as session:
        rel_repo = RelationshipRepository(session)
        edge = await rel_repo.create(
            tenant_id=iso_tenant_a,
            from_entity_id=from_id,
            to_entity_id=to_id,
            edge_type="resolves_to",
            confidence=Decimal("0.950"),
            observed_at=datetime.now(UTC),
            collector_id="test:iso-rel",
            evidence_ref="sha256:" + "a" * 64,
        )
        await session.commit()

    # Tenant B: querying for tenant A's entity ids must return empty.
    async with iso_session_factory() as session:
        rel_repo_b = RelationshipRepository(session)
        leaked_from = await rel_repo_b.find_for_entity(
            tenant_id=iso_tenant_b, entity_id=from_id, direction="both"
        )
        leaked_to = await rel_repo_b.find_for_entity(
            tenant_id=iso_tenant_b, entity_id=to_id, direction="both"
        )
        assert len(leaked_from) == 0, (
            "tenant B must not see tenant A's relationships (from-entity query)"
        )
        assert len(leaked_to) == 0, (
            "tenant B must not see tenant A's relationships (to-entity query)"
        )

    # Sanity: tenant A sees its relationship.
    async with iso_session_factory() as session:
        rel_repo_a = RelationshipRepository(session)
        own_rels = await rel_repo_a.find_for_entity(
            tenant_id=iso_tenant_a, entity_id=from_id, direction="out"
        )
        assert len(own_rels) == 1, "tenant A must see its own relationship"
        assert own_rels[0].id == edge.id


# === Test 3: Run repository tenant isolation ================================


@pytest.mark.integration
async def test_run_repo_tenant_isolation(
    iso_session_factory: async_sessionmaker[AsyncSession],
    iso_tenant_a: TenantId,
    iso_tenant_b: TenantId,
) -> None:
    """ADR-007: runs created under tenant A are invisible to tenant B via
    get_by_id and list_for_tenant; cross-tenant update_state raises LookupError."""

    # Create a run under tenant A.
    async with iso_session_factory() as session:
        run_repo = RunRepository(session)
        run_a = await run_repo.create(
            tenant_id=iso_tenant_a,
            pipeline_version="v0.1.0-iso",
            target_count=10,
        )
        await session.commit()

    run_a_id = RunId(run_a.id)

    # Tenant B: get_by_id must return None.
    async with iso_session_factory() as session:
        run_repo_b = RunRepository(session)
        leaked = await run_repo_b.get_by_id(
            tenant_id=iso_tenant_b, run_id=run_a_id
        )
        assert leaked is None, (
            "tenant B must not read tenant A's run via get_by_id"
        )

    # Tenant B: list_for_tenant must return empty.
    async with iso_session_factory() as session:
        run_repo_b = RunRepository(session)
        b_runs = await run_repo_b.list_for_tenant(tenant_id=iso_tenant_b)
        assert len(b_runs) == 0, (
            "tenant B's run list must be empty when only tenant A has runs"
        )

    # Tenant B: update_state must raise LookupError (not PermissionError —
    # foreign-tenant rows are indistinguishable from nonexistent per ADR-007).
    async with iso_session_factory() as session:
        run_repo_b = RunRepository(session)
        with pytest.raises(LookupError):
            await run_repo_b.update_state(
                tenant_id=iso_tenant_b, run_id=run_a_id, new_state="running"
            )

    # Sanity: tenant A sees the run and it is still pending (B's failed
    # update_state did not mutate it).
    async with iso_session_factory() as session:
        run_repo_a = RunRepository(session)
        own = await run_repo_a.get_by_id(
            tenant_id=iso_tenant_a, run_id=run_a_id
        )
        assert own is not None, "tenant A must see its own run"
        assert own.state == "pending", (
            "tenant B's failed update_state must not mutate tenant A's run"
        )

        a_runs = await run_repo_a.list_for_tenant(tenant_id=iso_tenant_a)
        assert len(a_runs) == 1


# === Test 4: Collector config carries correct tenant_id =====================


class _StubCollector(Collector):
    """Minimal concrete collector for isolation tests."""

    collector_id = "test:stub-isolation"
    collector_version = "0.0.1"

    async def expand(self, seed: Seed):  # type: ignore[override]
        """Yield a single observation carrying the config's tenant_id."""
        yield Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.DNS_RESOLUTION,
            subject=ObservationSubject(
                identifier_type="domain",
                identifier_value=seed.value,
            ),
            observed_at=datetime.now(UTC),
        )

    async def health_check(self) -> CollectorHealthCheck:
        return CollectorHealthCheck(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            status=CollectorStatus.SUCCESS,
            checked_at=datetime.now(UTC),
        )


def test_collector_config_carries_correct_tenant_id(
    tenant_a: TenantId,
    tenant_b: TenantId,
) -> None:
    """CollectorConfig propagates tenant_id to the collector and its observations.
    Two collectors with different tenant_ids do not share state."""
    run_id_a = uuid4()
    run_id_b = uuid4()

    config_a = CollectorConfig(tenant_id=tenant_a, run_id=run_id_a)
    config_b = CollectorConfig(tenant_id=tenant_b, run_id=run_id_b)

    collector_a = _StubCollector(config_a)
    collector_b = _StubCollector(config_b)

    # Each collector carries its own tenant context.
    assert collector_a.config.tenant_id == tenant_a, (
        "collector A must carry tenant A's id"
    )
    assert collector_b.config.tenant_id == tenant_b, (
        "collector B must carry tenant B's id"
    )

    # Configs are distinct objects — no shared mutable state.
    assert collector_a.config is not collector_b.config, (
        "two collectors must not share a config instance"
    )
    assert collector_a.config.tenant_id != collector_b.config.tenant_id, (
        "collector A and B must carry different tenant_ids"
    )


async def test_collector_observation_inherits_tenant_id(
    tenant_a: TenantId,
    tenant_b: TenantId,
) -> None:
    """Observations emitted by a collector carry the config's tenant_id,
    not a leaked or default value."""
    config_a = CollectorConfig(tenant_id=tenant_a, run_id=uuid4())
    config_b = CollectorConfig(tenant_id=tenant_b, run_id=uuid4())

    collector_a = _StubCollector(config_a)
    collector_b = _StubCollector(config_b)

    seed = Seed(seed_type=SeedType.DOMAIN, value="obs-test.example.com")

    obs_a = [obs async for obs in collector_a.expand(seed)]
    obs_b = [obs async for obs in collector_b.expand(seed)]

    assert len(obs_a) == 1
    assert len(obs_b) == 1
    assert obs_a[0].tenant_id == tenant_a, (
        "observation from collector A must carry tenant A's id"
    )
    assert obs_b[0].tenant_id == tenant_b, (
        "observation from collector B must carry tenant B's id"
    )
    assert obs_a[0].tenant_id != obs_b[0].tenant_id, (
        "observations from different tenants must not share tenant_id"
    )


# === Test 5: Tier-3 dispatch gate per-tenant scope ==========================


def test_tier3_dispatch_gate_per_tenant_scope(
    tenant_a: TenantId,
    tenant_b: TenantId,
) -> None:
    """Per-tenant TenantAuthorizationScope gates Tier-3 dispatch independently.

    Tenant A authorizes ``example.com``; tenant B authorizes ``other.org``.
    The gate must allow A's scope for example.com and deny B's, and vice versa.
    """
    scope_a = TenantAuthorizationScope(
        explicit_entity_identifiers=frozenset({"example.com", "sub.example.com"})
    )
    scope_b = TenantAuthorizationScope(
        explicit_entity_identifiers=frozenset({"other.org"})
    )

    # Entity in scope_a but not scope_b.
    entity_in_a = EntityAttributionView(
        entity_identifier="example.com",
        attribution_tier=None,  # Unattributed — relies on scope membership.
    )
    assert is_tier_3_dispatch_allowed(entity_in_a, scope_a) is True, (
        "entity in tenant A's scope must be allowed for Tier-3 dispatch"
    )
    assert is_tier_3_dispatch_allowed(entity_in_a, scope_b) is False, (
        "entity NOT in tenant B's scope must be denied for Tier-3 dispatch"
    )

    # Entity in scope_b but not scope_a.
    entity_in_b = EntityAttributionView(
        entity_identifier="other.org",
        attribution_tier=None,
    )
    assert is_tier_3_dispatch_allowed(entity_in_b, scope_b) is True, (
        "entity in tenant B's scope must be allowed"
    )
    assert is_tier_3_dispatch_allowed(entity_in_b, scope_a) is False, (
        "entity NOT in tenant A's scope must be denied"
    )

    # Entity with sufficient attribution passes regardless of scope.
    entity_confirmed = EntityAttributionView(
        entity_identifier="neutral.net",
        attribution_tier=AttributionTier.CONFIRMED,
    )
    assert is_tier_3_dispatch_allowed(entity_confirmed, scope_a) is True
    assert is_tier_3_dispatch_allowed(entity_confirmed, scope_b) is True

    # Entity with insufficient attribution and no scope membership is denied.
    entity_medium = EntityAttributionView(
        entity_identifier="unknown.example",
        attribution_tier=AttributionTier.MEDIUM,
    )
    assert is_tier_3_dispatch_allowed(entity_medium, scope_a) is False
    assert is_tier_3_dispatch_allowed(entity_medium, scope_b) is False


# === Test 6: Secrets backend per-tenant isolation ===========================


async def test_secrets_backend_per_tenant_isolation(
    tenant_a: TenantId,
    tenant_b: TenantId,
) -> None:
    """InMemorySecretsBackend stores secrets per tenant; tenant A's secrets
    are not accessible to tenant B queries."""
    backend = InMemoryBackend()

    # Store secrets under different tenants with the same key name.
    await backend.set(tenant_id=tenant_a, key="shodan:api_key", value="KEY_A")
    await backend.set(tenant_id=tenant_b, key="shodan:api_key", value="KEY_B")

    # Each tenant retrieves only its own value.
    val_a = await backend.get(tenant_id=tenant_a, key="shodan:api_key")
    val_b = await backend.get(tenant_id=tenant_b, key="shodan:api_key")

    assert val_a == "KEY_A", "tenant A must retrieve its own secret"
    assert val_b == "KEY_B", "tenant B must retrieve its own secret"
    assert val_a != val_b, "tenant A's secret must differ from tenant B's"

    # List keys shows per-tenant isolation.
    keys_a = await backend.list_keys(tenant_id=tenant_a)
    keys_b = await backend.list_keys(tenant_id=tenant_b)
    assert list(keys_a) == ["shodan:api_key"]
    assert list(keys_b) == ["shodan:api_key"]

    # Deleting tenant A's key does not affect tenant B.
    await backend.delete(tenant_id=tenant_a, key="shodan:api_key")
    remaining_b = await backend.get(tenant_id=tenant_b, key="shodan:api_key")
    assert remaining_b == "KEY_B", (
        "deleting tenant A's secret must not affect tenant B's"
    )

    # Tenant A's key is now gone.
    with pytest.raises(SecretNotFoundError):
        await backend.get(tenant_id=tenant_a, key="shodan:api_key")


# === Test 7: Observation tenant_id immutability =============================


def test_observation_tenant_id_immutable(
    tenant_a: TenantId,
    tenant_b: TenantId,
) -> None:
    """Observation is frozen (Pydantic frozen=True); attempting to reassign
    tenant_id raises ValidationError, preventing post-creation re-tagging."""
    obs = Observation(
        collector_id="test:immutable-check",
        collector_version="0.0.1",
        tenant_id=tenant_a,
        observation_type=ObservationType.DNS_RESOLUTION,
        subject=ObservationSubject(
            identifier_type="domain",
            identifier_value="frozen.example.com",
        ),
        observed_at=datetime.now(UTC),
    )

    assert obs.tenant_id == tenant_a

    # Attempting to reassign tenant_id must raise.
    with pytest.raises(ValidationError):
        obs.tenant_id = tenant_b  # type: ignore[misc]

    # After the failed assignment, the original value is preserved.
    assert obs.tenant_id == tenant_a, (
        "tenant_id must remain unchanged after a failed reassignment"
    )

    # Also verify other frozen fields cannot be mutated.
    with pytest.raises(ValidationError):
        obs.collector_id = "hijacked"  # type: ignore[misc]


# Forward-compat: keep imported references visible so ruff doesn't strip them.
_ = (UUID, RunId)
