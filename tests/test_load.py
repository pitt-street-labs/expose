"""Load tests — synthetic entity generation and pipeline throughput measurement.

Generates 10K synthetic entities with realistic properties and measures
throughput of core pipeline components:

- Entity batch insert (via ORM, SQLite-compatible)
- Lead scoring engine (pure Python, no I/O)
- Relationship creation (via ORM, SQLite-compatible)

All tests are marked ``@pytest.mark.slow`` so they can be skipped in fast CI
runs with ``-m "not slow"``.

Run with::

    pytest tests/test_load.py -x -v --no-header
"""

from __future__ import annotations

import hashlib
import resource
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import uuid4

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
from expose.pipeline.lead_scoring import LeadScoringEngine

# ---------------------------------------------------------------------------
# Synthetic data generators (faker-style, no external dependency)
# ---------------------------------------------------------------------------

# Deterministic seed material for reproducible generation.
_TLDS = ["com", "net", "org", "io", "co", "dev", "app", "xyz", "info", "biz"]
_DOMAIN_WORDS = [
    "acme", "cloud", "alpha", "beta", "gamma", "delta", "omega", "sigma",
    "north", "south", "east", "west", "peak", "core", "edge", "vault",
    "nexus", "synth", "forge", "pulse", "nova", "lunar", "solar", "cyber",
    "data", "mesh", "grid", "link", "gate", "node", "stack", "flux",
]
_SUBDOMAIN_PREFIXES = [
    "api", "staging", "dev", "test", "prod", "mail", "cdn", "vpn",
    "admin", "portal", "dashboard", "app", "www", "blog", "docs", "git",
]
_ORG_SUFFIXES = ["Inc", "LLC", "Corp", "Ltd", "GmbH", "AG", "SA", "Pty"]
_ORG_WORDS = [
    "Quantum", "Atlas", "Horizon", "Vertex", "Cipher", "Nexus", "Prism",
    "Helios", "Zenith", "Echo", "Apex", "Titan", "Vortex", "Helix",
]
_COLLECTOR_IDS = [
    "ct-crtsh", "ct-certspotter", "ct-censys", "active-dns",
    "active-http-fingerprint", "active-tls-handshake", "active-port-surface",
    "rdap-whois", "dns-subdomain-enum", "common-crawl", "wayback-machine",
    "scan-shodan", "scan-censys", "scan-binaryedge",
]
_PRIORITY_TIERS = ["critical", "high", "medium", "low"]
_EDGE_TYPES = [
    "resolves_to", "hosts", "issued_for", "registered_by",
    "belongs_to", "subdomain_of", "sibling_of", "serves",
]


def _generate_domain(index: int) -> str:
    """Generate a deterministic but realistic domain name."""
    word = _DOMAIN_WORDS[index % len(_DOMAIN_WORDS)]
    tld = _TLDS[index % len(_TLDS)]
    suffix = index // len(_DOMAIN_WORDS)
    if suffix > 0:
        return f"{word}{suffix}.{tld}"
    return f"{word}.{tld}"


def _generate_subdomain(index: int) -> str:
    """Generate a deterministic subdomain."""
    prefix = _SUBDOMAIN_PREFIXES[index % len(_SUBDOMAIN_PREFIXES)]
    domain = _generate_domain(index // len(_SUBDOMAIN_PREFIXES))
    return f"{prefix}.{domain}"


def _generate_ip(index: int) -> str:
    """Generate a deterministic IPv4 address in non-reserved ranges."""
    # Spread across plausible public ranges (avoid 0.x, 10.x, 127.x, etc.)
    octet1 = 44 + (index % 180)  # 44-223
    octet2 = (index // 180) % 256
    octet3 = (index // (180 * 256)) % 256
    octet4 = 1 + (index % 254)
    return f"{octet1}.{octet2}.{octet3}.{octet4}"


def _generate_cert_fingerprint(index: int) -> str:
    """Generate a deterministic certificate SHA-256 fingerprint."""
    digest = hashlib.sha256(f"cert-{index}".encode()).hexdigest()
    return f"sha256:{digest}"


def _generate_org_name(index: int) -> str:
    """Generate a deterministic organization name."""
    word = _ORG_WORDS[index % len(_ORG_WORDS)]
    suffix = _ORG_SUFFIXES[index % len(_ORG_SUFFIXES)]
    num = index // len(_ORG_WORDS)
    if num > 0:
        return f"{word} {num} {suffix}"
    return f"{word} {suffix}"


def generate_entity(index: int) -> dict[str, Any]:
    """Generate a single synthetic entity dict.

    Distribution: 60% domains, 25% IPs, 10% certificates, 5% organizations.

    Returns a dict suitable for direct ORM insertion with realistic properties
    including ``_collector_id``, ``_observed_at``, ``_lead_score``, and
    ``_priority_tier``.
    """
    bucket = index % 20  # 20 slots for percentage distribution

    if bucket < 12:  # 60% domains (0-11)
        entity_type = "Domain"
        # Mix of bare domains and subdomains
        if bucket < 6:
            canonical_identifier = _generate_domain(index)
        else:
            canonical_identifier = _generate_subdomain(index)
    elif bucket < 17:  # 25% IPs (12-16)
        entity_type = "IP"
        canonical_identifier = _generate_ip(index)
    elif bucket < 19:  # 10% certificates (17-18)
        entity_type = "Certificate"
        canonical_identifier = _generate_cert_fingerprint(index)
    else:  # 5% organizations (19)
        entity_type = "Organization"
        canonical_identifier = _generate_org_name(index)

    collector_id = _COLLECTOR_IDS[index % len(_COLLECTOR_IDS)]
    lead_score = (index * 7 + 13) % 101  # Deterministic 0-100
    priority_tier = _PRIORITY_TIERS[min(lead_score // 25, 3)]

    properties = {
        "_collector_id": collector_id,
        "_observed_at": datetime(2026, 5, 11, 12, 0, 0, tzinfo=UTC).isoformat(),
        "_lead_score": lead_score,
        "_priority_tier": priority_tier,
        "source": f"load-test-{index}",
    }

    return {
        "entity_type": entity_type,
        "canonical_identifier": canonical_identifier,
        "properties": properties,
        "attribution_status": "unattributed",
        "attribution_confidence": Decimal("0.000"),
    }


def generate_entities(count: int) -> list[dict[str, Any]]:
    """Generate *count* synthetic entities with realistic distribution."""
    return [generate_entity(i) for i in range(count)]


def generate_lead_scoring_inputs(count: int) -> list[dict[str, Any]]:
    """Generate *count* dicts suitable for ``LeadScoringEngine.score_entities``.

    Each dict has ``entity_identifier`` plus optional signal-bearing fields
    to exercise multiple scoring paths.
    """
    inputs: list[dict[str, Any]] = []
    for i in range(count):
        entry: dict[str, Any] = {
            "entity_identifier": _generate_domain(i) if i % 4 != 3 else _generate_ip(i),
        }

        # Add observations for ~40% of entities to exercise header/cert checks
        if i % 5 < 2:
            entry["observations"] = [
                {
                    "_collector_id": "active-http-fingerprint",
                    "structured_payload": {
                        "headers": (
                            {"content-type": "text/html"}
                            if i % 3 == 0
                            else {
                                "content-type": "text/html",
                                "strict-transport-security": "max-age=31536000",
                                "content-security-policy": "default-src 'self'",
                            }
                        ),
                        "server_header": f"nginx/{1 + i % 3}.{20 + i % 10}.0" if i % 7 == 0 else None,
                    },
                }
            ]

        # Add WAF detection for ~30% of entities
        if i % 10 < 3:
            entry["waf_detected"] = False

        # Add DNSBL listings for ~10% of entities
        if i % 10 == 5:
            entry["dnsbl_listings"] = [
                {
                    "blacklist_name": "zen.spamhaus.org",
                    "listing_type": "xbl" if i % 20 == 5 else "sbl",
                    "severity": "critical" if i % 20 == 5 else "medium",
                }
            ]

        inputs.append(entry)
    return inputs


# ---------------------------------------------------------------------------
# SQLite table-creation helper (same pattern as test_e2e_api.py)
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _peak_rss_mb() -> float:
    """Return peak RSS in megabytes via ``resource.getrusage``."""
    # ru_maxrss is in kilobytes on Linux, bytes on macOS.
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_maxrss / 1024  # KB -> MB on Linux


async def _seed_tenant(
    session_factory: async_sessionmaker[AsyncSession],
    name: str,
) -> tuple[Any, Any]:
    """Insert a tenant row and return (tenant_id, tenant_uuid)."""
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


async def _insert_entities_orm(
    session_factory: async_sessionmaker[AsyncSession],
    tenant_id: Any,
    entities: list[dict[str, Any]],
) -> list[Entity]:
    """Insert entities via direct ORM add_all (SQLite-compatible)."""
    now = datetime.now(UTC)
    rows: list[Entity] = []
    async with session_factory() as session:
        for e in entities:
            row = Entity(
                id=uuid4(),
                tenant_id=tenant_id,
                entity_type=e["entity_type"],
                canonical_identifier=e["canonical_identifier"],
                properties=e["properties"],
                attribution_status=e["attribution_status"],
                attribution_confidence=e["attribution_confidence"],
                first_observed_at=now,
                last_observed_at=now,
            )
            rows.append(row)
        session.add_all(rows)
        await session.commit()
    return rows


async def _insert_relationships_orm(
    session_factory: async_sessionmaker[AsyncSession],
    tenant_id: Any,
    entity_ids: list[Any],
    count: int,
) -> int:
    """Create *count* relationships between random entity pairs via ORM."""
    now = datetime.now(UTC)
    created = 0
    async with session_factory() as session:
        for i in range(count):
            from_idx = i % len(entity_ids)
            to_idx = (i + 1) % len(entity_ids)
            if from_idx == to_idx:
                to_idx = (to_idx + 1) % len(entity_ids)
            rel = Relationship(
                id=uuid4(),
                tenant_id=tenant_id,
                from_entity_id=entity_ids[from_idx],
                to_entity_id=entity_ids[to_idx],
                edge_type=_EDGE_TYPES[i % len(_EDGE_TYPES)],
                confidence=Decimal("0.850"),
                observed_at=now,
                collector_id=_COLLECTOR_IDS[i % len(_COLLECTOR_IDS)],
                properties={},
            )
            session.add(rel)
            created += 1
        await session.commit()
    return created


# ---------------------------------------------------------------------------
# Tests — entity generation throughput
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_entity_generation_throughput() -> None:
    """Entity generation must exceed 5000 entities/second (pure Python)."""
    count = 10_000
    rss_before = _peak_rss_mb()

    t0 = time.perf_counter()
    entities = generate_entities(count)
    elapsed = time.perf_counter() - t0

    rss_after = _peak_rss_mb()
    rate = count / elapsed

    # Verify we actually got the right number
    assert len(entities) == count

    # Verify type distribution is approximately correct
    type_counts: dict[str, int] = {}
    for e in entities:
        t = e["entity_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    total = sum(type_counts.values())
    domain_pct = type_counts.get("Domain", 0) / total * 100
    ip_pct = type_counts.get("IP", 0) / total * 100
    cert_pct = type_counts.get("Certificate", 0) / total * 100
    org_pct = type_counts.get("Organization", 0) / total * 100

    assert 55 <= domain_pct <= 65, f"Domain % out of range: {domain_pct:.1f}%"
    assert 20 <= ip_pct <= 30, f"IP % out of range: {ip_pct:.1f}%"
    assert 5 <= cert_pct <= 15, f"Certificate % out of range: {cert_pct:.1f}%"
    assert 2 <= org_pct <= 8, f"Organization % out of range: {org_pct:.1f}%"

    # Verify all entities have required properties
    for e in entities:
        assert "_collector_id" in e["properties"]
        assert "_observed_at" in e["properties"]
        assert "_lead_score" in e["properties"]
        assert "_priority_tier" in e["properties"]

    # Performance bound: > 5000 entities/second
    assert rate > 5_000, (
        f"Entity generation too slow: {rate:.0f} entities/s (need >5000)"
    )

    print(f"\n--- Entity Generation ---")
    print(f"  Count:      {count:,}")
    print(f"  Time:       {elapsed:.3f}s")
    print(f"  Rate:       {rate:,.0f} entities/s")
    print(f"  Peak RSS:   {rss_after:.1f} MB (delta: {rss_after - rss_before:+.1f} MB)")


# ---------------------------------------------------------------------------
# Tests — lead scoring throughput
# ---------------------------------------------------------------------------


@pytest.mark.slow
@pytest.mark.parametrize("count", [100, 1_000, 5_000], ids=["100", "1K", "5K"])
def test_lead_scoring_throughput(count: int) -> None:
    """LeadScoringEngine.score_entities must exceed 1000 entities/second."""
    engine = LeadScoringEngine()
    inputs = generate_lead_scoring_inputs(count)
    rss_before = _peak_rss_mb()

    t0 = time.perf_counter()
    scores = engine.score_entities(inputs)
    elapsed = time.perf_counter() - t0

    rss_after = _peak_rss_mb()
    rate = count / elapsed

    # Verify we got scores back for every entity
    assert len(scores) == count

    # Verify scores are sorted descending (contract of score_entities)
    for i in range(len(scores) - 1):
        assert scores[i].score >= scores[i + 1].score

    # Verify all scores have valid tiers
    valid_tiers = {"critical", "high", "medium", "low"}
    for s in scores:
        assert s.priority_tier in valid_tiers
        assert 0 <= s.score <= 100

    # Performance bound: > 1000 entities/second
    assert rate > 1_000, (
        f"Lead scoring too slow at n={count}: {rate:.0f} scores/s (need >1000)"
    )

    print(f"\n--- Lead Scoring (n={count:,}) ---")
    print(f"  Time:       {elapsed:.3f}s")
    print(f"  Rate:       {rate:,.0f} scores/s")
    print(f"  Peak RSS:   {rss_after:.1f} MB (delta: {rss_after - rss_before:+.1f} MB)")

    # Distribution summary
    tier_counts: dict[str, int] = {}
    for s in scores:
        tier_counts[s.priority_tier] = tier_counts.get(s.priority_tier, 0) + 1
    for tier in ["critical", "high", "medium", "low"]:
        pct = tier_counts.get(tier, 0) / count * 100
        print(f"  {tier:>10}: {tier_counts.get(tier, 0):>5} ({pct:.1f}%)")


# ---------------------------------------------------------------------------
# Tests — entity batch insert throughput (DB, via ORM)
# ---------------------------------------------------------------------------


@pytest.mark.slow
@pytest.mark.parametrize("count", [100, 500, 1_000], ids=["100", "500", "1K"])
async def test_entity_batch_insert_throughput(
    session_factory: async_sessionmaker[AsyncSession],
    count: int,
) -> None:
    """Entity batch insert throughput via ORM into in-memory SQLite."""
    tid = await _seed_tenant(session_factory, f"load-batch-{count}")
    entities = generate_entities(count)
    rss_before = _peak_rss_mb()

    t0 = time.perf_counter()
    rows = await _insert_entities_orm(session_factory, tid, entities)
    elapsed = time.perf_counter() - t0

    rss_after = _peak_rss_mb()
    rate = count / elapsed

    assert len(rows) == count

    # Verify entities are actually persisted
    async with session_factory() as session:
        from sqlalchemy import func, select  # noqa: PLC0415
        result = await session.execute(
            select(func.count()).select_from(Entity).where(Entity.tenant_id == tid)
        )
        persisted_count = result.scalar_one()
    assert persisted_count == count

    print(f"\n--- Entity Batch Insert (n={count:,}) ---")
    print(f"  Time:       {elapsed:.3f}s")
    print(f"  Rate:       {rate:,.0f} entities/s")
    print(f"  Peak RSS:   {rss_after:.1f} MB (delta: {rss_after - rss_before:+.1f} MB)")


# ---------------------------------------------------------------------------
# Tests — relationship creation throughput (DB, via ORM)
# ---------------------------------------------------------------------------


@pytest.mark.slow
@pytest.mark.parametrize("count", [1_000, 5_000], ids=["1K", "5K"])
async def test_relationship_creation_throughput(
    session_factory: async_sessionmaker[AsyncSession],
    count: int,
) -> None:
    """Relationship creation throughput via ORM into in-memory SQLite."""
    tid = await _seed_tenant(session_factory, f"load-rel-{count}")

    # Need at least count+1 entities for unique from/to pairs.
    # Generate enough entities so we have distinct IDs.
    num_entities = min(count + 1, 2000)
    entities = generate_entities(num_entities)
    rows = await _insert_entities_orm(session_factory, tid, entities)
    entity_ids = [row.id for row in rows]

    rss_before = _peak_rss_mb()

    t0 = time.perf_counter()
    created = await _insert_relationships_orm(session_factory, tid, entity_ids, count)
    elapsed = time.perf_counter() - t0

    rss_after = _peak_rss_mb()
    rate = count / elapsed

    assert created == count

    # Verify relationships are actually persisted
    async with session_factory() as session:
        from sqlalchemy import func, select  # noqa: PLC0415
        result = await session.execute(
            select(func.count()).select_from(Relationship).where(
                Relationship.tenant_id == tid
            )
        )
        persisted_count = result.scalar_one()
    assert persisted_count == count

    print(f"\n--- Relationship Creation (n={count:,}) ---")
    print(f"  Time:       {elapsed:.3f}s")
    print(f"  Rate:       {rate:,.0f} relationships/s")
    print(f"  Peak RSS:   {rss_after:.1f} MB (delta: {rss_after - rss_before:+.1f} MB)")


# ---------------------------------------------------------------------------
# Tests — full synthetic pipeline benchmark (10K entities)
# ---------------------------------------------------------------------------


@pytest.mark.slow
async def test_full_pipeline_benchmark(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """End-to-end benchmark: generate 10K entities, insert, score, relate.

    This is the headline load test. It exercises the full synthetic pipeline
    and reports aggregate throughput numbers.
    """
    total_entities = 10_000
    scoring_sample = 5_000
    relationship_count = 5_000

    rss_start = _peak_rss_mb()

    # Phase 1: Generate synthetic entities
    t_gen_start = time.perf_counter()
    entities = generate_entities(total_entities)
    t_gen_end = time.perf_counter()
    gen_rate = total_entities / (t_gen_end - t_gen_start)

    assert len(entities) == total_entities
    assert gen_rate > 5_000, f"Generation too slow: {gen_rate:.0f}/s"

    # Phase 2: Insert into DB (in batches of 1000 to avoid huge transactions)
    tid = await _seed_tenant(session_factory, "full-benchmark")
    batch_size = 1_000
    all_rows: list[Entity] = []

    t_insert_start = time.perf_counter()
    for i in range(0, total_entities, batch_size):
        batch = entities[i : i + batch_size]
        rows = await _insert_entities_orm(session_factory, tid, batch)
        all_rows.extend(rows)
    t_insert_end = time.perf_counter()
    insert_rate = total_entities / (t_insert_end - t_insert_start)

    assert len(all_rows) == total_entities

    # Phase 3: Score a sample via LeadScoringEngine
    scoring_engine = LeadScoringEngine()
    scoring_inputs = generate_lead_scoring_inputs(scoring_sample)

    t_score_start = time.perf_counter()
    scores = scoring_engine.score_entities(scoring_inputs)
    t_score_end = time.perf_counter()
    score_rate = scoring_sample / (t_score_end - t_score_start)

    assert len(scores) == scoring_sample
    assert score_rate > 1_000, f"Scoring too slow: {score_rate:.0f}/s"

    # Phase 4: Create relationships
    entity_ids = [row.id for row in all_rows[:2000]]  # Use first 2000 entities

    t_rel_start = time.perf_counter()
    rel_count = await _insert_relationships_orm(
        session_factory, tid, entity_ids, relationship_count
    )
    t_rel_end = time.perf_counter()
    rel_rate = relationship_count / (t_rel_end - t_rel_start)

    assert rel_count == relationship_count

    rss_end = _peak_rss_mb()

    # Summary report
    print("\n" + "=" * 60)
    print("  FULL PIPELINE BENCHMARK — 10K Entities")
    print("=" * 60)
    print(f"  Entity generation:  {gen_rate:>10,.0f} entities/s   ({t_gen_end - t_gen_start:.3f}s)")
    print(f"  DB insert (ORM):    {insert_rate:>10,.0f} entities/s   ({t_insert_end - t_insert_start:.3f}s)")
    print(f"  Lead scoring:       {score_rate:>10,.0f} scores/s     ({t_score_end - t_score_start:.3f}s)")
    print(f"  Relationships:      {rel_rate:>10,.0f} rels/s        ({t_rel_end - t_rel_start:.3f}s)")
    print(f"  Peak RSS:           {rss_end:>10.1f} MB  (delta: {rss_end - rss_start:+.1f} MB)")
    print("=" * 60)
