# ADR-002: Graph storage

**Status:** Accepted
**Date:** 2026-05-09
**Decision-makers:** Korlogos / Pitt Street Labs

## Context

The observation graph is the central data structure of EXPOSE. Every collector writes into it; the attribution engine reads from it; the LLM enrichment layer queries it; the canonical artifact serializes from it.

Workload characteristics:
- Realistic graph size: 100k-500k nodes, 1M-5M edges per tenant. Large but not extreme.
- Read pattern: heavy on multi-hop traversal during attribution rules, mostly 1-3 hops, occasionally 4-5.
- Write pattern: append-mostly with occasional re-resolution of existing entities.
- Multi-tenancy: tenant_id scopes every query, baked in from day one.
- Operational concerns: backup, migration, version upgrade, observability.

Three options were considered: Postgres with Apache AGE extension, Neo4j (Community or Enterprise), or Postgres with a normalized graph schema (no graph engine).

## Decision

**Postgres with a normalized graph schema, no dedicated graph engine** for v1.

Schema (illustrative; full DDL via Alembic migrations):

```sql
CREATE TABLE entities (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    entity_type TEXT NOT NULL,
    canonical_identifier TEXT NOT NULL,
    properties JSONB NOT NULL DEFAULT '{}',
    attribution_status TEXT NOT NULL,
    attribution_confidence NUMERIC(4,3) NOT NULL,
    first_observed_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, entity_type, canonical_identifier)
);

CREATE TABLE relationships (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    from_entity_id UUID NOT NULL,
    to_entity_id UUID NOT NULL,
    edge_type TEXT NOT NULL,
    confidence NUMERIC(4,3) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    collector_id TEXT NOT NULL,
    evidence_ref TEXT,
    properties JSONB NOT NULL DEFAULT '{}'
);
```

Recursive CTEs handle traversal queries. Indexes on `(tenant_id, entity_type)`, `(tenant_id, canonical_identifier)`, `(tenant_id, from_entity_id, edge_type)`, and `(tenant_id, to_entity_id, edge_type)` cover the common query patterns.

Evidence (raw cert PEMs, raw HTTP responses, raw DNS responses) is stored in object storage (MinIO/S3) keyed by SHA-256 content hash. The `evidence_ref` field holds `sha256:<hex>` pointers. Graph stays small and queryable; evidence stays cheap and immutable.

## Consequences

**Positive:**

- Single operational footprint. Postgres backup, replication, version upgrade, monitoring — all standard.
- Migration story is just Alembic. No graph-specific migration tooling.
- Boring, well-understood SQL. New contributors can read the codebase without learning Cypher.
- JSON document fields (`properties` JSONB) accommodate type-specific attributes without schema explosion.
- Indexed queries handle the shallow traversals (1-3 hops) attribution rules need, with predictable latency.
- Future migration to Apache AGE is straightforward — same database, add the extension, parallel access path. Migration to Neo4j is larger but data semantics translate cleanly.
- Multi-tenancy enforcement is straightforward — `tenant_id` in every WHERE clause, enforced by middleware.

**Negative:**

- Deep traversal queries (5+ hops) are uglier and slower in SQL than in Cypher. We'll feel this when attribution rules evolve toward more complex correlation patterns.
- No native graph visualization tooling. Analyst tools that want to inspect the graph need a separate visualization layer (or ad-hoc queries).
- Recursive CTEs are not the most performant traversal mechanism for very deep paths. We'll need to monitor query latencies.
- Lacks the query optimizer maturity of Neo4j for graph-shaped workloads.

## Alternatives considered

**Apache AGE.** Postgres extension providing openCypher queries on top of standard SQL. Tempting because it preserves the single-Postgres ops simplicity while adding graph ergonomics. Rejected for v1 because:
- Version compatibility with Postgres releases lags. Currently AGE supports Postgres 16 only; EXPOSE should not be locked to a specific Postgres version.
- The query optimizer for Cypher-on-Postgres is less mature than Neo4j's.
- Operational tooling (backup verification, replication monitoring) is less mature for AGE than for plain Postgres.

Migration path preserved — when traversal complexity outgrows recursive CTEs, AGE is a parallel access path on the same database.

**Neo4j.** Best-in-class graph ergonomics, mature query optimizer, genuinely useful visualization tooling (Bloom, Browser). Rejected for v1 because:
- Separate operational footprint — another database to back up, monitor, upgrade. ARC has limited team capacity for additional services.
- Two sources of truth complicate the architecture: Postgres for everything else (jobs, secrets, audit log, runs), Neo4j for the graph.
- Community Edition lacks clustering; Enterprise licensing is real money.

Migration path preserved — Neo4j adoption is a future-work decision, separate from the v1 storage choice.

## When to revisit

Trigger conditions for moving from option 3 to option 1 (AGE) or option 2 (Neo4j):

- Attribution rule queries regularly require 5+ hop pathfinding with poor recursive CTE performance.
- Analyst tooling becomes a priority and requires graph-native visualization.
- Graph size grows beyond 5M-10M nodes per tenant (single-Postgres scale ceiling).

When triggered, AGE is the cheaper migration. Neo4j becomes worthwhile only if graph workload dominates total system load.

## References

- Decision recorded in design conversation 2026-05-09.
- Future-work item: AGE-vs-Neo4j upgrade path. See `docs/issues-backlog.md`.
