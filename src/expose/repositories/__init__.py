"""Async tenant-scoped repository layer for the EXPOSE observation graph.

Per **ADR-002** (graph storage): all data access against `entities`,
`relationships`, and `runs` flows through this layer; SQL is encapsulated here
so the upstream pipeline (collectors, attribution engine, artifact generator)
sees domain-shaped methods rather than raw queries.

Per **ADR-007** (multi-tenancy logical-only in v1): every public method on every
repository takes `tenant_id` as a required keyword-only argument and includes
it in the WHERE clause of every read and the INSERT/UPDATE values of every
write. Cross-tenant access is impossible by construction — passing a
mismatched ``tenant_id`` returns ``None`` / empty rather than raising, which
keeps the failure mode "you got nothing" rather than "you got something you
shouldn't have." The cross-tenant isolation suite in
``tests/test_repositories.py`` exercises this guarantee for each repository.

The three repositories are deliberately kept thin: they own one ORM table each,
provide a small handful of well-typed methods, and leave transaction control
to the caller. Combine via the same ``AsyncSession`` to maintain atomicity
across multi-table writes (entity + outgoing relationship in the same Stage 4
ingest, for example).

Usage::

    from sqlalchemy.ext.asyncio import AsyncSession

    async with session_scope(factory) as session:
        entities = EntityRepository(session)
        ent = await entities.create_or_update(
            tenant_id=tenant_id,
            entity_type="Domain",
            canonical_identifier="example.com",
            properties={"registrar": "example-rar"},
            attribution_status="confirmed",
            attribution_confidence=Decimal("0.95"),
        )
"""
from __future__ import annotations

from expose.repositories.entity_repo import EntityRepository
from expose.repositories.relationship_repo import RelationshipRepository
from expose.repositories.run_repo import RunRepository

__all__ = [
    "EntityRepository",
    "RelationshipRepository",
    "RunRepository",
]
