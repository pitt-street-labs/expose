"""Tenant-scoped repository for the ``entities`` table.

Per ADR-002 the entity row is the observation-graph node — Domain, Subdomain,
IP, CIDR, Certificate, Service, CloudResource, Organization, Registrant, ASN
(SPEC.md §5.2). Per ADR-007 every public method takes ``tenant_id`` as a
required keyword argument and uses it in every WHERE / INSERT clause; passing a
foreign tenant returns ``None`` / empty rather than raising, by deliberate
design (see package docstring).

The headline write method is :meth:`EntityRepository.create_or_update`, which
is the canonical re-resolution path used by every collector when it observes
an entity. It maps onto a Postgres ``INSERT ... ON CONFLICT (tenant_id,
entity_type, canonical_identifier) DO UPDATE`` driven by the unique constraint
``uq_entities_tenant_type_identifier`` declared on the model.
"""
from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from expose.db.models import Entity
from expose.types.shared import EntityId, TenantId


class EntityRepository:
    """Async tenant-scoped CRUD/upsert for :class:`expose.db.models.Entity`.

    Construct one per ``AsyncSession`` (cheap; just a session reference). All
    methods are coroutines and require ``tenant_id``; cross-tenant calls return
    ``None`` or empty sequences.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_or_update(
        self,
        *,
        tenant_id: TenantId,
        entity_type: str,
        canonical_identifier: str,
        properties: dict[str, Any],
        attribution_status: str,
        attribution_confidence: Decimal,
    ) -> Entity:
        """Idempotent upsert keyed on the unique
        ``(tenant_id, entity_type, canonical_identifier)`` constraint.

        Conflict-resolution policy (deliberate, documented):

        - On insert: a fresh ``id`` (UUID4) is assigned and ``first_observed_at``
          / ``last_observed_at`` default to ``NOW()`` from the schema.
        - On conflict: ``properties`` is replaced wholesale with the incoming
          dict (last-writer-wins per field; collectors are responsible for
          merging their own retained properties before calling), and
          ``attribution_status`` / ``attribution_confidence`` are taken from
          the incoming call (the attribution engine is the authoritative writer
          when it re-evaluates a node). ``last_observed_at`` advances to
          ``NOW()`` on every observation; ``first_observed_at`` is preserved
          (intentionally not overwritten).

        Returns the persisted ORM row with up-to-date column values. The caller
        controls transaction boundaries — no commit is issued here.
        """
        insert_stmt = pg_insert(Entity).values(
            id=uuid4(),
            tenant_id=tenant_id,
            entity_type=entity_type,
            canonical_identifier=canonical_identifier,
            properties=properties,
            attribution_status=attribution_status,
            attribution_confidence=attribution_confidence,
        )
        upsert_stmt = insert_stmt.on_conflict_do_update(
            constraint="uq_entities_tenant_type_identifier",
            set_={
                "properties": insert_stmt.excluded.properties,
                "attribution_status": insert_stmt.excluded.attribution_status,
                "attribution_confidence": insert_stmt.excluded.attribution_confidence,
                "last_observed_at": text("NOW()"),
            },
        ).returning(Entity)

        # ``returning(Entity)`` + ``execution_options(populate_existing=True)``
        # gives us a hydrated ORM instance whose mutable columns reflect the
        # post-UPDATE state, which is what callers expect.
        result = await self._session.execute(
            upsert_stmt, execution_options={"populate_existing": True}
        )
        entity: Entity = result.scalar_one()
        await self._session.flush()
        return entity

    async def get_by_id(
        self,
        *,
        tenant_id: TenantId,
        entity_id: EntityId,
    ) -> Entity | None:
        """Fetch by primary key, scoped to ``tenant_id``.

        Returns ``None`` if the row does not exist OR exists under a different
        tenant — there is intentionally no signal distinguishing these two
        cases (per ADR-007 cross-tenant invisibility).
        """
        stmt = select(Entity).where(
            Entity.id == entity_id,
            Entity.tenant_id == tenant_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def find_by_canonical(
        self,
        *,
        tenant_id: TenantId,
        entity_type: str,
        canonical_identifier: str,
    ) -> Entity | None:
        """Look up via the unique
        ``(tenant_id, entity_type, canonical_identifier)`` index.

        Useful when a collector wants to check existence without forcing a
        write (the upsert path is used when the collector intends to insert
        or refresh).
        """
        stmt = select(Entity).where(
            Entity.tenant_id == tenant_id,
            Entity.entity_type == entity_type,
            Entity.canonical_identifier == canonical_identifier,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_tenant(
        self,
        *,
        tenant_id: TenantId,
        entity_type: str | None = None,
        limit: int = 100,
    ) -> Sequence[Entity]:
        """List entities for a tenant, optionally filtered by ``entity_type``.

        Default limit of 100 keeps the path bounded; callers that need to
        page beyond that should add cursor support in a follow-up (filed as
        a Sprint 5 backlog item alongside the artifact generator's full-graph
        traversal).
        """
        stmt = select(Entity).where(Entity.tenant_id == tenant_id)
        if entity_type is not None:
            stmt = stmt.where(Entity.entity_type == entity_type)
        stmt = stmt.order_by(Entity.last_observed_at.desc()).limit(limit)
        result = await self._session.execute(stmt)
        return result.scalars().all()


__all__ = ["EntityRepository"]


# Forward-compat: keep these here so static type checkers can see the explicit
# UUID/EntityId equivalence at module read time without importing them at
# call-site (the repository accepts NewType-style ids, which are UUIDs at
# runtime).
_ = (UUID, EntityId)
