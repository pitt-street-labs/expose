"""Tenant-scoped repository for the ``relationships`` table.

Per ADR-002 the relationship row is the observation-graph edge — typed,
directional, with provenance metadata (``collector_id``, ``observed_at``,
``confidence``, optional ``evidence_ref``) per SPEC.md §5.3. Per ADR-007 every
public method takes ``tenant_id`` as a required keyword argument and includes
it in every WHERE / INSERT clause; cross-tenant calls return empty.

Edges are append-mostly in the engine's data-flow model — collectors observe
and record, the attribution engine reads — so the v1 repository surface is
deliberately small: ``create`` for the write path, ``find_for_entity`` for the
read path. Multi-hop traversal (recursive CTEs per ADR-002) lives in a
separate Sprint 5+ traversal helper that composes on top of this repository.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal
from uuid import uuid4

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from expose.db.models import Relationship
from expose.types.shared import EntityId, TenantId

Direction = Literal["out", "in", "both"]


class RelationshipRepository:
    """Async tenant-scoped CRUD for :class:`expose.db.models.Relationship`.

    Construct one per ``AsyncSession``. All methods are coroutines and require
    ``tenant_id``; cross-tenant calls return empty sequences.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        tenant_id: TenantId,
        from_entity_id: EntityId,
        to_entity_id: EntityId,
        edge_type: str,
        confidence: Decimal,
        observed_at: datetime,
        collector_id: str,
        evidence_ref: str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> Relationship:
        """Insert a directional edge ``from -> to`` of type ``edge_type``.

        Edges are append-only in v1 — every observation creates a new row.
        Deduplication / collapsing of identical edges is a Sprint 5+ task on
        the artifact generator (it's cheaper to dedupe at read time than to
        add an upsert constraint here, given how cheap append writes are).

        ``properties`` defaults to ``{}`` when not supplied. The caller controls
        transaction boundaries — no commit is issued here.
        """
        rel = Relationship(
            id=uuid4(),
            tenant_id=tenant_id,
            from_entity_id=from_entity_id,
            to_entity_id=to_entity_id,
            edge_type=edge_type,
            confidence=confidence,
            observed_at=observed_at,
            collector_id=collector_id,
            evidence_ref=evidence_ref,
            properties=properties if properties is not None else {},
        )
        self._session.add(rel)
        await self._session.flush()
        return rel

    async def find_for_entity(
        self,
        *,
        tenant_id: TenantId,
        entity_id: EntityId,
        direction: Direction = "both",
        edge_type: str | None = None,
        limit: int = 100,
    ) -> Sequence[Relationship]:
        """Find edges incident on ``entity_id``.

        ``direction``:

        - ``"out"`` — edges where ``from_entity_id == entity_id``
        - ``"in"`` — edges where ``to_entity_id == entity_id``
        - ``"both"`` — union of out + in (default, common for analyst-facing
          neighborhood queries)

        Results are ordered by ``observed_at DESC`` and capped at ``limit``
        rows. Wider traversal lives in the (future) graph traversal helper.
        """
        stmt = select(Relationship).where(Relationship.tenant_id == tenant_id)
        if direction == "out":
            stmt = stmt.where(Relationship.from_entity_id == entity_id)
        elif direction == "in":
            stmt = stmt.where(Relationship.to_entity_id == entity_id)
        else:
            stmt = stmt.where(
                or_(
                    Relationship.from_entity_id == entity_id,
                    Relationship.to_entity_id == entity_id,
                )
            )
        if edge_type is not None:
            stmt = stmt.where(Relationship.edge_type == edge_type)
        stmt = stmt.order_by(Relationship.observed_at.desc()).limit(limit)
        result = await self._session.execute(stmt)
        return result.scalars().all()


__all__ = ["Direction", "RelationshipRepository"]
