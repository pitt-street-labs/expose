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
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from expose.db.models import Relationship
from expose.types.shared import EntityId, TenantId

Direction = Literal["out", "in", "both"]


class RelationshipRepository:
    """Async tenant-scoped CRUD for :class:`expose.db.models.Relationship`.

    Construct one per ``AsyncSession``. All methods are coroutines and require
    ``tenant_id``; cross-tenant calls return empty sequences.
    """

    # Sentinel so callers can distinguish real repositories from mocks.
    supports_batch_create: bool = True

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

    async def create_or_update(
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
        """Idempotent upsert: create edge or update if same
        ``(tenant_id, from_entity_id, to_entity_id, edge_type, collector_id)``
        already exists.

        Uses a single ``INSERT ... ON CONFLICT DO UPDATE`` against the
        ``uq_relationships_logical_key`` constraint — one round-trip instead
        of SELECT + INSERT/UPDATE.

        On conflict the ``observed_at``, ``confidence``, ``properties``, and
        ``evidence_ref`` (when non-null) are refreshed; the existing row id
        is preserved.

        The caller controls transaction boundaries — no commit is issued here.
        """
        insert_stmt = pg_insert(Relationship).values(
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

        set_clause: dict[str, Any] = {
            "confidence": insert_stmt.excluded.confidence,
            "observed_at": insert_stmt.excluded.observed_at,
            "properties": insert_stmt.excluded.properties,
        }
        if evidence_ref is not None:
            set_clause["evidence_ref"] = insert_stmt.excluded.evidence_ref

        upsert_stmt = insert_stmt.on_conflict_do_update(
            index_elements=["tenant_id", "from_entity_id", "to_entity_id", "edge_type", "collector_id"],
            set_=set_clause,
        ).returning(Relationship)

        result = await self._session.execute(
            upsert_stmt, execution_options={"populate_existing": True}
        )
        rel: Relationship = result.scalar_one()
        await self._session.flush()
        return rel

    async def batch_create(
        self,
        relationships: list[dict[str, Any]],
    ) -> list[Relationship]:
        """Batch upsert multiple relationship rows in a single multi-row
        ``INSERT ... ON CONFLICT DO UPDATE`` statement.

        Each dict must contain: ``tenant_id``, ``from_entity_id``,
        ``to_entity_id``, ``edge_type``, ``confidence``, ``observed_at``,
        ``collector_id``.  Optional: ``evidence_ref``, ``properties``.

        Returns the list of persisted :class:`Relationship` rows with
        post-upsert state. A single ``flush()`` is issued at the end.

        The caller controls transaction boundaries -- no commit is issued.
        """
        if not relationships:
            return []

        seen: dict[tuple, dict] = {}
        for rel in relationships:
            key = (
                str(rel["tenant_id"]),
                str(rel["from_entity_id"]),
                str(rel["to_entity_id"]),
                rel["edge_type"],
                rel["collector_id"],
            )
            if key in seen:
                merged_props = {**seen[key].get("properties", {}), **rel.get("properties", {})}
                seen[key]["properties"] = merged_props
                if rel["confidence"] > seen[key]["confidence"]:
                    seen[key]["confidence"] = rel["confidence"]
            else:
                seen[key] = dict(rel)

        values = [
            {
                "id": uuid4(),
                "tenant_id": rel["tenant_id"],
                "from_entity_id": rel["from_entity_id"],
                "to_entity_id": rel["to_entity_id"],
                "edge_type": rel["edge_type"],
                "confidence": rel["confidence"],
                "observed_at": rel["observed_at"],
                "collector_id": rel["collector_id"],
                "evidence_ref": rel.get("evidence_ref"),
                "properties": rel.get("properties", {}),
            }
            for rel in seen.values()
        ]

        insert_stmt = pg_insert(Relationship).values(values)
        upsert_stmt = insert_stmt.on_conflict_do_update(
            index_elements=["tenant_id", "from_entity_id", "to_entity_id", "edge_type", "collector_id"],
            set_={
                "confidence": insert_stmt.excluded.confidence,
                "observed_at": insert_stmt.excluded.observed_at,
                "properties": insert_stmt.excluded.properties,
                "evidence_ref": insert_stmt.excluded.evidence_ref,
            },
        ).returning(Relationship)

        result = await self._session.execute(
            upsert_stmt, execution_options={"populate_existing": True}
        )
        upserted: list[Relationship] = list(result.scalars().all())
        await self._session.flush()
        return upserted

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
