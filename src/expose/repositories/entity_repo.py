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

from sqlalchemy import bindparam, distinct, func, select, text, union_all, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from expose.db.models import Entity, Relationship
from expose.types.shared import EntityId, TenantId

# Attribution tier thresholds — maps from distinct-collector count to
# (attribution_status, attribution_confidence).  Evaluated in order; the
# first matching predicate wins.
_ATTRIBUTION_TIERS: list[tuple[int, str, str]] = [
    # (min_collectors, status, confidence)
    (4, "confirmed", "0.900"),
    (3, "high", "0.700"),
    (2, "medium", "0.400"),
]
_DEFAULT_STATUS = "unattributed"
_DEFAULT_CONFIDENCE = "0.000"


class EntityRepository:
    """Async tenant-scoped CRUD/upsert for :class:`expose.db.models.Entity`.

    Construct one per ``AsyncSession`` (cheap; just a session reference). All
    methods are coroutines and require ``tenant_id``; cross-tenant calls return
    ``None`` or empty sequences.
    """

    # Sentinel so callers can distinguish real repositories from mocks
    # that auto-generate attributes.  ``_flush_batch`` in ``RunExecutor``
    # checks this before calling ``batch_upsert``.
    supports_batch_upsert: bool = True

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
        - On conflict: ``properties`` is shallow-merged — existing keys from
          prior collectors are preserved, and the incoming dict adds or
          overwrites its own keys via Postgres ``||`` on jsonb.  This allows
          properties from multiple collectors to accumulate on the same entity.
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
                # Merge new properties INTO existing ones (shallow).
                # Preserves keys from prior collectors while allowing
                # the current collector to add or update its own keys.
                "properties": text(
                    "COALESCE(entities.properties, '{}'::jsonb) || EXCLUDED.properties"
                ),
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

    async def batch_upsert(
        self,
        entities: list[dict[str, Any]],
    ) -> list[Entity]:
        """Batch upsert multiple entities in a single multi-row
        ``INSERT ... ON CONFLICT DO UPDATE`` statement.

        Each dict in ``entities`` must contain the same keys accepted by
        :meth:`create_or_update`: ``tenant_id``, ``entity_type``,
        ``canonical_identifier``, ``properties``, ``attribution_status``,
        ``attribution_confidence``.

        Returns a list of hydrated :class:`Entity` ORM instances reflecting
        the post-upsert state. A single ``flush()`` is issued at the end.
        """
        if not entities:
            return []

        seen: dict[tuple, dict] = {}
        for e in entities:
            key = (str(e["tenant_id"]), e["entity_type"], e["canonical_identifier"])
            if key in seen:
                merged_props = {**seen[key]["properties"], **e["properties"]}
                seen[key]["properties"] = merged_props
                if e.get("attribution_confidence", 0) > seen[key].get("attribution_confidence", 0):
                    seen[key]["attribution_status"] = e["attribution_status"]
                    seen[key]["attribution_confidence"] = e["attribution_confidence"]
            else:
                seen[key] = dict(e)

        deduped = list(seen.values())
        all_results: list[Entity] = []
        _CHUNK_SIZE = 500

        for chunk_start in range(0, len(deduped), _CHUNK_SIZE):
            chunk = deduped[chunk_start : chunk_start + _CHUNK_SIZE]
            chunk_results = await self._batch_upsert_chunk(chunk)
            all_results.extend(chunk_results)

        return all_results

    async def _batch_upsert_chunk(
        self,
        chunk: list[dict[str, Any]],
    ) -> list[Entity]:
        """Upsert a single chunk (max 500 entities) to stay within Postgres parameter limits."""
        values = [
            {
                "id": uuid4(),
                "tenant_id": e["tenant_id"],
                "entity_type": e["entity_type"],
                "canonical_identifier": e["canonical_identifier"],
                "properties": e["properties"],
                "attribution_status": e["attribution_status"],
                "attribution_confidence": e["attribution_confidence"],
            }
            for e in chunk
        ]

        insert_stmt = pg_insert(Entity).values(values)
        upsert_stmt = insert_stmt.on_conflict_do_update(
            constraint="uq_entities_tenant_type_identifier",
            set_={
                # Merge new properties INTO existing ones rather than
                # replacing wholesale.  COALESCE handles the case where
                # existing properties is NULL.  Postgres ``||`` on jsonb
                # does a shallow top-level merge — new keys are added,
                # existing keys are overwritten only if present in the
                # incoming dict.
                "properties": text(
                    "COALESCE(entities.properties, '{}'::jsonb) || EXCLUDED.properties"
                ),
                "attribution_status": insert_stmt.excluded.attribution_status,
                "attribution_confidence": insert_stmt.excluded.attribution_confidence,
                "last_observed_at": text("NOW()"),
            },
        ).returning(Entity)

        result = await self._session.execute(
            upsert_stmt, execution_options={"populate_existing": True}
        )
        upserted: list[Entity] = list(result.scalars().all())
        await self._session.flush()
        return upserted

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

    async def update_attribution_scores(
        self,
        *,
        tenant_id: TenantId,
    ) -> int:
        """Re-evaluate attribution scores for all entities in a tenant.

        Queries the ``relationships`` table to count distinct ``collector_id``
        values referencing each entity (as either endpoint), then bulk-updates
        ``attribution_status`` and ``attribution_confidence`` according to the
        tier thresholds defined in SPEC.md:

        - 0-1 collectors -> ``unattributed``, confidence 0.0
        - 2 collectors   -> ``medium``, confidence 0.4
        - 3 collectors   -> ``high``, confidence 0.7
        - 4+ collectors  -> ``confirmed``, confidence 0.9

        Uses a single ``UPDATE ... FROM (VALUES ...)`` statement to apply all
        attribution changes in one round-trip instead of per-entity UPDATEs.

        Returns the number of entities whose attribution was updated (changed
        from their previous value). The caller controls transaction boundaries.
        """
        # --- Subquery: distinct collector_ids per entity -----------------------
        outgoing = select(
            Relationship.from_entity_id.label("entity_id"),
            Relationship.collector_id.label("collector_id"),
        ).where(Relationship.tenant_id == tenant_id)

        incoming = select(
            Relationship.to_entity_id.label("entity_id"),
            Relationship.collector_id.label("collector_id"),
        ).where(Relationship.tenant_id == tenant_id)

        all_refs = union_all(outgoing, incoming).subquery("all_refs")

        collector_counts = (
            select(
                all_refs.c.entity_id,
                func.count(distinct(all_refs.c.collector_id)).label(
                    "collector_count"
                ),
            )
            .group_by(all_refs.c.entity_id)
            .subquery("collector_counts")
        )

        # --- Fetch entities with their collector counts -----------------------
        stmt = (
            select(
                Entity.id,
                Entity.attribution_status,
                Entity.attribution_confidence,
                func.coalesce(collector_counts.c.collector_count, 0).label(
                    "collector_count"
                ),
            )
            .outerjoin(
                collector_counts, Entity.id == collector_counts.c.entity_id
            )
            .where(Entity.tenant_id == tenant_id)
        )
        result = await self._session.execute(stmt)
        rows = list(result.all())

        # --- Compute changes and batch into a single UPDATE -------------------
        updates: list[tuple[UUID, str, Decimal]] = []
        for entity_id, current_status, current_confidence, count in rows:
            # Determine the new tier
            new_status = _DEFAULT_STATUS
            new_confidence = _DEFAULT_CONFIDENCE
            for min_collectors, status, confidence in _ATTRIBUTION_TIERS:
                if count >= min_collectors:
                    new_status = status
                    new_confidence = confidence
                    break

            # Skip if unchanged
            if (
                current_status == new_status
                and str(current_confidence) == new_confidence
            ):
                continue

            # Never downgrade: if entity already has medium+ attribution
            # (e.g., seed entities), don't overwrite with a weaker tier.
            _STATUS_RANK = {"confirmed": 4, "high": 3, "medium": 2, "unattributed": 0}
            if _STATUS_RANK.get(current_status, 0) > _STATUS_RANK.get(new_status, 0):
                continue

            updates.append((entity_id, new_status, Decimal(new_confidence)))

        # --- Second pass: parent-domain attribution inheritance --------
        # Subdomains seen by only one collector stay ``unattributed`` after
        # the collector-count pass above.  If the parent (apex) domain has
        # ``medium`` or higher attribution, the subdomain should inherit at
        # least ``medium`` (confidence 0.400) as a secondary signal.
        #
        # Build the set of entity IDs that the collector-count pass already
        # plans to update so we don't overwrite them.
        updated_ids: set[UUID] = {eid for eid, _, _ in updates}

        # Collect all domain entities for this tenant so we can match
        # subdomains to their apex parent.
        domain_stmt = select(
            Entity.id,
            Entity.canonical_identifier,
            Entity.attribution_status,
        ).where(
            Entity.tenant_id == tenant_id,
            Entity.entity_type == "domain",
        )
        domain_result = await self._session.execute(domain_stmt)
        domain_rows = list(domain_result.all())

        # Map canonical_identifier -> attribution_status for domains that
        # already have ``medium`` or better (either from the DB or from
        # the collector-count updates we just computed).
        _INHERITABLE_STATUSES = {"medium", "high", "confirmed"}

        # Start with the DB-stored status, then overlay any collector-count
        # updates that are about to be flushed.
        domain_status: dict[str, str] = {
            cid: status for _, cid, status in domain_rows
        }
        for eid, new_status, _ in updates:
            # Find the canonical_identifier for this entity id
            for did, cid, _ in domain_rows:
                if did == eid:
                    domain_status[cid] = new_status
                    break

        # Set of apex domains with inheritable attribution
        attributed_apex: set[str] = {
            cid
            for cid, status in domain_status.items()
            if status in _INHERITABLE_STATUSES
        }

        # For every unattributed domain, check if it's a subdomain of an
        # attributed apex domain and promote it.
        _INHERIT_STATUS = "medium"
        _INHERIT_CONFIDENCE = Decimal("0.400")

        for entity_id, cid, current_status in domain_rows:
            # Skip entities already handled by the collector-count pass
            if entity_id in updated_ids:
                continue
            # Only promote unattributed entities
            if current_status != _DEFAULT_STATUS:
                continue
            # Walk up the label hierarchy to find an attributed parent.
            # e.g. "www.example.com" -> check "example.com"
            #      "a.b.example.com" -> check "b.example.com", then "example.com"
            parts = cid.split(".")
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                if parent in attributed_apex:
                    updates.append(
                        (entity_id, _INHERIT_STATUS, _INHERIT_CONFIDENCE)
                    )
                    # Mark so we don't double-add
                    updated_ids.add(entity_id)
                    break

        if not updates:
            return 0

        # Build a VALUES list for a bulk UPDATE ... FROM (VALUES ...) statement.
        # This issues a single UPDATE for all changed entities instead of N
        # individual UPDATEs.
        values_params = [
            {"eid": eid, "new_status": ns, "new_confidence": nc}
            for eid, ns, nc in updates
        ]
        bulk_update = (
            update(Entity.__table__)
            .where(
                Entity.__table__.c.id == bindparam("eid"),
            )
            .values(
                attribution_status=bindparam("new_status"),
                attribution_confidence=bindparam("new_confidence"),
            )
        )
        conn = await self._session.connection()
        await conn.execute(bulk_update, values_params)
        await self._session.flush()
        return len(updates)


__all__ = ["EntityRepository"]


# Forward-compat: keep these here so static type checkers can see the explicit
# UUID/EntityId equivalence at module read time without importing them at
# call-site (the repository accepts NewType-style ids, which are UUIDs at
# runtime).
_ = (UUID, EntityId)
