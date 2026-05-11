"""FastAPI router for the provenance chain query endpoint.

Serves the provenance chain for a single entity — a consolidated view of
which collectors observed it, when, which attribution rules have been
applied, and which relationships connect it to other entities in the
observation graph.

* **Get provenance** — ``GET /v1/tenants/{tenant_id}/entities/{entity_id}/provenance`` → 200 | 404

The provenance chain is the primary trust-verification mechanism in the
EXPOSE UI — it answers "why do we think this entity belongs to the target?"
by surfacing every observation, rule evaluation, and relationship that
contributed to the current attribution status.

Per ADR-007 all queries are tenant-scoped; a cross-tenant request returns
404 (intentional invisibility).
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from expose.api.tenants import get_session
from expose.db.models import Entity, Relationship
from expose.types.pipeline import ProvenanceRuleApplication

# ---------------------------------------------------------------------------
# Session dependency — reuses the same placeholder as tenants.py.
# ---------------------------------------------------------------------------

SessionDep = Annotated[AsyncSession, Depends(get_session)]


# ---------------------------------------------------------------------------
# Response models (frozen — immutable once built)
# ---------------------------------------------------------------------------


class ProvenanceObservation(BaseModel):
    """A single collector observation contributing to this entity's provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    collector_id: str
    observed_at: str | None
    observation_type: str | None


class ProvenanceRelationship(BaseModel):
    """A relationship edge connecting this entity to another in the graph."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    edge_type: str
    target_identifier: str
    target_type: str


class ProvenanceResponse(BaseModel):
    """Full provenance chain for a single entity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_id: str
    entity_identifier: str
    entity_type: str
    attribution_status: str
    attribution_confidence: float
    observations: list[ProvenanceObservation]
    rules_applied: list[ProvenanceRuleApplication]
    relationships: list[ProvenanceRelationship]


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(tags=["provenance"])


@router.get(
    "/v1/tenants/{tenant_id}/entities/{entity_id}/provenance",
    response_model=ProvenanceResponse,
)
async def get_provenance(
    tenant_id: UUID,
    entity_id: UUID,
    session: SessionDep,
) -> ProvenanceResponse:
    """Return the provenance chain for a single entity.

    The provenance chain consolidates:

    1. **Observations** — extracted from the entity's ``properties`` dict.
       Collectors store ``_collector_id``, ``_observed_at``, and
       ``_observation_type`` as internal property keys when they observe
       an entity. Additionally, every relationship touching this entity
       contributes an observation (the relationship's ``collector_id`` and
       ``observed_at`` fields).

    2. **Rules applied** — extracted from the ``_rules_applied`` list in
       the entity's ``properties`` dict, if present. Each entry is a dict
       with ``rule_id``, ``outcome``, and ``confidence_delta`` keys.

    3. **Relationships** — all edges (incoming and outgoing) involving this
       entity. For each edge, the *other* entity's identifier and type are
       resolved by joining back to the entities table.

    Returns 404 if the entity does not exist under the given tenant (or
    exists under a different tenant — cross-tenant invisibility per ADR-007).
    """
    # -- Fetch entity (tenant-scoped) ------------------------------------------
    entity_stmt = select(Entity).where(
        Entity.id == entity_id,
        Entity.tenant_id == tenant_id,
    )
    result = await session.execute(entity_stmt)
    entity = result.scalar_one_or_none()

    if entity is None:
        raise HTTPException(
            status_code=404,
            detail=f"Entity {entity_id} not found in tenant {tenant_id}",
        )

    # -- Extract observations from entity properties --------------------------
    props = entity.properties or {}
    observations: list[ProvenanceObservation] = []

    # Primary observation from the entity's own collector metadata
    if props.get("_collector_id"):
        observations.append(
            ProvenanceObservation(
                collector_id=str(props["_collector_id"]),
                observed_at=str(props["_observed_at"]) if props.get("_observed_at") else None,
                observation_type=str(props["_observation_type"]) if props.get("_observation_type") else None,
            )
        )

    # -- Fetch relationships (both directions) ---------------------------------
    rel_stmt = (
        select(Relationship)
        .where(
            Relationship.tenant_id == tenant_id,
            or_(
                Relationship.from_entity_id == entity_id,
                Relationship.to_entity_id == entity_id,
            ),
        )
        .order_by(Relationship.observed_at.desc())
        .limit(200)
    )
    rel_result = await session.execute(rel_stmt)
    relationships = list(rel_result.scalars().all())

    # Collect the IDs of the "other" entity for each relationship
    other_entity_ids: set[UUID] = set()
    for rel in relationships:
        if rel.from_entity_id == entity_id:
            other_entity_ids.add(rel.to_entity_id)
        else:
            other_entity_ids.add(rel.from_entity_id)

    # Batch-fetch other entities for identifier/type resolution
    other_entities: dict[UUID, Entity] = {}
    if other_entity_ids:
        other_stmt = select(Entity).where(
            Entity.id.in_(other_entity_ids),
            Entity.tenant_id == tenant_id,
        )
        other_result = await session.execute(other_stmt)
        for ent in other_result.scalars().all():
            other_entities[ent.id] = ent

    # Additional observations from relationship collector metadata
    seen_collector_obs: set[str] = set()
    if observations:
        seen_collector_obs.add(observations[0].collector_id)

    for rel in relationships:
        obs_key = rel.collector_id
        if obs_key not in seen_collector_obs:
            seen_collector_obs.add(obs_key)
            observations.append(
                ProvenanceObservation(
                    collector_id=rel.collector_id,
                    observed_at=rel.observed_at.isoformat() if rel.observed_at else None,
                    observation_type="relationship",
                )
            )

    # Build relationship response objects
    prov_relationships: list[ProvenanceRelationship] = []
    for rel in relationships:
        if rel.from_entity_id == entity_id:
            other_id = rel.to_entity_id
        else:
            other_id = rel.from_entity_id

        other_ent = other_entities.get(other_id)
        prov_relationships.append(
            ProvenanceRelationship(
                edge_type=rel.edge_type,
                target_identifier=other_ent.canonical_identifier if other_ent else str(other_id),
                target_type=other_ent.entity_type if other_ent else "unknown",
            )
        )

    # -- Extract rules applied from properties --------------------------------
    rules_applied: list[ProvenanceRuleApplication] = []
    raw_rules = props.get("_rules_applied", [])
    if isinstance(raw_rules, list):
        for rule in raw_rules:
            if isinstance(rule, dict):
                rules_applied.append(ProvenanceRuleApplication(
                    rule_id=rule.get("rule_id", "unknown"),
                    outcome=rule.get("outcome", "unknown"),
                    confidence_delta=rule.get("confidence_delta", 0.0),
                ))

    return ProvenanceResponse(
        entity_id=str(entity.id),
        entity_identifier=entity.canonical_identifier,
        entity_type=entity.entity_type,
        attribution_status=entity.attribution_status,
        attribution_confidence=float(entity.attribution_confidence),
        observations=observations,
        rules_applied=rules_applied,
        relationships=prov_relationships,
    )
