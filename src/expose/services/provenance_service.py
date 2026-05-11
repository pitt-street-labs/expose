"""Service layer for provenance chain queries.

Extracts entity provenance business logic from the API route handler into a
reusable service class that receives an ``AsyncSession`` via dependency
injection.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from expose.api.provenance import (
    CorrelationSummary,
    ProvenanceObservation,
    ProvenanceRelationship,
    ProvenanceResponse,
    _build_correlation_summary,
)
from expose.db.models import Entity, Relationship
from expose.types.pipeline import ProvenanceRuleApplication


class ProvenanceService:
    """Builds provenance chains for entities.

    Consolidates collector observations, rule evaluations, relationship
    edges, and correlation evidence into a single provenance response.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_provenance(
        self,
        tenant_id: UUID,
        entity_id: UUID,
    ) -> ProvenanceResponse | None:
        """Return the provenance chain for a single entity, or None if not found.

        The caller (route handler) is responsible for mapping None to a 404
        HTTP response.
        """
        # -- Fetch entity (tenant-scoped) ------------------------------------------
        entity_stmt = select(Entity).where(
            Entity.id == entity_id,
            Entity.tenant_id == tenant_id,
        )
        result = await self._session.execute(entity_stmt)
        entity = result.scalar_one_or_none()

        if entity is None:
            return None

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
        rel_result = await self._session.execute(rel_stmt)
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
            other_result = await self._session.execute(other_stmt)
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

        # -- Build correlation evidence -----------------------------------------
        correlation = _build_correlation_summary(
            props=props,
            rules_applied=rules_applied,
            prov_relationships=prov_relationships,
            other_entities=other_entities,
            entity=entity,
            relationships=relationships,
            entity_id=entity_id,
            observations=observations,
        )

        return ProvenanceResponse(
            entity_id=str(entity.id),
            entity_identifier=entity.canonical_identifier,
            entity_type=entity.entity_type,
            attribution_status=entity.attribution_status,
            attribution_confidence=float(entity.attribution_confidence),
            observations=observations,
            rules_applied=rules_applied,
            relationships=prov_relationships,
            correlation=correlation,
        )
