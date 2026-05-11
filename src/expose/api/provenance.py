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
# Predicate-to-dimension mapping (closed vocabulary per SPEC §8.2)
# ---------------------------------------------------------------------------

_PREDICATE_DIMENSION_MAP: dict[str, str] = {
    "target_has_certificate_with_san_in_scope": "cert",
    "target_ip_in_authorized_cloud_account_range": "cloud",
    "target_registrant_matches_authorized_pattern": "whois",
    "target_shares_cert_chain_with_attributed_target": "cert",
    "target_nameserver_matches_authorized_pattern": "nameserver",
    "target_asn_in_authorized_list": "asn",
    "target_subdomain_of_authorized_apex": "subdomain",
    "target_in_explicit_authorization_scope": "explicit",
    "target_observed_by_collectors_count_gte": "observation",
    "target_first_observed_within_days": "recency",
    "target_has_exposure_indicator": "exposure",
    "target_responds_with_authorized_naming_convention": "naming",
}

# Human-readable description templates keyed by dimension.
_DIMENSION_DESCRIPTIONS: dict[str, str] = {
    "cert": "Shares TLS certificate evidence",
    "cloud": "IP in authorized cloud account range",
    "whois": "WHOIS registrant matches authorized pattern",
    "nameserver": "Nameserver matches authorized pattern",
    "asn": "ASN in authorized list",
    "subdomain": "Subdomain of authorized apex domain",
    "explicit": "Explicitly in authorization scope",
    "observation": "Observed by multiple independent collectors",
    "recency": "First observed within recency window",
    "exposure": "Has exposure indicator",
    "naming": "Responds with authorized naming convention",
}

# Relationship edge-type to dimension mapping for fallback evidence.
_EDGE_DIMENSION_MAP: dict[str, str] = {
    "ns_for": "nameserver",
    "certificate_for": "cert",
    "belongs_to": "whois",
    "hosts": "dns",
    "resolves_to": "dns",
    "depends_on": "cloud",
    "cname_for": "dns",
    "mx_for": "dns",
    "acquired_by": "whois",
}

# The complete set of pivot dimensions checked during correlation.
ALL_PIVOT_DIMENSIONS: set[str] = {
    "cert", "dns", "whois", "asn", "nameserver", "subdomain",
    "cloud", "observation", "exposure", "naming", "explicit", "recency",
}


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


class CorrelationEvidence(BaseModel):
    """A single piece of correlation evidence supporting attribution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dimension: str
    description: str
    confidence_delta: float
    source_entity: str | None = None
    source_status: str | None = None
    predicate: str | None = None


class CorrelationSummary(BaseModel):
    """Aggregated correlation evidence for an entity's attribution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    total_confidence: float
    evidence: list[CorrelationEvidence]
    llm_analysis: str | None = None
    pivot_dimensions_checked: int
    pivot_dimensions_matched: int


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
    correlation: CorrelationSummary | None = None


# ---------------------------------------------------------------------------
# Correlation evidence builder
# ---------------------------------------------------------------------------


def _build_correlation_summary(
    *,
    props: dict,
    rules_applied: list[ProvenanceRuleApplication],
    prov_relationships: list[ProvenanceRelationship],
    other_entities: dict[UUID, Entity],
    entity: Entity,
    relationships: list,
    entity_id: UUID,
    observations: list[ProvenanceObservation],
) -> CorrelationSummary:
    """Build a CorrelationSummary from rules, relationships, and observations.

    Strategy:
    1. If rules were applied (_rules_applied is populated), map each rule to
       a CorrelationEvidence entry using the predicate-to-dimension map.
    2. If no rules were applied, fall back to relationship-derived evidence.
    3. Always add an observation-count evidence entry when multiple collectors
       contributed.
    4. Include LLM analysis text if present in properties.
    """
    evidence: list[CorrelationEvidence] = []
    matched_dimensions: set[str] = set()

    # --- Strategy 1: Build from applied rules --------------------------------
    raw_rules = props.get("_rules_applied", [])
    has_rules = isinstance(raw_rules, list) and len(raw_rules) > 0

    if has_rules:
        for rule in raw_rules:
            if not isinstance(rule, dict):
                continue
            rule_id = rule.get("rule_id", "unknown")
            outcome = rule.get("outcome", "unknown")
            delta = float(rule.get("confidence_delta", 0.0))
            predicate = rule.get("predicate")

            # Determine the dimension from the predicate or rule_id
            dimension = None
            if predicate:
                dimension = _PREDICATE_DIMENSION_MAP.get(predicate)

            # Fall back to scanning the predicate map for a match in rule_id
            if dimension is None:
                for pred_key, dim in _PREDICATE_DIMENSION_MAP.items():
                    # Match by substring of rule_id against the predicate key
                    # (e.g., rule_id "cert-san-match" contains "cert")
                    if pred_key in rule_id.lower().replace("-", "_"):
                        dimension = dim
                        break

            # Last resort: infer from rule_id keywords
            if dimension is None:
                dimension = _infer_dimension_from_rule_id(rule_id)

            description = _DIMENSION_DESCRIPTIONS.get(
                dimension or "observation",
                f"Rule {rule_id} evaluated",
            )
            description = f"{description} ({outcome})"

            matched_dimensions.add(dimension or "observation")
            evidence.append(CorrelationEvidence(
                dimension=dimension or "observation",
                description=description,
                confidence_delta=delta,
                source_entity=None,
                source_status=outcome,
                predicate=predicate,
            ))

    # --- Strategy 2: Fall back to relationship-derived evidence ---------------
    if not has_rules and prov_relationships:
        for rel in prov_relationships:
            dimension = _EDGE_DIMENSION_MAP.get(rel.edge_type, "dns")
            description = f"{_edge_type_label(rel.edge_type)} {rel.target_identifier}"
            matched_dimensions.add(dimension)
            evidence.append(CorrelationEvidence(
                dimension=dimension,
                description=description,
                confidence_delta=0.0,
                source_entity=rel.target_identifier,
                source_status=None,
                predicate=None,
            ))

    # --- Strategy 3: Add observation-count evidence --------------------------
    collector_ids: set[str] = set()
    raw_collector_ids = props.get("_collector_ids", [])
    if not raw_collector_ids:
        single = props.get("_collector_id")
        if single:
            raw_collector_ids = [single]
    if isinstance(raw_collector_ids, str):
        raw_collector_ids = [raw_collector_ids]
    collector_ids.update(str(c) for c in raw_collector_ids)
    # Also count relationship-derived collectors
    for obs in observations:
        collector_ids.add(obs.collector_id)

    if len(collector_ids) > 1:
        obs_dim = "observation"
        if obs_dim not in matched_dimensions:
            matched_dimensions.add(obs_dim)
        evidence.append(CorrelationEvidence(
            dimension=obs_dim,
            description=f"Observed by {len(collector_ids)} independent collectors",
            confidence_delta=0.0,
            source_entity=None,
            source_status=None,
            predicate=None,
        ))

    # --- LLM analysis text ---------------------------------------------------
    llm_analysis: str | None = None
    llm_enrichment = props.get("_llm_enrichment")
    if isinstance(llm_enrichment, dict):
        # Try several common keys for the LLM summary text
        llm_analysis = (
            llm_enrichment.get("summary")
            or llm_enrichment.get("analysis")
            or llm_enrichment.get("attribution", {}).get("adjustment_reasoning")
        )
    if not llm_analysis:
        llm_analysis = props.get("_llm_summary")

    # --- Compute totals ------------------------------------------------------
    total_confidence = sum(e.confidence_delta for e in evidence)
    pivot_checked = len(ALL_PIVOT_DIMENSIONS)
    pivot_matched = len(matched_dimensions & ALL_PIVOT_DIMENSIONS)

    return CorrelationSummary(
        total_confidence=round(total_confidence, 4),
        evidence=evidence,
        llm_analysis=llm_analysis,
        pivot_dimensions_checked=pivot_checked,
        pivot_dimensions_matched=pivot_matched,
    )


def _infer_dimension_from_rule_id(rule_id: str) -> str:
    """Best-effort dimension inference from a rule ID string."""
    rid = rule_id.lower()
    keyword_map = {
        "cert": "cert",
        "tls": "cert",
        "san": "cert",
        "cloud": "cloud",
        "whois": "whois",
        "registrant": "whois",
        "org": "whois",
        "nameserver": "nameserver",
        "ns": "nameserver",
        "asn": "asn",
        "subdomain": "subdomain",
        "apex": "subdomain",
        "scope": "explicit",
        "explicit": "explicit",
        "collector": "observation",
        "observed": "observation",
        "recen": "recency",
        "first": "recency",
        "expos": "exposure",
        "naming": "naming",
        "convention": "naming",
        "dns": "dns",
    }
    for keyword, dim in keyword_map.items():
        if keyword in rid:
            return dim
    return "observation"


def _edge_type_label(edge_type: str) -> str:
    """Human-readable prefix for a relationship edge type."""
    labels = {
        "ns_for": "Shares nameserver with",
        "certificate_for": "Shares certificate with",
        "belongs_to": "Belongs to",
        "hosts": "Hosted by",
        "resolves_to": "Resolves to",
        "depends_on": "Depends on",
        "cname_for": "CNAME for",
        "mx_for": "MX for",
        "acquired_by": "Acquired by",
    }
    return labels.get(edge_type, f"{edge_type} relationship with")


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
