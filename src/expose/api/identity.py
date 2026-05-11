"""FastAPI router for Identity Surface endpoints (issue #109).

Provides registrant-identity correlation and organizational graph
construction as commercial module endpoints:

* ``GET /v1/tenants/{tenant_id}/identity/registrant-pivot``
  -- Find related domains by shared registrant attributes
* ``GET /v1/tenants/{tenant_id}/identity/org-graph``
  -- Organizational hierarchy for the tenant's entities

Each endpoint queries entities from the DB (via ``session_factory`` on
``app.state``), feeds them to the Identity Surface module, and returns
the result. If no ``session_factory`` is available, placeholder data is
returned that demonstrates the format with realistic examples.

License-gated per ADR-009. Ethics gate enforced via
``per_tenant_authorization=True`` (always enabled at the API layer since
API access implies tenant authorization).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from expose.modules.identity_surface import check_license
from expose.modules.identity_surface.org_graph import (
    EdgeType,
    NodeType,
    OrgGraphBuilder,
)
from expose.modules.identity_surface.registrant_pivot import (
    PivotDimension,
    RegistrantPivot,
    WhoisEntity,
)

router = APIRouter(
    prefix="/v1/tenants/{tenant_id}/identity",
    tags=["identity"],
)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ClusterMemberResponse(BaseModel):
    """A single domain within a registrant pivot cluster."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    domain: str
    registrant_org: str | None = None
    registrant_email: str | None = None


class PivotClusterResponse(BaseModel):
    """A group of related domains sharing a registrant attribute."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    dimension: str
    key: str
    confidence: float = Field(ge=0.0, le=1.0)
    members: list[ClusterMemberResponse]


class RegistrantPivotResponse(BaseModel):
    """Response for registrant pivot queries."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    query_domain: str
    generated_at: str
    is_placeholder: bool = True
    total_clusters: int
    clusters: list[PivotClusterResponse]


class GraphNodeResponse(BaseModel):
    """A node in the organizational graph."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str
    node_type: str
    properties: dict[str, Any] = {}


class GraphEdgeResponse(BaseModel):
    """A directed edge in the organizational graph."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str
    target: str
    edge_type: str
    confidence: float = Field(ge=0.0, le=1.0)


class OrgGraphResponse(BaseModel):
    """Response for organizational graph queries."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    generated_at: str
    is_placeholder: bool = True
    total_nodes: int
    total_edges: int
    nodes: list[GraphNodeResponse]
    edges: list[GraphEdgeResponse]


# ---------------------------------------------------------------------------
# Placeholder data
# ---------------------------------------------------------------------------

_PLACEHOLDER_WHOIS_ENTITIES: list[dict[str, Any]] = [
    {
        "domain": "acme-corp.com",
        "registrant_org": "Acme Corporation",
        "registrant_email": "domains@acme-corp.com",
        "registrant_city": "San Francisco",
        "registrant_country": "US",
        "name_servers": ["ns1.acmedns.net", "ns2.acmedns.net"],
    },
    {
        "domain": "acme-corp.net",
        "registrant_org": "ACME Corp",
        "registrant_email": "admin@acme-corp.com",
        "registrant_city": "San Francisco",
        "registrant_country": "US",
        "name_servers": ["ns1.acmedns.net", "ns2.acmedns.net"],
    },
    {
        "domain": "acme-labs.io",
        "registrant_org": "Acme Corp.",
        "registrant_email": "hostmaster@acme-corp.com",
        "registrant_city": "San Francisco",
        "registrant_country": "US",
        "name_servers": ["ns1.acmedns.net", "ns2.acmedns.net"],
    },
    {
        "domain": "globex.com",
        "registrant_org": "Globex Corporation",
        "registrant_email": "dns@globex.com",
        "registrant_city": "New York",
        "registrant_country": "US",
        "name_servers": ["ns1.globexdns.com", "ns2.globexdns.com"],
    },
    {
        "domain": "globex.io",
        "registrant_org": "Globex Corp",
        "registrant_email": "admin@globex.com",
        "registrant_city": "New York",
        "registrant_country": "US",
        "name_servers": ["ns1.globexdns.com", "ns2.globexdns.com"],
    },
]

_PLACEHOLDER_MA_DATA: list[dict[str, Any]] = [
    {
        "acquirer": "Acme Corporation",
        "target": "Widget Co",
        "relationship": "acquired_by",
        "confidence": 0.9,
        "properties": {"date": "2024-01-15"},
    },
    {
        "acquirer": "Globex Corporation",
        "target": "Initech LLC",
        "relationship": "parent_subsidiary",
        "confidence": 0.85,
    },
]

_PLACEHOLDER_DNS_DATA: list[dict[str, Any]] = [
    {
        "parent_domain": "acme-corp.com",
        "child_domain": "api.acme-corp.com",
        "relationship": "dns_delegation",
        "confidence": 0.9,
        "ip_ranges": ["198.51.100.0/24"],
    },
    {
        "parent_domain": "globex.com",
        "child_domain": "mail.globex.com",
        "confidence": 0.8,
    },
]


# ---------------------------------------------------------------------------
# DB query helper
# ---------------------------------------------------------------------------


async def _fetch_whois_entities_from_db(
    session_factory: Any,
    tenant_id: UUID,
    *,
    domain_filter: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]] | None:
    """Query domain entities from the database and extract WHOIS data.

    Returns ``None`` when no ``session_factory`` is available or the query
    yields no results, signaling the caller to fall back to placeholder data.
    """
    if session_factory is None:
        return None

    from sqlalchemy import select  # noqa: PLC0415

    from expose.db.models import Entity  # noqa: PLC0415

    async with session_factory() as session:
        stmt = (
            select(Entity)
            .where(
                Entity.tenant_id == tenant_id,
                Entity.entity_type == "domain",
            )
            .order_by(Entity.last_observed_at.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        rows = result.scalars().all()

    if not rows:
        return None

    entities: list[dict[str, Any]] = []
    for row in rows:
        props = row.properties or {}
        entity: dict[str, Any] = {
            "domain": row.canonical_identifier,
            "registrant_org": props.get("registrant_org"),
            "registrant_email": props.get("registrant_email"),
            "registrant_city": props.get("registrant_city"),
            "registrant_country": props.get("registrant_country"),
            "name_servers": props.get("name_servers", []),
        }
        entities.append(entity)

    if domain_filter:
        # Include the queried domain even if not in tenant (for pivot context),
        # and filter to entities that share at least one registrant dimension
        # with the queried domain. For now, return all -- the pivot engine
        # handles clustering.
        pass

    return entities if entities else None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/registrant-pivot")
async def get_registrant_pivot(
    request: Request,
    tenant_id: UUID,
    domain: str = Query(
        description="Domain to pivot on -- find related domains by shared registrant",
    ),
    fuzzy_threshold: float = Query(
        default=0.85,
        ge=0.5,
        le=1.0,
        description="Minimum fuzzy match ratio for org name comparison",
    ),
) -> RegistrantPivotResponse:
    """Find related domains that share registrant attributes with the query domain.

    Uses WHOIS/RDAP registrant data to cluster domains by org name (fuzzy),
    email domain, address (city+country), and name server patterns.

    When a database is available, real entities are used. Otherwise,
    placeholder data demonstrates the format.

    License-gated per ADR-009. Returns 403 if module is not licensed.
    """
    if not check_license():
        raise HTTPException(
            status_code=403,
            detail="Identity Surface module is not licensed. See ADR-009.",
        )

    session_factory = getattr(request.app.state, "session_factory", None)
    db_entities = await _fetch_whois_entities_from_db(
        session_factory, tenant_id, domain_filter=domain,
    )
    is_placeholder = db_entities is None

    if is_placeholder:
        raw_entities = _PLACEHOLDER_WHOIS_ENTITIES
    else:
        raw_entities = db_entities

    # Coerce to WhoisEntity models and run the pivot.
    whois_entities = [WhoisEntity.model_validate(e) for e in raw_entities]

    pivot = RegistrantPivot(
        per_tenant_authorization=True,
        fuzzy_threshold=fuzzy_threshold,
    )
    result = pivot.pivot(whois_entities)

    # Filter clusters to those containing the query domain (or all if placeholder).
    clusters: list[PivotClusterResponse] = []
    for cluster in result.clusters:
        member_domains = {m.domain for m in cluster.members}
        # In placeholder mode, include all clusters for demo purposes.
        # In production, only include clusters that contain the queried domain.
        if is_placeholder or domain.lower().strip() in member_domains:
            clusters.append(
                PivotClusterResponse(
                    dimension=str(cluster.dimension.value),
                    key=cluster.key,
                    confidence=cluster.confidence,
                    members=[
                        ClusterMemberResponse(
                            domain=m.domain,
                            registrant_org=m.registrant_org,
                            registrant_email=m.registrant_email,
                        )
                        for m in cluster.members
                    ],
                )
            )

    now = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    return RegistrantPivotResponse(
        tenant_id=tenant_id,
        query_domain=domain,
        generated_at=now,
        is_placeholder=is_placeholder,
        total_clusters=len(clusters),
        clusters=clusters,
    )


@router.get("/org-graph")
async def get_org_graph(
    request: Request,
    tenant_id: UUID,
    include_dns: bool = Query(
        default=True,
        description="Include DNS delegation relationships in the graph",
    ),
    include_ma: bool = Query(
        default=True,
        description="Include M&A (mergers and acquisitions) relationships",
    ),
) -> OrgGraphResponse:
    """Return the organizational hierarchy graph for this tenant's entities.

    Builds a directed graph from registrant pivot results, M&A discovery
    data, and DNS relationship data. Nodes represent organizations, domains,
    and IP ranges; edges represent typed relationships.

    When a database is available, real entities are used. Otherwise,
    placeholder data demonstrates the format.

    License-gated per ADR-009. Returns 403 if module is not licensed.
    """
    if not check_license():
        raise HTTPException(
            status_code=403,
            detail="Identity Surface module is not licensed. See ADR-009.",
        )

    session_factory = getattr(request.app.state, "session_factory", None)
    db_entities = await _fetch_whois_entities_from_db(session_factory, tenant_id)
    is_placeholder = db_entities is None

    if is_placeholder:
        raw_entities = _PLACEHOLDER_WHOIS_ENTITIES
        ma_data = _PLACEHOLDER_MA_DATA if include_ma else []
        dns_data = _PLACEHOLDER_DNS_DATA if include_dns else []
    else:
        raw_entities = db_entities
        ma_data = [] if include_ma else []  # DB M&A data would go here
        dns_data = [] if include_dns else []  # DB DNS data would go here

    # Build pivot results first, then construct the graph.
    whois_entities = [WhoisEntity.model_validate(e) for e in raw_entities]
    pivot = RegistrantPivot(per_tenant_authorization=True)
    pivot_result = pivot.pivot(whois_entities)

    builder = OrgGraphBuilder(per_tenant_authorization=True)
    builder.add_pivot_results(pivot_result)

    if ma_data:
        builder.add_ma_results(ma_data)
    if dns_data:
        builder.add_dns_relationships(dns_data)

    graph = builder.build()

    now = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    nodes = [
        GraphNodeResponse(
            node_id=n.node_id,
            node_type=n.node_type.value,
            properties=dict(n.properties),
        )
        for n in graph.nodes
    ]
    edges = [
        GraphEdgeResponse(
            source=e.source,
            target=e.target,
            edge_type=e.edge_type.value,
            confidence=e.confidence,
        )
        for e in graph.edges
    ]

    return OrgGraphResponse(
        tenant_id=tenant_id,
        generated_at=now,
        is_placeholder=is_placeholder,
        total_nodes=len(nodes),
        total_edges=len(edges),
        nodes=nodes,
        edges=edges,
    )
