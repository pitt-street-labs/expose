"""FastAPI router for the observation graph data endpoint.

Serves the D3 force-directed renderer (``graph.js``) with node and edge data
for a tenant's observation graph.  The endpoint is tenant-scoped per ADR-007.

* **Get graph** — ``GET /v1/tenants/{tenant_id}/graph`` → 200

Nodes correspond to :class:`~expose.db.models.Entity` rows;
edges correspond to :class:`~expose.db.models.Relationship` rows.
``collector_count`` is computed as the number of distinct ``collector_id``
values across all relationships touching a given entity.
``attribution_confidence`` is read directly from the entity column
(defaults to ``0.0`` if somehow absent).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy import distinct, func, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from expose.api.tenants import get_session
from expose.db.models import Entity, Relationship

# ---------------------------------------------------------------------------
# Session dependency — reuses the same placeholder as tenants.py.
# ---------------------------------------------------------------------------

SessionDep = Annotated[AsyncSession, Depends(get_session)]


# ---------------------------------------------------------------------------
# Response models (frozen — immutable once built)
# ---------------------------------------------------------------------------


class GraphNode(BaseModel):
    """A single node in the observation graph, rendered as a D3 circle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    label: str
    entity_type: str
    attribution_status: str
    attribution_confidence: float
    collector_count: int
    first_observed: datetime | None = None


class GraphEdge(BaseModel):
    """A single edge in the observation graph, rendered as a D3 link."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str
    target: str
    relationship_type: str
    collector_id: str | None = None


class GraphData(BaseModel):
    """Top-level response containing the full observation graph for D3."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    nodes: list[GraphNode]
    edges: list[GraphEdge]


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(tags=["graph"])


@router.get("/v1/tenants/{tenant_id}/graph", response_model=GraphData)
async def get_graph(
    tenant_id: UUID,
    session: SessionDep,
) -> GraphData:
    """Return the observation graph for D3 rendering.

    Queries all entities for the tenant as nodes and all relationships as
    edges.  ``collector_count`` is computed via a subquery counting distinct
    ``collector_id`` values from relationships where the entity appears as
    either endpoint.
    """
    # -- Subquery: count distinct collector_ids per entity -------------------
    # Union both directions so an entity that only appears on one side of a
    # relationship still gets its collector counted.
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
            func.count(distinct(all_refs.c.collector_id)).label("collector_count"),
        )
        .group_by(all_refs.c.entity_id)
        .subquery("collector_counts")
    )

    # -- Main entity query with left-joined collector count -----------------
    stmt = (
        select(
            Entity,
            func.coalesce(collector_counts.c.collector_count, 0).label("collector_count"),
        )
        .outerjoin(collector_counts, Entity.id == collector_counts.c.entity_id)
        .where(Entity.tenant_id == tenant_id)
    )
    result = await session.execute(stmt)
    rows = list(result.all())

    nodes: list[GraphNode] = []
    for entity, count in rows:
        nodes.append(
            GraphNode(
                id=str(entity.id),
                label=entity.canonical_identifier,
                entity_type=entity.entity_type,
                attribution_status=entity.attribution_status,
                attribution_confidence=float(entity.attribution_confidence),
                collector_count=int(count),
                first_observed=entity.first_observed_at,
            )
        )

    # -- Relationships → edges ----------------------------------------------
    edge_stmt = select(Relationship).where(Relationship.tenant_id == tenant_id)
    edge_result = await session.execute(edge_stmt)
    relationships = list(edge_result.scalars().all())

    edges: list[GraphEdge] = [
        GraphEdge(
            source=str(rel.from_entity_id),
            target=str(rel.to_entity_id),
            relationship_type=rel.edge_type,
            collector_id=rel.collector_id,
        )
        for rel in relationships
    ]

    return GraphData(nodes=nodes, edges=edges)
