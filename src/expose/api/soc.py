"""FastAPI router for SOC Threat Package endpoints (issue #115).

Produces actionable threat intelligence packages for SOC teams:

* ``GET /v1/tenants/{tenant_id}/soc/stix``  -- STIX 2.1 bundle JSON
* ``GET /v1/tenants/{tenant_id}/soc/misp``  -- MISP event JSON
* ``GET /v1/tenants/{tenant_id}/soc/ioc-feed``  -- IoC feed JSON
* ``GET /v1/tenants/{tenant_id}/soc/suspicious``  -- Suspicious endpoints

Each endpoint queries entities from the DB (via ``session_factory`` on
``app.state``), feeds them to ``SocPackageGenerator``, and returns the
result. If no ``session_factory`` is available, placeholder data is returned
that demonstrates the format with realistic examples.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from expose.modules.soc_package.generator import (
    Severity,
    SocPackageGenerator,
)

router = APIRouter(prefix="/v1/tenants/{tenant_id}/soc", tags=["soc"])

# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class StixBundleResponse(BaseModel):
    """Wraps a STIX 2.1 bundle with metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    generated_at: str
    is_placeholder: bool = True
    bundle: dict[str, Any]


class MispEventResponse(BaseModel):
    """Wraps a MISP event with metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    generated_at: str
    is_placeholder: bool = True
    event: dict[str, Any]


class IoCFeedResponse(BaseModel):
    """Wraps an IoC feed with metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    generated_at: str
    is_placeholder: bool = True
    total_indicators: int
    indicators: list[dict[str, Any]]


class SuspiciousEndpointEntry(BaseModel):
    """A single suspicious endpoint in the response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_identifier: str
    reason: str
    severity: str
    recommended_action: str


class SuspiciousEndpointResponse(BaseModel):
    """Wraps suspicious endpoint detection results."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    generated_at: str
    is_placeholder: bool = True
    total_suspicious: int
    endpoints: list[SuspiciousEndpointEntry]


# ---------------------------------------------------------------------------
# Placeholder data
# ---------------------------------------------------------------------------

_PLACEHOLDER_ENTITIES: list[dict[str, Any]] = [
    {
        "entity_type": "domain",
        "canonical_identifier": "staging.example.com",
        "properties": {
            "open_ports": [{"port": 22}, {"port": 3389}],
            "has_waf": False,
            "response_headers": {"X-Debug": "true", "X-Powered-By": "Express"},
            "has_stack_trace": True,
            "_lead_score": 92,
            "attack_techniques": ["T1595", "T1592"],
        },
        "attribution_confidence": 0.85,
    },
    {
        "entity_type": "ip",
        "canonical_identifier": "203.0.113.42",
        "properties": {
            "open_ports": [{"port": 22}, {"port": 5900}],
            "has_waf": False,
            "dnsbl_listed": True,
            "dnsbl_lists": ["zen.spamhaus.org", "bl.spamcop.net"],
            "_lead_score": 85,
            "attack_techniques": ["T1595.001"],
        },
        "attribution_confidence": 0.70,
    },
    {
        "entity_type": "certificate",
        "canonical_identifier": "ab:cd:ef:01:23:45:67:89",
        "properties": {
            "serial_number": "ABCDEF0123456789",
            "is_self_signed": True,
            "_lead_score": 74,
        },
        "attribution_confidence": 0.60,
    },
    {
        "entity_type": "domain",
        "canonical_identifier": "admin.example.com",
        "properties": {
            "zone_transfer_allowed": True,
            "is_self_signed": True,
            "_lead_score": 71,
            "attack_techniques": ["T1590.002"],
        },
        "attribution_confidence": 0.90,
    },
    {
        "entity_type": "domain",
        "canonical_identifier": "api.example.com",
        "properties": {
            "response_headers": {"X-Debug-Token": "abc123"},
            "has_stack_trace": True,
            "_lead_score": 63,
            "attack_techniques": ["T1190"],
        },
        "attribution_confidence": 0.95,
    },
]

_PLACEHOLDER_RELATIONSHIPS: list[dict[str, Any]] = [
    {
        "from_identifier": "staging.example.com",
        "to_identifier": "203.0.113.42",
        "edge_type": "resolves-to",
        "confidence": 0.95,
    },
    {
        "from_identifier": "admin.example.com",
        "to_identifier": "203.0.113.42",
        "edge_type": "resolves-to",
        "confidence": 0.90,
    },
]


# ---------------------------------------------------------------------------
# DB query helper
# ---------------------------------------------------------------------------


async def _fetch_entities_from_db(
    session_factory: Any,
    tenant_id: UUID,
    *,
    limit: int = 500,
) -> list[dict[str, Any]] | None:
    """Query entities from the database and return as dicts.

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
            .where(Entity.tenant_id == tenant_id)
            .order_by(Entity.last_observed_at.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        rows = result.scalars().all()

    if not rows:
        return None

    entities: list[dict[str, Any]] = []
    for row in rows:
        entities.append({
            "entity_type": row.entity_type,
            "canonical_identifier": row.canonical_identifier,
            "properties": row.properties or {},
            "attribution_confidence": float(row.attribution_confidence),
        })

    return entities


async def _fetch_relationships_from_db(
    session_factory: Any,
    tenant_id: UUID,
    *,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """Query relationships from the database and return as dicts.

    Returns an empty list when no ``session_factory`` is available or the
    query yields no results.
    """
    if session_factory is None:
        return []

    from sqlalchemy import select  # noqa: PLC0415

    from expose.db.models import Entity, Relationship  # noqa: PLC0415

    async with session_factory() as session:
        # Join to resolve entity identifiers from IDs.
        stmt = (
            select(
                Relationship,
                Entity.canonical_identifier.label("from_identifier"),
            )
            .join(Entity, Relationship.from_entity_id == Entity.id)
            .where(Relationship.tenant_id == tenant_id)
            .order_by(Relationship.observed_at.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        rows = result.all()

    if not rows:
        return []

    # We need to_identifier too -- fetch a second join or build a lookup.
    # For simplicity, build an entity ID -> identifier map.
    entity_ids: set[UUID] = set()
    for row in rows:
        rel = row[0]
        entity_ids.add(rel.from_entity_id)
        entity_ids.add(rel.to_entity_id)

    id_to_identifier: dict[UUID, str] = {}
    if entity_ids:
        from sqlalchemy import select as sa_select  # noqa: PLC0415

        async with session_factory() as session:
            id_stmt = (
                sa_select(Entity.id, Entity.canonical_identifier)
                .where(Entity.id.in_(entity_ids))
            )
            id_result = await session.execute(id_stmt)
            for eid, cid in id_result.all():
                id_to_identifier[eid] = cid

    relationships: list[dict[str, Any]] = []
    for row in rows:
        rel = row[0]
        from_id = id_to_identifier.get(rel.from_entity_id, "")
        to_id = id_to_identifier.get(rel.to_entity_id, "")
        relationships.append({
            "from_identifier": from_id,
            "to_identifier": to_id,
            "edge_type": rel.edge_type,
            "confidence": float(rel.confidence),
        })

    return relationships


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/stix")
async def get_stix_bundle(
    request: Request,
    tenant_id: UUID,
    tlp: str = Query(default="TLP:AMBER", description="TLP marking level"),
) -> StixBundleResponse:
    """Return a STIX 2.1 bundle for all entities in this tenant.

    When a database is available, real entities are used. Otherwise,
    placeholder data demonstrates the format.
    """
    session_factory = getattr(request.app.state, "session_factory", None)
    entities = await _fetch_entities_from_db(session_factory, tenant_id)
    is_placeholder = entities is None

    if is_placeholder:
        entities = _PLACEHOLDER_ENTITIES
        relationships = _PLACEHOLDER_RELATIONSHIPS
    else:
        relationships = await _fetch_relationships_from_db(
            session_factory, tenant_id
        )

    generator = SocPackageGenerator(tlp_level=tlp)
    bundle = generator.generate_stix_bundle(entities, relationships)
    now = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    return StixBundleResponse(
        tenant_id=tenant_id,
        generated_at=now,
        is_placeholder=is_placeholder,
        bundle=bundle,
    )


@router.get("/misp")
async def get_misp_event(
    request: Request,
    tenant_id: UUID,
) -> MispEventResponse:
    """Return a MISP event for all entities in this tenant.

    When a database is available, real entities are used. Otherwise,
    placeholder data demonstrates the format.
    """
    session_factory = getattr(request.app.state, "session_factory", None)
    entities = await _fetch_entities_from_db(session_factory, tenant_id)
    is_placeholder = entities is None

    if is_placeholder:
        entities = _PLACEHOLDER_ENTITIES

    generator = SocPackageGenerator()
    event = generator.generate_misp_event(entities)
    now = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    return MispEventResponse(
        tenant_id=tenant_id,
        generated_at=now,
        is_placeholder=is_placeholder,
        event=event,
    )


@router.get("/ioc-feed")
async def get_ioc_feed(
    request: Request,
    tenant_id: UUID,
    min_confidence: int = Query(default=0, ge=0, le=100),
) -> IoCFeedResponse:
    """Return an IoC feed for all entities in this tenant.

    When a database is available, real entities are used. Otherwise,
    placeholder data demonstrates the format.
    """
    session_factory = getattr(request.app.state, "session_factory", None)
    entities = await _fetch_entities_from_db(session_factory, tenant_id)
    is_placeholder = entities is None

    if is_placeholder:
        entities = _PLACEHOLDER_ENTITIES

    generator = SocPackageGenerator()
    feed = generator.generate_ioc_feed(entities)

    # Apply min_confidence filter.
    if min_confidence > 0:
        feed = [
            entry for entry in feed
            if entry.get("confidence", 0) >= min_confidence
        ]

    now = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    return IoCFeedResponse(
        tenant_id=tenant_id,
        generated_at=now,
        is_placeholder=is_placeholder,
        total_indicators=len(feed),
        indicators=feed,
    )


@router.get("/suspicious")
async def get_suspicious_endpoints(
    request: Request,
    tenant_id: UUID,
    min_severity: str = Query(
        default="info",
        description="Minimum severity filter (info, low, medium, high, critical)",
    ),
) -> SuspiciousEndpointResponse:
    """Return suspicious endpoints detected among tenant entities.

    When a database is available, real entities are used. Otherwise,
    placeholder data demonstrates the format.
    """
    session_factory = getattr(request.app.state, "session_factory", None)
    entities = await _fetch_entities_from_db(session_factory, tenant_id)
    is_placeholder = entities is None

    if is_placeholder:
        entities = _PLACEHOLDER_ENTITIES

    generator = SocPackageGenerator()
    endpoints = generator.detect_suspicious_endpoints(entities)

    # Apply severity filter.
    severity_order = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    try:
        min_sev = Severity(min_severity.lower())
    except ValueError:
        min_sev = Severity.INFO

    min_sev_level = severity_order.get(min_sev, 0)
    filtered = [
        ep for ep in endpoints
        if severity_order.get(ep.severity, 0) >= min_sev_level
    ]

    now = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    response_endpoints = [
        SuspiciousEndpointEntry(
            entity_identifier=ep.entity_identifier,
            reason=ep.reason,
            severity=ep.severity.value,
            recommended_action=ep.recommended_action,
        )
        for ep in filtered
    ]

    return SuspiciousEndpointResponse(
        tenant_id=tenant_id,
        generated_at=now,
        is_placeholder=is_placeholder,
        total_suspicious=len(response_endpoints),
        endpoints=response_endpoints,
    )
