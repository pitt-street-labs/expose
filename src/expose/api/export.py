"""FastAPI router for CSV export of filtered entities.

Implements the quick-export feature described in issue #66:

* **Export** — ``GET /v1/tenants/{tenant_id}/export/csv`` → StreamingResponse (text/csv)

Phase 1 uses in-memory placeholder data (same pattern as the UI router's
``_PLACEHOLDER_ENTITIES``). When a database session factory is available on
``request.app.state.session_factory``, entities are queried from the
``entities`` table with optional filters applied.

Filters (all optional, via query params):
  - ``entity_type`` — e.g. ``domain``, ``ip_address``, ``certificate``
  - ``attribution_tier`` — e.g. ``confirmed``, ``high``, ``medium``, ``requires_review``
  - ``collector_id`` — matches inside the properties JSON (Phase 2)
  - ``environment`` — matches the ``environment`` property (Phase 2)
  - ``limit`` — max rows returned (default 10,000, capped at 10,000)
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

router = APIRouter(prefix="/v1/tenants/{tenant_id}/export", tags=["export"])

# ---------------------------------------------------------------------------
# CSV column specification
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "entity_identifier",
    "entity_type",
    "attribution_tier",
    "confidence",
    "collectors",
    "first_seen",
    "last_seen",
    "environment",
    "risk_summary",
]

# ---------------------------------------------------------------------------
# Phase 1 placeholder data — mirrors UI router pattern
# ---------------------------------------------------------------------------

_PLACEHOLDER_ENTITIES = [
    {
        "entity_identifier": "example.com",
        "entity_type": "domain",
        "attribution_tier": "confirmed",
        "confidence": "0.950",
        "collectors": "ct_crtsh,dns_subdomain_enum",
        "first_seen": "2026-05-10T08:00:00Z",
        "last_seen": "2026-05-10T12:30:00Z",
        "environment": "production",
        "risk_summary": "Apex domain, 3 subdomains attributed",
    },
    {
        "entity_identifier": "api.example.com",
        "entity_type": "domain",
        "attribution_tier": "high",
        "confidence": "0.870",
        "collectors": "dns_subdomain_enum",
        "first_seen": "2026-05-10T08:15:00Z",
        "last_seen": "2026-05-10T12:30:00Z",
        "environment": "production",
        "risk_summary": "API endpoint, TLS valid",
    },
    {
        "entity_identifier": "203.0.113.42",
        "entity_type": "ip_address",
        "attribution_tier": "requires_review",
        "confidence": "0.410",
        "collectors": "dns_reverse_ptr",
        "first_seen": "2026-05-10T09:00:00Z",
        "last_seen": "2026-05-10T12:30:00Z",
        "environment": "unknown",
        "risk_summary": "Reverse PTR match, no corroboration",
    },
    {
        "entity_identifier": "mail.example.com",
        "entity_type": "domain",
        "attribution_tier": "medium",
        "confidence": "0.620",
        "collectors": "dns_subdomain_enum,email_auth",
        "first_seen": "2026-05-10T09:30:00Z",
        "last_seen": "2026-05-10T12:30:00Z",
        "environment": "production",
        "risk_summary": "MX record, SPF aligned",
    },
    {
        "entity_identifier": "198.51.100.7",
        "entity_type": "ip_address",
        "attribution_tier": "confirmed",
        "confidence": "0.980",
        "collectors": "rdap_whois,bgp_ripestat",
        "first_seen": "2026-05-10T10:00:00Z",
        "last_seen": "2026-05-10T12:30:00Z",
        "environment": "production",
        "risk_summary": "WHOIS-confirmed, ASN match",
    },
    {
        "entity_identifier": "*.example.com",
        "entity_type": "certificate",
        "attribution_tier": "high",
        "confidence": "0.890",
        "collectors": "ct_crtsh",
        "first_seen": "2026-05-10T08:05:00Z",
        "last_seen": "2026-05-10T12:30:00Z",
        "environment": "production",
        "risk_summary": "Wildcard cert, Let's Encrypt issued",
    },
    {
        "entity_identifier": "Example Corp",
        "entity_type": "organization",
        "attribution_tier": "confirmed",
        "confidence": "0.990",
        "collectors": "rdap_whois",
        "first_seen": "2026-05-10T08:00:00Z",
        "last_seen": "2026-05-10T12:30:00Z",
        "environment": "corporate",
        "risk_summary": "WHOIS registrant org, seed anchor",
    },
    {
        "entity_identifier": "staging.example.com",
        "entity_type": "domain",
        "attribution_tier": "medium",
        "confidence": "0.550",
        "collectors": "dns_subdomain_enum",
        "first_seen": "2026-05-10T10:45:00Z",
        "last_seen": "2026-05-10T12:30:00Z",
        "environment": "staging",
        "risk_summary": "Staging subdomain, no TLS",
    },
]


def _filter_entities(
    entities: list[dict[str, str]],
    *,
    entity_type: str | None,
    attribution_tier: str | None,
    collector_id: str | None,
    environment: str | None,
) -> list[dict[str, str]]:
    """Apply optional filters to entity dicts.

    Each filter, when set, narrows the result set. Filters combine with AND.
    """
    result = entities

    if entity_type:
        result = [e for e in result if e.get("entity_type") == entity_type]

    if attribution_tier:
        result = [
            e for e in result if e.get("attribution_tier") == attribution_tier
        ]

    if collector_id:
        result = [
            e
            for e in result
            if collector_id in (e.get("collectors") or "").split(",")
        ]

    if environment:
        result = [e for e in result if e.get("environment") == environment]

    return result


def _generate_csv(rows: list[dict[str, str]]) -> str:
    """Render a list of entity dicts as a CSV string with header row."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.get("/csv")
async def export_csv(
    request: Request,
    tenant_id: UUID,
    entity_type: str | None = Query(default=None),
    attribution_tier: str | None = Query(default=None),
    collector_id: str | None = Query(default=None),
    environment: str | None = Query(default=None),
    limit: int = Query(default=10000, ge=1, le=10000),
) -> StreamingResponse:
    """Export filtered entities as CSV.

    Returns a ``StreamingResponse`` with ``Content-Disposition: attachment``
    so browsers trigger a download. The filename embeds the tenant ID and a
    UTC timestamp for traceability.

    Phase 1 returns placeholder data. When ``request.app.state.session_factory``
    is available, real entities are queried from the database.
    """
    session_factory = getattr(request.app.state, "session_factory", None)

    if session_factory is not None:
        # --- Database path (production / integration tests) ---
        from sqlalchemy import select  # noqa: PLC0415

        from expose.db.models import Entity  # noqa: PLC0415

        async with session_factory() as session:
            stmt = select(Entity).where(Entity.tenant_id == tenant_id)

            if entity_type:
                stmt = stmt.where(Entity.entity_type == entity_type)
            if attribution_tier:
                stmt = stmt.where(Entity.attribution_status == attribution_tier)

            stmt = stmt.order_by(Entity.last_observed_at.desc()).limit(limit)
            result = await session.execute(stmt)
            rows = result.scalars().all()

        entities = [
            {
                "entity_identifier": e.canonical_identifier,
                "entity_type": e.entity_type,
                "attribution_tier": e.attribution_status,
                "confidence": str(e.attribution_confidence),
                "collectors": ",".join(
                    (e.properties or {}).get("collectors", [])
                ),
                "first_seen": (
                    e.first_observed_at.isoformat()
                    if e.first_observed_at
                    else ""
                ),
                "last_seen": (
                    e.last_observed_at.isoformat()
                    if e.last_observed_at
                    else ""
                ),
                "environment": (e.properties or {}).get("environment", ""),
                "risk_summary": (e.properties or {}).get("risk_summary", ""),
            }
            for e in rows
        ]

        # Apply collector_id and environment filters that couldn't be done
        # efficiently in SQL on the JSONB properties column in Phase 1.
        if collector_id or environment:
            entities = _filter_entities(
                entities,
                entity_type=None,
                attribution_tier=None,
                collector_id=collector_id,
                environment=environment,
            )

    else:
        # --- Placeholder path (dev / no-DB tests) ---
        entities = _filter_entities(
            list(_PLACEHOLDER_ENTITIES),
            entity_type=entity_type,
            attribution_tier=attribution_tier,
            collector_id=collector_id,
            environment=environment,
        )

    # Apply limit
    entities = entities[:limit]

    csv_content = _generate_csv(entities)
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    filename = f"expose-export-{tenant_id}-{timestamp}.csv"

    return StreamingResponse(
        content=iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
