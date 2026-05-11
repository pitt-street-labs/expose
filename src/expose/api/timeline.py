"""FastAPI router for temporal banner timeline analysis.

Implements issue #172 — temporal analysis endpoint:

* **GET** ``/v1/tenants/{tenant_id}/entities/{entity_id}/timeline``
  → timeline + progression patterns

Queries entity observations from the database, builds the banner timeline,
runs all five progression detectors (security regression, environment
promotion, infrastructure drift, certificate lifecycle, new exposure), and
returns the aggregate result.

When no database session factory is available (standalone / test mode),
returns a realistic placeholder timeline demonstrating a security regression
over a 3-month period.

Per ADR-007 all queries are tenant-scoped.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from expose.pipeline.temporal_analysis import (
    TemporalAnalyzer,
)

router = APIRouter(
    prefix="/v1/tenants/{tenant_id}/entities/{entity_id}",
    tags=["timeline"],
)

# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class SnapshotResponse(BaseModel):
    """API representation of a single banner snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    timestamp: datetime
    source: str
    banner_text: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    status_code: int | None = None
    tls_version: str | None = None
    server_header: str | None = None
    technologies: list[str] = Field(default_factory=list)


class PatternResponse(BaseModel):
    """API representation of a detected progression pattern."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pattern_type: str
    severity: str
    description: str
    evidence: list[dict[str, Any]]
    detected_at: datetime
    scoring_delta: int


class TimelineResponse(BaseModel):
    """Top-level response for the timeline endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    entity_id: str
    span_days: int
    snapshots: list[SnapshotResponse]
    patterns: list[PatternResponse]
    temporal_score_delta: int
    is_placeholder: bool = True


# ---------------------------------------------------------------------------
# Placeholder data — realistic 3-month security regression scenario
# ---------------------------------------------------------------------------


def _build_placeholder_timeline(
    tenant_id: UUID,
    entity_id: str,
) -> TimelineResponse:
    """Build a realistic placeholder timeline showing security regression.

    Demonstrates:
    - Month 1: TLSv1.3, all security headers present, nginx/1.24.0
    - Month 2: TLSv1.2 downgrade, HSTS removed (security regression)
    - Month 3: Self-signed cert, debug headers appearing (critical)
    """
    now = datetime.now(tz=UTC)

    observations: list[dict[str, Any]] = [
        # Month 1 — healthy baseline (Wayback Machine)
        {
            "_collector_id": "active-http-fingerprint",
            "structured_payload": {
                "_observed_at": (now.replace(day=1) - _delta(days=90)).isoformat(),
                "status_code": 200,
                "headers": {
                    "server": "nginx/1.24.0",
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-content-type-options": "nosniff",
                },
                "technologies": ["nginx", "React"],
            },
        },
        {
            "_collector_id": "active-tls-handshake",
            "structured_payload": {
                "_observed_at": (now.replace(day=1) - _delta(days=90)).isoformat(),
                "tls_version": "TLSv1.3",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
                "cert_subject_cn": "example.com",
                "cert_issuer_cn": "Let's Encrypt Authority X3",
                "cert_not_after": (now + _delta(days=90)).isoformat(),
            },
        },
        # Month 2 — TLS downgrade + HSTS removed (Shodan)
        {
            "_collector_id": "active-http-fingerprint",
            "structured_payload": {
                "_observed_at": (now.replace(day=1) - _delta(days=45)).isoformat(),
                "status_code": 200,
                "headers": {
                    "server": "nginx/1.24.0",
                    "content-security-policy": "default-src 'self'",
                    "x-content-type-options": "nosniff",
                },
                "technologies": ["nginx", "React"],
            },
        },
        {
            "_collector_id": "active-tls-handshake",
            "structured_payload": {
                "_observed_at": (now.replace(day=1) - _delta(days=45)).isoformat(),
                "tls_version": "TLSv1.2",
                "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
                "cert_subject_cn": "example.com",
                "cert_issuer_cn": "Let's Encrypt Authority X3",
                "cert_not_after": (now + _delta(days=90)).isoformat(),
            },
        },
        # Month 3 — self-signed cert + debug headers (active scan)
        {
            "_collector_id": "active-http-fingerprint",
            "structured_payload": {
                "_observed_at": now.isoformat(),
                "status_code": 200,
                "headers": {
                    "server": "nginx/1.24.0",
                    "x-debug": "true",
                    "x-debug-token": "abc123",
                },
                "technologies": ["nginx", "React", "PHP"],
            },
        },
        {
            "_collector_id": "active-tls-handshake",
            "structured_payload": {
                "_observed_at": now.isoformat(),
                "tls_version": "TLSv1.2",
                "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
                "cert_subject_cn": "example.com",
                "cert_issuer_cn": "example.com",
                "cert_not_after": (now + _delta(days=365)).isoformat(),
            },
        },
    ]

    analyzer = TemporalAnalyzer()
    result = analyzer.analyze(entity_id, observations)

    snapshots_resp = [
        SnapshotResponse(
            timestamp=s.timestamp,
            source=s.source,
            banner_text=s.banner_text,
            headers=s.headers,
            status_code=s.status_code,
            tls_version=s.tls_version,
            server_header=s.server_header,
            technologies=list(s.technologies),
        )
        for s in result.timeline.snapshots
    ]

    patterns_resp = [
        PatternResponse(
            pattern_type=p.pattern_type,
            severity=p.severity,
            description=p.description,
            evidence=p.evidence,
            detected_at=p.detected_at,
            scoring_delta=p.scoring_delta,
        )
        for p in result.patterns
    ]

    return TimelineResponse(
        tenant_id=tenant_id,
        entity_id=entity_id,
        span_days=result.timeline.span_days,
        snapshots=snapshots_resp,
        patterns=patterns_resp,
        temporal_score_delta=result.temporal_score_delta,
        is_placeholder=True,
    )


def _delta(*, days: int) -> __import__("datetime").timedelta:
    """Convenience wrapper for timedelta construction."""
    from datetime import timedelta  # noqa: PLC0415
    return timedelta(days=days)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/timeline",
    response_model=TimelineResponse,
    summary="Get temporal banner timeline with progression patterns",
    responses={
        200: {
            "description": "Timeline with detected progression patterns",
        },
    },
)
async def get_entity_timeline(
    tenant_id: UUID,
    entity_id: str,
    request: Request,
) -> TimelineResponse:
    """Return the temporal banner timeline and detected patterns for an entity.

    Queries the observation history for the entity, builds the timeline from
    all available sources (Wayback Machine, Shodan, active scans), runs
    progression detectors, and returns the aggregate result.

    If no database is available, returns realistic placeholder data
    demonstrating a security regression over 3 months.
    """
    # Try to load real observations from the database.
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is not None:
        observations = await _load_entity_observations(
            session_factory, tenant_id, entity_id,
        )
        if observations:
            analyzer = TemporalAnalyzer()
            result = analyzer.analyze(entity_id, observations)

            snapshots_resp = [
                SnapshotResponse(
                    timestamp=s.timestamp,
                    source=s.source,
                    banner_text=s.banner_text,
                    headers=s.headers,
                    status_code=s.status_code,
                    tls_version=s.tls_version,
                    server_header=s.server_header,
                    technologies=list(s.technologies),
                )
                for s in result.timeline.snapshots
            ]

            patterns_resp = [
                PatternResponse(
                    pattern_type=p.pattern_type,
                    severity=p.severity,
                    description=p.description,
                    evidence=p.evidence,
                    detected_at=p.detected_at,
                    scoring_delta=p.scoring_delta,
                )
                for p in result.patterns
            ]

            return TimelineResponse(
                tenant_id=tenant_id,
                entity_id=entity_id,
                span_days=result.timeline.span_days,
                snapshots=snapshots_resp,
                patterns=patterns_resp,
                temporal_score_delta=result.temporal_score_delta,
                is_placeholder=False,
            )

    # Fall back to placeholder data.
    return _build_placeholder_timeline(tenant_id, entity_id)


async def _load_entity_observations(
    session_factory: Any,
    tenant_id: UUID,
    entity_id: str,
) -> list[dict[str, Any]]:
    """Load observations for an entity from the database.

    Returns a list of observation dicts suitable for the TemporalAnalyzer.
    Returns an empty list if the entity is not found or has no observations.
    """
    try:
        from sqlalchemy import select  # noqa: PLC0415

        from expose.db.models import Entity  # noqa: PLC0415

        async with session_factory() as session:
            stmt = select(Entity).where(
                Entity.tenant_id == tenant_id,
                Entity.identifier == entity_id,
            )
            result = await session.execute(stmt)
            entity = result.scalar_one_or_none()

            if entity is None:
                return []

            # Extract observations from entity metadata if available.
            raw_observations = getattr(entity, "raw_observations", None)
            if isinstance(raw_observations, list):
                return raw_observations

    except Exception:
        # DB query failed — fall back to placeholder.
        pass

    return []
