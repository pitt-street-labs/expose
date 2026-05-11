"""FastAPI router for prioritized findings (lead-scored entities).

Implements issue #69 — Priority Findings panel API:

* **Findings** — ``GET /v1/tenants/{tenant_id}/findings/`` → FindingsResponse

Phase 1 uses in-memory placeholder data that demonstrates the format with
realistic example findings across different priority tiers and signal
combinations.  When a database session factory is available on
``request.app.state.session_factory`` and lead scoring is wired, real
scored entities will be returned.

Response is always sorted by score descending (highest risk first).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(prefix="/v1/tenants/{tenant_id}/findings", tags=["findings"])

# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class FindingEntry(BaseModel):
    """A single scored entity in the findings list."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rank: int = Field(ge=1)
    entity_identifier: str
    entity_type: str
    score: int = Field(ge=0, le=100)
    priority_tier: str  # "critical", "high", "medium", "low"
    justification: str
    signals: list[dict[str, Any]]  # simplified signal list


class FindingsResponse(BaseModel):
    """Top-level response for the findings endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    findings: list[FindingEntry]
    total_scored: int
    generated_at: datetime
    is_placeholder: bool = True  # True when findings are placeholder/demo data only


# ---------------------------------------------------------------------------
# Phase 1 placeholder data — realistic findings for UX demonstration
# ---------------------------------------------------------------------------

_PLACEHOLDER_FINDINGS: list[dict[str, Any]] = [
    {
        "entity_identifier": "staging.example.com",
        "entity_type": "domain",
        "score": 92,
        "priority_tier": "critical",
        "justification": (
            "Staging environment exposed to internet with no TLS, "
            "directory listing enabled, and default credentials detected."
        ),
        "signals": [
            {"signal": "no_tls", "weight": 30},
            {"signal": "directory_listing", "weight": 25},
            {"signal": "default_credentials", "weight": 20},
            {"signal": "non_production_exposed", "weight": 17},
        ],
    },
    {
        "entity_identifier": "203.0.113.42",
        "entity_type": "ip_address",
        "score": 85,
        "priority_tier": "critical",
        "justification": (
            "Unattributed IP address with open management ports (SSH, RDP) "
            "and weak cipher suites. Reverse PTR matches org pattern."
        ),
        "signals": [
            {"signal": "open_management_ports", "weight": 35},
            {"signal": "weak_ciphers", "weight": 25},
            {"signal": "unattributed_asset", "weight": 15},
            {"signal": "ptr_match", "weight": 10},
        ],
    },
    {
        "entity_identifier": "*.example.com",
        "entity_type": "certificate",
        "score": 74,
        "priority_tier": "high",
        "justification": (
            "Wildcard certificate expiring in 12 days. Covers 7 known subdomains "
            "including API and admin portals."
        ),
        "signals": [
            {"signal": "cert_expiry_imminent", "weight": 40},
            {"signal": "wildcard_scope", "weight": 20},
            {"signal": "covers_critical_services", "weight": 14},
        ],
    },
    {
        "entity_identifier": "admin.example.com",
        "entity_type": "domain",
        "score": 71,
        "priority_tier": "high",
        "justification": (
            "Administrative portal accessible without VPN. Basic auth only, "
            "no MFA detected. Linked to 3 internal management endpoints."
        ),
        "signals": [
            {"signal": "admin_portal_exposed", "weight": 30},
            {"signal": "no_mfa", "weight": 25},
            {"signal": "basic_auth_only", "weight": 16},
        ],
    },
    {
        "entity_identifier": "api.example.com",
        "entity_type": "domain",
        "score": 63,
        "priority_tier": "high",
        "justification": (
            "API endpoint returning verbose error messages including stack traces. "
            "CORS misconfigured with wildcard origin."
        ),
        "signals": [
            {"signal": "verbose_errors", "weight": 25},
            {"signal": "cors_wildcard", "weight": 20},
            {"signal": "stack_trace_leak", "weight": 18},
        ],
    },
    {
        "entity_identifier": "198.51.100.7",
        "entity_type": "ip_address",
        "score": 48,
        "priority_tier": "medium",
        "justification": (
            "Production server with outdated TLS 1.0 still enabled alongside TLS 1.3. "
            "WHOIS-confirmed ownership."
        ),
        "signals": [
            {"signal": "legacy_tls", "weight": 25},
            {"signal": "mixed_tls_versions", "weight": 15},
            {"signal": "confirmed_ownership", "weight": -8},
        ],
    },
    {
        "entity_identifier": "mail.example.com",
        "entity_type": "domain",
        "score": 41,
        "priority_tier": "medium",
        "justification": (
            "Mail server with DMARC policy set to 'none' (monitoring only). "
            "SPF record present but overly permissive."
        ),
        "signals": [
            {"signal": "dmarc_none", "weight": 20},
            {"signal": "spf_permissive", "weight": 15},
            {"signal": "valid_mx", "weight": -5},
        ],
    },
    {
        "entity_identifier": "vpn.example.com",
        "entity_type": "domain",
        "score": 28,
        "priority_tier": "low",
        "justification": (
            "VPN gateway with current TLS and strong ciphers. Minor: server "
            "banner reveals product version."
        ),
        "signals": [
            {"signal": "banner_disclosure", "weight": 15},
            {"signal": "strong_tls", "weight": -10},
            {"signal": "confirmed_ownership", "weight": -5},
        ],
    },
    {
        "entity_identifier": "Example Corp",
        "entity_type": "organization",
        "score": 15,
        "priority_tier": "low",
        "justification": (
            "Seed anchor organization. WHOIS registrant confirmed. No direct "
            "exposure signals; score reflects attribution completeness."
        ),
        "signals": [
            {"signal": "seed_anchor", "weight": 5},
            {"signal": "whois_confirmed", "weight": 5},
            {"signal": "attribution_complete", "weight": 5},
        ],
    },
    {
        "entity_identifier": "example.com",
        "entity_type": "domain",
        "score": 12,
        "priority_tier": "low",
        "justification": (
            "Apex domain with valid DNSSEC, strong TLS, and proper security "
            "headers. Low residual score from public DNS exposure."
        ),
        "signals": [
            {"signal": "dnssec_valid", "weight": -10},
            {"signal": "security_headers_present", "weight": -8},
            {"signal": "public_dns_exposure", "weight": 10},
        ],
    },
]


def _build_placeholder_findings(
    tenant_id: UUID,
    *,
    limit: int,
    min_score: int,
) -> FindingsResponse:
    """Generate a FindingsResponse from placeholder data.

    Filters by ``min_score``, sorts by score descending, applies ``limit``,
    and assigns sequential ranks.
    """
    # Filter by minimum score
    filtered = [f for f in _PLACEHOLDER_FINDINGS if f["score"] >= min_score]

    # Sort by score descending (highest risk first)
    filtered.sort(key=lambda f: f["score"], reverse=True)

    # Apply limit
    filtered = filtered[:limit]

    # Build ranked entries
    entries = [
        FindingEntry(rank=idx + 1, **item)
        for idx, item in enumerate(filtered)
    ]

    return FindingsResponse(
        tenant_id=tenant_id,
        findings=entries,
        total_scored=len(_PLACEHOLDER_FINDINGS),
        generated_at=datetime.now(tz=UTC),
    )


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


async def _build_takeover_findings(
    session_factory: Any,
    tenant_id: UUID,
) -> list[FindingEntry]:
    """Query entities with ``_takeover_risk`` in properties and build findings.

    Returns a list of ``FindingEntry`` objects for entities flagged with
    subdomain takeover risk by the ``takeover_detection`` pipeline stage.
    """
    if session_factory is None:
        return []

    from sqlalchemy import select  # noqa: PLC0415

    from expose.db.models import Entity  # noqa: PLC0415

    async with session_factory() as session:
        stmt = (
            select(Entity)
            .where(Entity.tenant_id == tenant_id)
            .order_by(Entity.last_observed_at.desc())
            .limit(500)
        )
        result = await session.execute(stmt)
        rows = result.scalars().all()

    findings: list[FindingEntry] = []
    rank = 1
    for entity in rows:
        props = entity.properties or {}
        takeover = props.get("_takeover_risk")
        if not takeover:
            continue

        risk_level = takeover.get("risk_level", "high")
        score = 98 if risk_level == "critical" else 85
        provider = takeover.get("provider", "unknown")
        cname_target = takeover.get("cname_target", "unknown")

        findings.append(FindingEntry(
            rank=rank,
            entity_identifier=entity.canonical_identifier,
            entity_type=entity.entity_type,
            score=score,
            priority_tier="critical",
            justification=(
                f"Subdomain takeover risk: CNAME points to {cname_target} "
                f"({provider}) but the service no longer exists. An attacker "
                f"can claim this service and hijack the subdomain."
            ),
            signals=[
                {"signal": "dangling_cname", "weight": 50},
                {"signal": f"vulnerable_provider_{provider}", "weight": 30},
                {"signal": "nxdomain_confirmed", "weight": 18},
            ],
        ))
        rank += 1

    return findings


async def _build_scored_findings(
    session_factory: Any,
    tenant_id: UUID,
) -> list[FindingEntry]:
    """Query entities with ``_lead_score`` in properties and build findings.

    Returns a list of ``FindingEntry`` objects for entities that have been
    scored by the ``LeadScoringEngine`` during pipeline execution.  Each
    entity's ``_lead_score`` and ``_priority_tier`` properties (written by
    the lead scoring step in ``_flush_batch``) are used to populate the
    finding entry.

    Returns an empty list when no session factory is available or no
    scored entities exist.
    """
    if session_factory is None:
        return []

    from sqlalchemy import select  # noqa: PLC0415

    from expose.db.models import Entity  # noqa: PLC0415

    async with session_factory() as session:
        stmt = (
            select(Entity)
            .where(Entity.tenant_id == tenant_id)
            .order_by(Entity.last_observed_at.desc())
            .limit(500)
        )
        result = await session.execute(stmt)
        rows = result.scalars().all()

    findings: list[FindingEntry] = []
    rank = 1
    for entity in rows:
        props = entity.properties or {}
        lead_score = props.get("_lead_score")
        if lead_score is None:
            continue

        # Coerce to int (may be stored as float in JSONB)
        try:
            score = int(lead_score)
        except (TypeError, ValueError):
            continue

        priority_tier = props.get("_priority_tier", "low")

        # Build signal list from stored properties — extract any signal-like
        # keys that were preserved alongside the score.
        signals: list[dict[str, Any]] = []
        for key, val in props.items():
            if key.startswith("_") or key in (
                "collector_id",
                "collector_version",
            ):
                continue
            if isinstance(val, (int, float)) and key not in (
                "lead_score",
                "priority_tier",
            ):
                signals.append({"signal": key, "weight": val})

        findings.append(FindingEntry(
            rank=rank,
            entity_identifier=entity.canonical_identifier,
            entity_type=entity.entity_type,
            score=score,
            priority_tier=priority_tier,
            justification=(
                f"{entity.canonical_identifier}: lead score {score} "
                f"({priority_tier})"
            ),
            signals=signals,
        ))
        rank += 1

    # Sort by score descending for consistent ordering
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings


@router.get("/")
async def get_findings(
    request: Request,
    tenant_id: UUID,
    limit: int = Query(default=20, ge=1, le=100),
    min_score: int = Query(default=0, ge=0, le=100),
) -> FindingsResponse:
    """Return top entities ranked by lead score.

    When a database session factory is available, queries for entities
    with lead scores (``_lead_score`` property written by the pipeline's
    lead scoring step) and subdomain takeover risks (``_takeover_risk``
    property). Real scored entities are returned with
    ``is_placeholder=False``.

    When no database is available or no scored entities exist, returns
    placeholder findings that demonstrate the prioritized-findings UX.

    Findings are always sorted by score descending (highest risk first).
    """
    session_factory = getattr(request.app.state, "session_factory", None)

    # Fetch real scored entities and takeover findings from the database
    scored_findings = await _build_scored_findings(session_factory, tenant_id)
    takeover_findings = await _build_takeover_findings(session_factory, tenant_id)

    # Combine real findings from both sources
    real_findings = takeover_findings + scored_findings
    has_real_data = len(real_findings) > 0

    if has_real_data:
        all_entries = real_findings
    else:
        # No DB or no scored entities — use placeholder data
        all_entries = [
            FindingEntry(rank=1, **item)  # rank re-assigned below
            for item in _PLACEHOLDER_FINDINGS
        ]

    total_scored = len(all_entries)

    # Filter by min_score, sort descending, apply limit
    filtered = [f for f in all_entries if f.score >= min_score]
    filtered.sort(key=lambda f: f.score, reverse=True)
    filtered = filtered[:limit]

    # Re-assign sequential ranks after filtering
    ranked = [
        FindingEntry(
            rank=idx + 1,
            entity_identifier=f.entity_identifier,
            entity_type=f.entity_type,
            score=f.score,
            priority_tier=f.priority_tier,
            justification=f.justification,
            signals=f.signals,
        )
        for idx, f in enumerate(filtered)
    ]

    return FindingsResponse(
        tenant_id=tenant_id,
        findings=ranked,
        total_scored=total_scored,
        generated_at=datetime.now(tz=UTC),
        is_placeholder=not has_real_data,
    )
