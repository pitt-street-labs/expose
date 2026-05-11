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

from fastapi import APIRouter, Query
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


@router.get("/")
async def get_findings(
    tenant_id: UUID,
    limit: int = Query(default=20, ge=1, le=100),
    min_score: int = Query(default=0, ge=0, le=100),
) -> FindingsResponse:
    """Return top entities ranked by lead score.

    Phase 1 returns placeholder findings data that demonstrates the
    prioritized-findings UX.  When the lead scoring engine
    (``expose.pipeline.lead_scoring``) is wired, this endpoint will
    return real scored entities from the database.

    Findings are always sorted by score descending (highest risk first).
    """
    return _build_placeholder_findings(
        tenant_id,
        limit=limit,
        min_score=min_score,
    )
