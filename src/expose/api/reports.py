"""FastAPI router for CISO reports (executive threat intelligence).

Implements issue #113 -- CISO Report endpoints:

* **Full report** -- ``GET /v1/tenants/{tenant_id}/reports/ciso``
* **Executive summary** -- ``GET /v1/tenants/{tenant_id}/reports/ciso/summary``

When a database session factory is available on
``request.app.state.session_factory``, real entity data is queried and
fed to the ``CisoReportGenerator``.  Otherwise, placeholder entities
demonstrate the report format with realistic example data.
"""

from __future__ import annotations

import os
import smtplib
from datetime import UTC, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from expose.modules.ciso_report.generator import (
    CisoReportGenerator,
)

router = APIRouter(prefix="/v1/tenants/{tenant_id}/reports", tags=["reports"])


# ---------------------------------------------------------------------------
# Response models (Pydantic)
# ---------------------------------------------------------------------------


class SectorAnalysisResponse(BaseModel):
    """Sector analysis section of the CISO report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sector: str
    confidence: float = Field(ge=0.0, le=1.0)
    indicators: list[str]


class ThreatActorResponse(BaseModel):
    """A threat actor profile in the report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    motivation: str
    relevance_score: float = Field(ge=0.0, le=1.0)
    typical_ttps: list[str]
    description: str


class AttractionFactorResponse(BaseModel):
    """A single factor in the attraction assessment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    factor: str
    score: int = Field(ge=0, le=100)
    description: str


class AttractionAssessmentResponse(BaseModel):
    """Attraction assessment section of the CISO report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    overall_score: int = Field(ge=0, le=100)
    factors: list[AttractionFactorResponse]


class RankedTargetResponse(BaseModel):
    """A ranked target entity in the report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_identifier: str
    risk_score: float = Field(ge=0.0, le=100.0)
    justification: str
    recommended_action: str


class KeyFindingResponse(BaseModel):
    """A key finding in the executive summary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str
    severity: str
    description: str


class RecommendationResponse(BaseModel):
    """A prioritized recommendation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    priority: int = Field(ge=1)
    title: str
    description: str
    effort: str


class OrganizationProfileResponse(BaseModel):
    """Organization profile in the executive summary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sector: str
    estimated_surface_size: str
    attack_surface_summary: str


class ThreatLandscapeResponse(BaseModel):
    """Threat landscape in the executive summary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    top_threats: list[str]
    actor_profiles: list[ThreatActorResponse]


class ReportMetricsResponse(BaseModel):
    """Report metrics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    total_entities: int = Field(ge=0)
    entities_by_tier: dict[str, int]
    coverage_stats: dict[str, Any]


class ExecutiveSummaryResponse(BaseModel):
    """Executive summary section of the CISO report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    organization_profile: OrganizationProfileResponse
    threat_landscape: ThreatLandscapeResponse
    key_findings: list[KeyFindingResponse]
    recommendations: list[RecommendationResponse]
    metrics: ReportMetricsResponse
    generated_at: datetime
    is_placeholder: bool = True


class VendorProfileResponse(BaseModel):
    """Per-vendor CWE distribution and risk summary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    vendor: str
    products: list[str]
    cwe_distribution: list[tuple[str, float]]
    aggregate_risk: float = Field(ge=0.0, le=100.0)


class HighRiskEndpointResponse(BaseModel):
    """An endpoint whose compound vendor risk exceeds threshold."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    identifier: str
    compound_risk: float = Field(ge=0.0, le=100.0)
    contributing_products: list[str]
    top_cwes: list[str]


class EolProductResponse(BaseModel):
    """A detected end-of-life product still in use."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    product: str
    vendor: str
    endpoint: str
    eol_reason: str


class ThreatActorCweAlignmentResponse(BaseModel):
    """Maps a threat actor to CWE patterns found in the vendor stack."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    actor_name: str
    matching_cwes: list[str]
    alignment_score: float = Field(ge=0.0, le=1.0)


class VendorDnaAnalysisResponse(BaseModel):
    """Vendor Vulnerability DNA analysis section of the CISO report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    vendor_profiles: list[VendorProfileResponse]
    high_risk_endpoints: list[HighRiskEndpointResponse]
    eol_products: list[EolProductResponse]
    patch_velocity_assessment: str
    threat_actor_alignment: list[ThreatActorCweAlignmentResponse]


class CisoReportResponse(BaseModel):
    """Full CISO report response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    generated_at: datetime
    report_version: str
    sector_analysis: SectorAnalysisResponse
    threat_actors: list[ThreatActorResponse]
    attraction_assessment: AttractionAssessmentResponse
    ranked_targets: list[RankedTargetResponse]
    executive_summary: ExecutiveSummaryResponse
    vendor_dna: VendorDnaAnalysisResponse | None = None
    is_placeholder: bool = True


class CisoReportDeliverRequest(BaseModel):
    """Request body for CISO report email delivery."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    recipients: list[str]
    subject_prefix: str = "EXPOSE CISO Report"
    include_json_attachment: bool = True


class CisoReportDeliverResponse(BaseModel):
    """Response for CISO report email delivery."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    delivered_to: list[str]
    failed: list[str]
    message: str


# ---------------------------------------------------------------------------
# Placeholder entities for demo/no-DB mode
# ---------------------------------------------------------------------------

_PLACEHOLDER_ENTITIES: list[dict[str, Any]] = [
    {
        "canonical_identifier": "staging.example.com",
        "entity_type": "domain",
        "properties": {
            "open_ports": [{"port": 22}, {"port": 8080}, {"port": 3306}],
            "tls_version": "TLS1.0",
            "is_self_signed": True,
            "security_headers": {},
            "server_header": "Apache/2.2.34 (Unix) PHP/5.6.40",
            "technologies": ["PHP", "MySQL", "Apache"],
        },
        "attribution_status": "confirmed",
        "attribution_confidence": 0.95,
        "lead_score": 92,
    },
    {
        "canonical_identifier": "api.example.com",
        "entity_type": "domain",
        "properties": {
            "open_ports": [{"port": 443}, {"port": 8443}],
            "tls_version": "TLS1.2",
            "security_headers": {"strict_transport_security": True},
            "server_header": "nginx/1.24.0",
            "x_powered_by": "Express",
        },
        "attribution_status": "confirmed",
        "attribution_confidence": 0.90,
        "lead_score": 63,
    },
    {
        "canonical_identifier": "203.0.113.42",
        "entity_type": "ip_address",
        "properties": {
            "open_ports": [{"port": 22}, {"port": 3389}, {"port": 5432}],
            "tls_version": "TLS1.1",
            "security_headers": {},
        },
        "attribution_status": "high",
        "attribution_confidence": 0.80,
        "lead_score": 85,
    },
    {
        "canonical_identifier": "admin.example.com",
        "entity_type": "domain",
        "properties": {
            "open_ports": [{"port": 443}, {"port": 9090}],
            "tls_version": "TLS1.2",
            "is_self_signed": False,
            "security_headers": {
                "strict_transport_security": True,
                "content_security_policy": False,
            },
        },
        "attribution_status": "confirmed",
        "attribution_confidence": 0.92,
        "lead_score": 71,
    },
    {
        "canonical_identifier": "vpn.example.com",
        "entity_type": "domain",
        "properties": {
            "open_ports": [{"port": 443}],
            "tls_version": "TLS1.3",
            "security_headers": {
                "strict_transport_security": True,
                "content_security_policy": True,
            },
        },
        "attribution_status": "confirmed",
        "attribution_confidence": 0.98,
        "lead_score": 28,
    },
    {
        "canonical_identifier": "mail.example.com",
        "entity_type": "domain",
        "properties": {
            "open_ports": [{"port": 25}, {"port": 587}, {"port": 993}],
            "tls_version": "TLS1.2",
            "security_headers": {},
        },
        "attribution_status": "confirmed",
        "attribution_confidence": 0.88,
        "lead_score": 41,
    },
    {
        "canonical_identifier": "example.com",
        "entity_type": "domain",
        "properties": {
            "tls_version": "TLS1.3",
            "security_headers": {
                "strict_transport_security": True,
                "content_security_policy": True,
            },
        },
        "attribution_status": "confirmed",
        "attribution_confidence": 0.99,
        "lead_score": 12,
    },
    {
        "canonical_identifier": "dev.cloud.example.com",
        "entity_type": "domain",
        "properties": {
            "open_ports": [{"port": 22}, {"port": 8080}],
            "tls_version": "TLS1.2",
            "security_headers": {},
        },
        "attribution_status": "medium",
        "attribution_confidence": 0.60,
        "lead_score": 55,
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _load_entities(
    session_factory: Any,
    tenant_id: UUID,
) -> tuple[list[dict[str, Any]], bool]:
    """Load entities from DB if available, else return placeholders.

    Returns ``(entities_list, is_placeholder)`` tuple.
    """
    if session_factory is None:
        return _PLACEHOLDER_ENTITIES, True

    from sqlalchemy import select  # noqa: PLC0415

    from expose.db.models import Entity  # noqa: PLC0415

    try:
        async with session_factory() as session:
            stmt = (
                select(Entity)
                .where(Entity.tenant_id == tenant_id)
                .order_by(Entity.last_observed_at.desc())
                .limit(500)
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

        if not rows:
            return _PLACEHOLDER_ENTITIES, True

        entities: list[dict[str, Any]] = []
        for row in rows:
            entities.append({
                "canonical_identifier": row.canonical_identifier,
                "entity_type": row.entity_type,
                "properties": row.properties or {},
                "attribution_status": row.attribution_status,
                "attribution_confidence": float(row.attribution_confidence),
                "lead_score": (row.properties or {}).get("_lead_score"),
            })

        return entities, False

    except Exception:
        logger.warning(
            "Failed to load entities from DB for tenant %s; "
            "falling back to placeholder data",
            tenant_id,
            exc_info=True,
        )
        return _PLACEHOLDER_ENTITIES, True


def _vendor_dna_to_response(
    vendor_dna: Any,
) -> VendorDnaAnalysisResponse | None:
    """Convert a VendorDnaAnalysis dataclass to the Pydantic response model."""
    if vendor_dna is None:
        return None
    return VendorDnaAnalysisResponse(
        vendor_profiles=[
            VendorProfileResponse(
                vendor=vp.vendor,
                products=list(vp.products),
                cwe_distribution=list(vp.cwe_distribution),
                aggregate_risk=vp.aggregate_risk,
            )
            for vp in vendor_dna.vendor_profiles
        ],
        high_risk_endpoints=[
            HighRiskEndpointResponse(
                identifier=ep.identifier,
                compound_risk=ep.compound_risk,
                contributing_products=list(ep.contributing_products),
                top_cwes=list(ep.top_cwes),
            )
            for ep in vendor_dna.high_risk_endpoints
        ],
        eol_products=[
            EolProductResponse(
                product=eol.product,
                vendor=eol.vendor,
                endpoint=eol.endpoint,
                eol_reason=eol.eol_reason,
            )
            for eol in vendor_dna.eol_products
        ],
        patch_velocity_assessment=vendor_dna.patch_velocity_assessment,
        threat_actor_alignment=[
            ThreatActorCweAlignmentResponse(
                actor_name=ta.actor_name,
                matching_cwes=list(ta.matching_cwes),
                alignment_score=ta.alignment_score,
            )
            for ta in vendor_dna.threat_actor_alignment
        ],
    )


def _report_to_response(
    report: Any,
    tenant_id: UUID,
    is_placeholder: bool,
) -> CisoReportResponse:
    """Convert a CisoReport dataclass to the Pydantic response model."""
    return CisoReportResponse(
        tenant_id=tenant_id,
        generated_at=report.generated_at,
        report_version=report.report_version,
        sector_analysis=SectorAnalysisResponse(
            sector=report.sector_analysis.sector,
            confidence=report.sector_analysis.confidence,
            indicators=list(report.sector_analysis.indicators),
        ),
        threat_actors=[
            ThreatActorResponse(
                name=a.name,
                motivation=a.motivation,
                relevance_score=a.relevance_score,
                typical_ttps=list(a.typical_ttps),
                description=a.description,
            )
            for a in report.threat_actors
        ],
        attraction_assessment=AttractionAssessmentResponse(
            overall_score=report.attraction_assessment.overall_score,
            factors=[
                AttractionFactorResponse(
                    factor=f.factor,
                    score=f.score,
                    description=f.description,
                )
                for f in report.attraction_assessment.factors
            ],
        ),
        ranked_targets=[
            RankedTargetResponse(
                entity_identifier=t.entity_identifier,
                risk_score=t.risk_score,
                justification=t.justification,
                recommended_action=t.recommended_action,
            )
            for t in report.ranked_targets
        ],
        executive_summary=ExecutiveSummaryResponse(
            organization_profile=OrganizationProfileResponse(
                sector=report.executive_summary.organization_profile.sector,
                estimated_surface_size=(
                    report.executive_summary.organization_profile
                    .estimated_surface_size
                ),
                attack_surface_summary=(
                    report.executive_summary.organization_profile
                    .attack_surface_summary
                ),
            ),
            threat_landscape=ThreatLandscapeResponse(
                top_threats=list(
                    report.executive_summary.threat_landscape.top_threats
                ),
                actor_profiles=[
                    ThreatActorResponse(
                        name=a.name,
                        motivation=a.motivation,
                        relevance_score=a.relevance_score,
                        typical_ttps=list(a.typical_ttps),
                        description=a.description,
                    )
                    for a in (
                        report.executive_summary.threat_landscape.actor_profiles
                    )
                ],
            ),
            key_findings=[
                KeyFindingResponse(
                    title=f.title,
                    severity=f.severity,
                    description=f.description,
                )
                for f in report.executive_summary.key_findings
            ],
            recommendations=[
                RecommendationResponse(
                    priority=r.priority,
                    title=r.title,
                    description=r.description,
                    effort=r.effort,
                )
                for r in report.executive_summary.recommendations
            ],
            metrics=ReportMetricsResponse(
                total_entities=report.executive_summary.metrics.total_entities,
                entities_by_tier=(
                    report.executive_summary.metrics.entities_by_tier
                ),
                coverage_stats=(
                    report.executive_summary.metrics.coverage_stats
                ),
            ),
            generated_at=report.generated_at,
            is_placeholder=is_placeholder,
        ),
        vendor_dna=_vendor_dna_to_response(
            getattr(report, "vendor_dna", None),
        ),
        is_placeholder=is_placeholder,
    )


def _summary_to_response(
    report: Any,
    tenant_id: UUID,
    is_placeholder: bool,
) -> ExecutiveSummaryResponse:
    """Convert just the executive summary portion to a response model."""
    summary = report.executive_summary
    return ExecutiveSummaryResponse(
        organization_profile=OrganizationProfileResponse(
            sector=summary.organization_profile.sector,
            estimated_surface_size=(
                summary.organization_profile.estimated_surface_size
            ),
            attack_surface_summary=(
                summary.organization_profile.attack_surface_summary
            ),
        ),
        threat_landscape=ThreatLandscapeResponse(
            top_threats=list(summary.threat_landscape.top_threats),
            actor_profiles=[
                ThreatActorResponse(
                    name=a.name,
                    motivation=a.motivation,
                    relevance_score=a.relevance_score,
                    typical_ttps=list(a.typical_ttps),
                    description=a.description,
                )
                for a in summary.threat_landscape.actor_profiles
            ],
        ),
        key_findings=[
            KeyFindingResponse(
                title=f.title,
                severity=f.severity,
                description=f.description,
            )
            for f in summary.key_findings
        ],
        recommendations=[
            RecommendationResponse(
                priority=r.priority,
                title=r.title,
                description=r.description,
                effort=r.effort,
            )
            for r in summary.recommendations
        ],
        metrics=ReportMetricsResponse(
            total_entities=summary.metrics.total_entities,
            entities_by_tier=summary.metrics.entities_by_tier,
            coverage_stats=summary.metrics.coverage_stats,
        ),
        generated_at=report.generated_at,
        is_placeholder=is_placeholder,
    )


def _build_report_html(report_response: CisoReportResponse) -> str:
    """Build a simple table-based HTML email from a CISO report."""
    summary = report_response.executive_summary
    style = (
        "font-family:Arial,sans-serif;border-collapse:collapse;"
        "width:100%;margin-bottom:20px"
    )
    td_style = "border:1px solid #ddd;padding:8px;text-align:left"
    th_style = f"{td_style};background-color:#2c3e50;color:white"

    parts: list[str] = [
        "<html><body style='font-family:Arial,sans-serif;color:#333'>",
        f"<h1 style='color:#2c3e50'>EXPOSE CISO Report</h1>",
        f"<p><strong>Tenant:</strong> {report_response.tenant_id}</p>",
        f"<p><strong>Generated:</strong> {report_response.generated_at:%Y-%m-%d %H:%M UTC}</p>",
        f"<p><strong>Sector:</strong> {report_response.sector_analysis.sector} "
        f"(confidence: {report_response.sector_analysis.confidence:.0%})</p>",
        f"<p><strong>Attraction Score:</strong> "
        f"{report_response.attraction_assessment.overall_score}/100</p>",
    ]

    if summary.key_findings:
        parts.append("<h2 style='color:#2c3e50'>Key Findings</h2>")
        parts.append(f"<table style='{style}'>")
        parts.append(
            f"<tr><th style='{th_style}'>Title</th>"
            f"<th style='{th_style}'>Severity</th>"
            f"<th style='{th_style}'>Description</th></tr>"
        )
        for kf in summary.key_findings:
            parts.append(
                f"<tr><td style='{td_style}'>{kf.title}</td>"
                f"<td style='{td_style}'>{kf.severity}</td>"
                f"<td style='{td_style}'>{kf.description}</td></tr>"
            )
        parts.append("</table>")

    if report_response.ranked_targets:
        parts.append("<h2 style='color:#2c3e50'>Ranked Targets</h2>")
        parts.append(f"<table style='{style}'>")
        parts.append(
            f"<tr><th style='{th_style}'>Entity</th>"
            f"<th style='{th_style}'>Risk Score</th>"
            f"<th style='{th_style}'>Justification</th>"
            f"<th style='{th_style}'>Action</th></tr>"
        )
        for rt in report_response.ranked_targets:
            parts.append(
                f"<tr><td style='{td_style}'>{rt.entity_identifier}</td>"
                f"<td style='{td_style}'>{rt.risk_score:.1f}</td>"
                f"<td style='{td_style}'>{rt.justification}</td>"
                f"<td style='{td_style}'>{rt.recommended_action}</td></tr>"
            )
        parts.append("</table>")

    if summary.recommendations:
        parts.append("<h2 style='color:#2c3e50'>Recommendations</h2>")
        parts.append(f"<table style='{style}'>")
        parts.append(
            f"<tr><th style='{th_style}'>#</th>"
            f"<th style='{th_style}'>Title</th>"
            f"<th style='{th_style}'>Description</th>"
            f"<th style='{th_style}'>Effort</th></tr>"
        )
        for rec in summary.recommendations:
            parts.append(
                f"<tr><td style='{td_style}'>{rec.priority}</td>"
                f"<td style='{td_style}'>{rec.title}</td>"
                f"<td style='{td_style}'>{rec.description}</td>"
                f"<td style='{td_style}'>{rec.effort}</td></tr>"
            )
        parts.append("</table>")

    parts.append(
        "<hr style='border:1px solid #eee'>"
        "<p style='color:#999;font-size:12px'>"
        "Generated by EXPOSE EASI Platform</p>"
    )
    parts.append("</body></html>")
    return "".join(parts)


def _get_smtp_config() -> dict[str, Any] | None:
    """Read SMTP settings from environment. Returns None if unconfigured."""
    user = os.environ.get("EXPOSE_SMTP_USER")
    password = os.environ.get("EXPOSE_SMTP_PASSWORD")
    if not user or not password:
        return None
    return {
        "host": os.environ.get("EXPOSE_SMTP_HOST", "smtp.gmail.com"),
        "port": int(os.environ.get("EXPOSE_SMTP_PORT", "587")),
        "user": user,
        "password": password,
        "from_addr": os.environ.get("EXPOSE_SMTP_FROM", user),
    }


def _send_report_emails(
    smtp_cfg: dict[str, Any],
    recipients: list[str],
    subject: str,
    html_body: str,
    json_attachment: str | None,
) -> tuple[list[str], list[str]]:
    """Send the report email to each recipient individually.

    Returns ``(delivered, failed)`` lists.
    """
    delivered: list[str] = []
    failed: list[str] = []

    for recipient in recipients:
        try:
            msg = MIMEMultipart("mixed")
            msg["From"] = smtp_cfg["from_addr"]
            msg["To"] = recipient
            msg["Subject"] = subject

            msg.attach(MIMEText(html_body, "html"))

            if json_attachment:
                attachment = MIMEText(json_attachment, "plain")
                attachment.add_header(
                    "Content-Disposition",
                    "attachment",
                    filename="ciso-report.json",
                )
                msg.attach(attachment)

            with smtplib.SMTP(smtp_cfg["host"], smtp_cfg["port"], timeout=30) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(smtp_cfg["user"], smtp_cfg["password"])
                server.sendmail(smtp_cfg["from_addr"], [recipient], msg.as_string())

            delivered.append(recipient)
        except Exception:
            logger.exception("Failed to deliver CISO report to %s", recipient)
            failed.append(recipient)

    return delivered, failed


# ---------------------------------------------------------------------------
# Logging -- deferred to module level to avoid import in function body
# ---------------------------------------------------------------------------

import logging  # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/ciso")
async def get_ciso_report(
    request: Request,
    tenant_id: UUID,
) -> CisoReportResponse:
    """Generate a full CISO report for the tenant.

    When a database session factory is available, queries real entity data.
    Otherwise returns a report built from placeholder entities.
    """
    session_factory = getattr(request.app.state, "session_factory", None)
    entities, is_placeholder = await _load_entities(session_factory, tenant_id)

    generator = CisoReportGenerator()
    report = generator.generate_report(entities)

    return _report_to_response(report, tenant_id, is_placeholder)


@router.get("/ciso/summary")
async def get_ciso_summary(
    request: Request,
    tenant_id: UUID,
) -> ExecutiveSummaryResponse:
    """Generate just the executive summary for the tenant.

    Lighter-weight endpoint for dashboards and quick status checks.
    """
    session_factory = getattr(request.app.state, "session_factory", None)
    entities, is_placeholder = await _load_entities(session_factory, tenant_id)

    generator = CisoReportGenerator()
    report = generator.generate_report(entities)

    return _summary_to_response(report, tenant_id, is_placeholder)


@router.post("/ciso/deliver", response_model=None)
async def deliver_ciso_report(
    request: Request,
    tenant_id: UUID,
    body: CisoReportDeliverRequest,
) -> CisoReportDeliverResponse | JSONResponse:
    """Generate a CISO report and deliver it via email."""
    smtp_cfg = _get_smtp_config()
    if smtp_cfg is None:
        return JSONResponse(
            status_code=503,
            content={
                "detail": (
                    "SMTP not configured. Set EXPOSE_SMTP_USER and "
                    "EXPOSE_SMTP_PASSWORD environment variables."
                ),
            },
        )

    if not body.recipients:
        return JSONResponse(
            status_code=422,
            content={"detail": "recipients list must not be empty"},
        )

    session_factory = getattr(request.app.state, "session_factory", None)
    entities, is_placeholder = await _load_entities(session_factory, tenant_id)

    generator = CisoReportGenerator()
    report = generator.generate_report(entities)
    report_response = _report_to_response(report, tenant_id, is_placeholder)

    html_body = _build_report_html(report_response)

    json_attachment: str | None = None
    if body.include_json_attachment:
        json_attachment = report_response.model_dump_json(indent=2)

    subject = f"{body.subject_prefix} - {tenant_id}"

    delivered, failed = _send_report_emails(
        smtp_cfg, body.recipients, subject, html_body, json_attachment,
    )

    if not delivered and failed:
        return JSONResponse(
            status_code=502,
            content={
                "detail": "All email deliveries failed",
                "delivered_to": [],
                "failed": failed,
            },
        )

    return CisoReportDeliverResponse(
        delivered_to=delivered,
        failed=failed,
        message=f"Delivered to {len(delivered)}/{len(body.recipients)} recipients",
    )
