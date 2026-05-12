"""Tests for the CISO Report module (``expose.modules.ciso_report``).

Validates issue #113 -- automated executive-level threat intelligence
reporting:

 1. Sector analysis with various entity mixes (tech, financial,
    healthcare, government, general/unknown)
 2. Threat actor profiling for tech and financial sectors
 3. Attraction assessment scoring (surface area, management, TLS,
    database, integration gaps)
 4. Target ranking (top 10, lead_score * exposure_factor)
 5. Executive summary generation (all sections populated)
 6. Full report generation (orchestration)
 7. API endpoint tests (GET /ciso, GET /ciso/summary)
 8. Edge cases (empty entities, single entity, no scores)
 9. Frozen dataclass immutability
10. Response model validation

Uses ``httpx.AsyncClient`` with ``ASGITransport`` against a standalone
FastAPI app that includes only the reports router (no DB required for
placeholder tests).
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from expose.modules.ciso_report import check_license
from expose.modules.ciso_report.generator import (
    AttractionAssessment,
    CisoReport,
    CisoReportGenerator,
    EolProduct,
    ExecutiveSummary,
    HighRiskEndpoint,
    KeyFinding,
    OrganizationProfile,
    RankedTarget,
    Recommendation,
    ReportMetrics,
    SectorAnalysis,
    ThreatActorCweAlignment,
    ThreatActorProfile,
    ThreatLandscape,
    VendorDnaAnalysis,
    VendorProfile,
)
from expose.api.reports import (
    CisoReportResponse,
    ExecutiveSummaryResponse,
    VendorDnaAnalysisResponse,
    router,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TENANT_ID = "00000000-0000-0000-0000-000000000001"
_CISO_URL = f"http://test/v1/tenants/{_TENANT_ID}/reports/ciso"
_SUMMARY_URL = f"http://test/v1/tenants/{_TENANT_ID}/reports/ciso/summary"


def _make_app() -> FastAPI:
    """Build a minimal FastAPI app with the reports router mounted."""
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture()
def app() -> FastAPI:
    return _make_app()


@pytest.fixture()
async def client(app: FastAPI) -> AsyncClient:
    """Yield an async HTTP client wired to the test app."""
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    )


@pytest.fixture()
def generator() -> CisoReportGenerator:
    """A fresh CisoReportGenerator instance."""
    return CisoReportGenerator()


# ---------------------------------------------------------------------------
# Entity factory helpers
# ---------------------------------------------------------------------------


def _tech_entities() -> list[dict[str, Any]]:
    """Entities that should be classified as technology sector."""
    return [
        {
            "canonical_identifier": "api.cloud.example.io",
            "entity_type": "domain",
            "properties": {"open_ports": [{"port": 443}]},
            "attribution_status": "confirmed",
            "attribution_confidence": 0.9,
            "lead_score": 50,
        },
        {
            "canonical_identifier": "staging.dev.example.com",
            "entity_type": "domain",
            "properties": {"open_ports": [{"port": 8080}]},
            "attribution_status": "confirmed",
            "attribution_confidence": 0.85,
            "lead_score": 70,
        },
        {
            "canonical_identifier": "ci.example.com",
            "entity_type": "domain",
            "properties": {},
            "attribution_status": "high",
            "attribution_confidence": 0.75,
            "lead_score": 40,
        },
    ]


def _financial_entities() -> list[dict[str, Any]]:
    """Entities that should be classified as financial sector."""
    return [
        {
            "canonical_identifier": "banking.example.com",
            "entity_type": "domain",
            "properties": {"open_ports": [{"port": 443}]},
            "attribution_status": "confirmed",
            "attribution_confidence": 0.95,
            "lead_score": 60,
        },
        {
            "canonical_identifier": "payment.gateway.example.com",
            "entity_type": "domain",
            "properties": {},
            "attribution_status": "confirmed",
            "attribution_confidence": 0.90,
            "lead_score": 75,
        },
        {
            "canonical_identifier": "pci.compliance.example.com",
            "entity_type": "domain",
            "properties": {},
            "attribution_status": "high",
            "attribution_confidence": 0.80,
            "lead_score": 30,
        },
    ]


def _healthcare_entities() -> list[dict[str, Any]]:
    """Entities that should be classified as healthcare sector."""
    return [
        {
            "canonical_identifier": "ehr.hipaa.hospital.org",
            "entity_type": "domain",
            "properties": {},
            "attribution_status": "confirmed",
            "attribution_confidence": 0.90,
            "lead_score": 55,
        },
        {
            "canonical_identifier": "patient.portal.medical.org",
            "entity_type": "domain",
            "properties": {},
            "attribution_status": "confirmed",
            "attribution_confidence": 0.85,
            "lead_score": 65,
        },
    ]


def _government_entities() -> list[dict[str, Any]]:
    """Entities that should be classified as government sector."""
    return [
        {
            "canonical_identifier": "portal.agency.gov",
            "entity_type": "domain",
            "properties": {},
            "attribution_status": "confirmed",
            "attribution_confidence": 0.95,
            "lead_score": 45,
        },
        {
            "canonical_identifier": "fedramp.services.gov",
            "entity_type": "domain",
            "properties": {},
            "attribution_status": "confirmed",
            "attribution_confidence": 0.90,
            "lead_score": 50,
        },
    ]


def _mixed_entities_with_exposure() -> list[dict[str, Any]]:
    """Entities with various exposure signals for attraction testing."""
    return [
        {
            "canonical_identifier": "staging.example.com",
            "entity_type": "domain",
            "properties": {
                "open_ports": [{"port": 22}, {"port": 3389}, {"port": 3306}],
                "tls_version": "TLS1.0",
                "is_self_signed": True,
                "security_headers": {},
            },
            "attribution_status": "confirmed",
            "attribution_confidence": 0.95,
            "lead_score": 90,
        },
        {
            "canonical_identifier": "db.internal.example.com",
            "entity_type": "domain",
            "properties": {
                "open_ports": [{"port": 5432}, {"port": 27017}],
                "tls_version": "TLS1.2",
                "security_headers": {"strict_transport_security": True},
            },
            "attribution_status": "high",
            "attribution_confidence": 0.80,
            "lead_score": 85,
        },
        {
            "canonical_identifier": "www.example.com",
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
            "attribution_confidence": 0.99,
            "lead_score": 15,
        },
    ]


def _entities_with_integration_gaps() -> list[dict[str, Any]]:
    """Entities with signals of post-acquisition integration gaps."""
    return [
        {
            "canonical_identifier": "legacy.oldcorp.com",
            "entity_type": "domain",
            "properties": {
                "registrant": "OldCorp Inc.",
                "tls_version": "TLS1.0",
                "_ma_discovery": True,
            },
            "attribution_status": "medium",
            "attribution_confidence": 0.60,
            "lead_score": 70,
        },
        {
            "canonical_identifier": "portal.newcorp.com",
            "entity_type": "domain",
            "properties": {
                "registrant": "NewCorp LLC",
                "tls_version": "TLS1.3",
            },
            "attribution_status": "confirmed",
            "attribution_confidence": 0.90,
            "lead_score": 40,
        },
        {
            "canonical_identifier": "api.thirdparty.com",
            "entity_type": "domain",
            "properties": {
                "registrant": "ThirdParty Services",
                "tls_version": "TLS1.2",
                "acquisition": True,
            },
            "attribution_status": "high",
            "attribution_confidence": 0.75,
            "lead_score": 55,
        },
    ]


# ===========================================================================
# 1. License gate
# ===========================================================================


class TestLicenseGate:
    """Verify the module license check placeholder."""

    def test_check_license_returns_true(self) -> None:
        assert check_license() is True


# ===========================================================================
# 2. Sector analysis
# ===========================================================================


class TestSectorAnalysis:
    """Sector inference from entity identifiers and properties."""

    def test_technology_sector(self, generator: CisoReportGenerator) -> None:
        result = generator.analyze_sector(_tech_entities())
        assert result.sector == "technology"
        assert result.confidence > 0.3
        assert len(result.indicators) > 0

    def test_financial_sector(self, generator: CisoReportGenerator) -> None:
        result = generator.analyze_sector(_financial_entities())
        assert result.sector == "financial"
        assert result.confidence > 0.3
        assert len(result.indicators) > 0

    def test_healthcare_sector(self, generator: CisoReportGenerator) -> None:
        result = generator.analyze_sector(_healthcare_entities())
        assert result.sector == "healthcare"
        assert result.confidence > 0.3

    def test_government_sector(self, generator: CisoReportGenerator) -> None:
        result = generator.analyze_sector(_government_entities())
        assert result.sector == "government"
        assert result.confidence > 0.3

    def test_general_sector_for_generic_entities(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "www.example.com",
                "entity_type": "domain",
                "properties": {},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
            },
        ]
        result = generator.analyze_sector(entities)
        assert result.sector == "general"
        assert result.confidence == 0.1

    def test_empty_entities(self, generator: CisoReportGenerator) -> None:
        result = generator.analyze_sector([])
        assert result.sector == "general"
        assert result.confidence == 0.1
        assert result.indicators == ()

    def test_sector_from_properties(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "app.example.com",
                "entity_type": "domain",
                "properties": {"sector": "healthcare"},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
            },
        ]
        result = generator.analyze_sector(entities)
        assert result.sector == "healthcare"

    def test_sector_analysis_is_frozen(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_sector(_tech_entities())
        with pytest.raises(AttributeError):
            result.sector = "financial"  # type: ignore[misc]


# ===========================================================================
# 3. Threat actor profiling
# ===========================================================================


class TestThreatActorProfiling:
    """Threat actor identification based on sector and surface."""

    def test_tech_sector_actors(self, generator: CisoReportGenerator) -> None:
        sector = SectorAnalysis(
            sector="technology", confidence=0.8, indicators=(),
        )
        actors = generator.profile_threat_actors(sector, _tech_entities())
        assert len(actors) > 0
        # Should include sector-specific + general actors
        names = {a.name for a in actors}
        assert "APT41 (Double Dragon)" in names
        assert "LockBit Ransomware" in names  # general actor

    def test_financial_sector_actors(
        self, generator: CisoReportGenerator,
    ) -> None:
        sector = SectorAnalysis(
            sector="financial", confidence=0.85, indicators=(),
        )
        actors = generator.profile_threat_actors(
            sector, _financial_entities(),
        )
        names = {a.name for a in actors}
        assert "APT38 (Lazarus Financial)" in names

    def test_healthcare_sector_actors(
        self, generator: CisoReportGenerator,
    ) -> None:
        sector = SectorAnalysis(
            sector="healthcare", confidence=0.75, indicators=(),
        )
        actors = generator.profile_threat_actors(
            sector, _healthcare_entities(),
        )
        names = {a.name for a in actors}
        assert "FIN12" in names

    def test_government_sector_actors(
        self, generator: CisoReportGenerator,
    ) -> None:
        sector = SectorAnalysis(
            sector="government", confidence=0.9, indicators=(),
        )
        actors = generator.profile_threat_actors(
            sector, _government_entities(),
        )
        names = {a.name for a in actors}
        assert "APT29 (Cozy Bear)" in names

    def test_actors_sorted_by_relevance(
        self, generator: CisoReportGenerator,
    ) -> None:
        sector = SectorAnalysis(
            sector="technology", confidence=0.8, indicators=(),
        )
        actors = generator.profile_threat_actors(sector, _tech_entities())
        scores = [a.relevance_score for a in actors]
        assert scores == sorted(scores, reverse=True)

    def test_actors_have_ttps(
        self, generator: CisoReportGenerator,
    ) -> None:
        sector = SectorAnalysis(
            sector="financial", confidence=0.8, indicators=(),
        )
        actors = generator.profile_threat_actors(
            sector, _financial_entities(),
        )
        for actor in actors:
            assert len(actor.typical_ttps) > 0
            assert actor.motivation in (
                "espionage", "financial", "hacktivism", "destruction",
            )

    def test_management_ports_boost_relevance(
        self, generator: CisoReportGenerator,
    ) -> None:
        sector = SectorAnalysis(
            sector="technology", confidence=0.8, indicators=(),
        )
        entities_no_mgmt = [
            {
                "canonical_identifier": "web.example.com",
                "entity_type": "domain",
                "properties": {"open_ports": [{"port": 443}]},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
            },
        ]
        entities_with_mgmt = [
            {
                "canonical_identifier": "web.example.com",
                "entity_type": "domain",
                "properties": {"open_ports": [{"port": 22}, {"port": 3389}]},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
            },
        ]
        actors_no = generator.profile_threat_actors(sector, entities_no_mgmt)
        actors_yes = generator.profile_threat_actors(
            sector, entities_with_mgmt,
        )
        # With management ports, the top actor should have a higher score
        assert actors_yes[0].relevance_score >= actors_no[0].relevance_score

    def test_unknown_sector_returns_general_actors(
        self, generator: CisoReportGenerator,
    ) -> None:
        sector = SectorAnalysis(sector="general", confidence=0.1, indicators=())
        actors = generator.profile_threat_actors(sector, [])
        assert len(actors) > 0
        names = {a.name for a in actors}
        assert "LockBit Ransomware" in names

    def test_actor_profile_is_frozen(
        self, generator: CisoReportGenerator,
    ) -> None:
        sector = SectorAnalysis(
            sector="technology", confidence=0.8, indicators=(),
        )
        actors = generator.profile_threat_actors(sector, _tech_entities())
        with pytest.raises(AttributeError):
            actors[0].name = "Changed"  # type: ignore[misc]


# ===========================================================================
# 4. Attraction assessment
# ===========================================================================


class TestAttractionAssessment:
    """Attacker attraction scoring from entity exposure signals."""

    def test_high_exposure_entities(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.assess_attraction(_mixed_entities_with_exposure())
        assert 0 <= result.overall_score <= 100
        assert len(result.factors) == 5  # noqa: PLR2004

        factor_names = {f.factor for f in result.factors}
        assert "external_surface_area" in factor_names
        assert "management_interface_exposure" in factor_names
        assert "weak_security_posture" in factor_names
        assert "database_exposure" in factor_names
        assert "integration_gaps" in factor_names

    def test_management_exposure_scored(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "admin.example.com",
                "entity_type": "domain",
                "properties": {
                    "open_ports": [
                        {"port": 22}, {"port": 3389}, {"port": 9090},
                    ],
                },
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
            },
        ]
        result = generator.assess_attraction(entities)
        mgmt_factor = next(
            f for f in result.factors
            if f.factor == "management_interface_exposure"
        )
        assert mgmt_factor.score > 0

    def test_database_exposure_scored(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "db.example.com",
                "entity_type": "domain",
                "properties": {"open_ports": [{"port": 5432}]},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
            },
        ]
        result = generator.assess_attraction(entities)
        db_factor = next(
            f for f in result.factors if f.factor == "database_exposure"
        )
        assert db_factor.score > 0

    def test_no_exposure_low_score(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "www.example.com",
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
                "attribution_confidence": 0.99,
            },
        ]
        result = generator.assess_attraction(entities)
        assert result.overall_score < 30  # noqa: PLR2004

    def test_empty_entities_low_score(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.assess_attraction([])
        assert result.overall_score <= 10  # noqa: PLR2004

    def test_integration_gaps_from_registrants(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.assess_attraction(
            _entities_with_integration_gaps(),
        )
        gap_factor = next(
            f for f in result.factors if f.factor == "integration_gaps"
        )
        assert gap_factor.score > 0

    def test_weak_tls_scored(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "legacy.example.com",
                "entity_type": "domain",
                "properties": {
                    "tls_version": "TLS1.0",
                    "is_self_signed": True,
                    "is_expired": True,
                    "security_headers": {},
                },
                "attribution_status": "confirmed",
                "attribution_confidence": 0.8,
            },
        ]
        result = generator.assess_attraction(entities)
        tls_factor = next(
            f for f in result.factors if f.factor == "weak_security_posture"
        )
        assert tls_factor.score > 0

    def test_assessment_is_frozen(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.assess_attraction(_mixed_entities_with_exposure())
        with pytest.raises(AttributeError):
            result.overall_score = 50  # type: ignore[misc]


# ===========================================================================
# 5. Target ranking
# ===========================================================================


class TestTargetRanking:
    """Entity ranking by combined risk score."""

    def test_top_10_returned(
        self, generator: CisoReportGenerator,
    ) -> None:
        # Create 15 entities to verify top-10 cap
        entities = []
        for i in range(15):
            entities.append({
                "canonical_identifier": f"host{i}.example.com",
                "entity_type": "domain",
                "properties": {},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
                "lead_score": 50 + i,
            })
        targets = generator.rank_likely_targets(entities)
        assert len(targets) <= 10  # noqa: PLR2004

    def test_sorted_by_risk_descending(
        self, generator: CisoReportGenerator,
    ) -> None:
        targets = generator.rank_likely_targets(
            _mixed_entities_with_exposure(),
        )
        scores = [t.risk_score for t in targets]
        assert scores == sorted(scores, reverse=True)

    def test_exposure_factor_boosts_risk(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "secure.example.com",
                "entity_type": "domain",
                "properties": {"open_ports": [{"port": 443}]},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
                "lead_score": 50,
            },
            {
                "canonical_identifier": "exposed.example.com",
                "entity_type": "domain",
                "properties": {
                    "open_ports": [
                        {"port": 22}, {"port": 3306}, {"port": 5432},
                    ],
                    "is_self_signed": True,
                },
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
                "lead_score": 50,  # Same lead score
            },
        ]
        targets = generator.rank_likely_targets(entities)
        # exposed.example.com should rank higher due to exposure factor
        assert targets[0].entity_identifier == "exposed.example.com"
        assert targets[0].risk_score > targets[1].risk_score

    def test_targets_have_justification(
        self, generator: CisoReportGenerator,
    ) -> None:
        targets = generator.rank_likely_targets(
            _mixed_entities_with_exposure(),
        )
        for target in targets:
            assert len(target.justification) > 0
            assert len(target.recommended_action) > 0

    def test_database_port_recommendation(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "db.example.com",
                "entity_type": "domain",
                "properties": {"open_ports": [{"port": 5432}]},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
                "lead_score": 80,
            },
        ]
        targets = generator.rank_likely_targets(entities)
        assert "CRITICAL" in targets[0].recommended_action

    def test_empty_entities(
        self, generator: CisoReportGenerator,
    ) -> None:
        targets = generator.rank_likely_targets([])
        assert targets == []

    def test_default_lead_score(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "no-score.example.com",
                "entity_type": "domain",
                "properties": {},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
                # No lead_score key at all
            },
        ]
        targets = generator.rank_likely_targets(entities)
        assert len(targets) == 1
        assert targets[0].risk_score == 10.0

    def test_lead_score_from_properties(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "scored.example.com",
                "entity_type": "domain",
                "properties": {"_lead_score": 75},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
            },
        ]
        targets = generator.rank_likely_targets(entities)
        assert targets[0].risk_score >= 75.0

    def test_ranked_target_is_frozen(
        self, generator: CisoReportGenerator,
    ) -> None:
        targets = generator.rank_likely_targets(
            _mixed_entities_with_exposure(),
        )
        with pytest.raises(AttributeError):
            targets[0].risk_score = 99.0  # type: ignore[misc]


# ===========================================================================
# 6. Executive summary generation
# ===========================================================================


class TestExecutiveSummary:
    """Executive summary aggregation from all analyses."""

    def test_summary_structure(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = _mixed_entities_with_exposure()
        sector = generator.analyze_sector(entities)
        actors = generator.profile_threat_actors(sector, entities)
        attraction = generator.assess_attraction(entities)
        targets = generator.rank_likely_targets(entities)

        summary = generator.generate_executive_summary(
            entities, sector, actors, attraction, targets,
        )

        assert isinstance(summary, ExecutiveSummary)
        assert isinstance(summary.organization_profile, OrganizationProfile)
        assert isinstance(summary.threat_landscape, ThreatLandscape)
        assert isinstance(summary.metrics, ReportMetrics)
        assert len(summary.recommendations) > 0
        assert summary.metrics.total_entities == len(entities)

    def test_summary_has_key_findings(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = _mixed_entities_with_exposure()
        sector = generator.analyze_sector(entities)
        actors = generator.profile_threat_actors(sector, entities)
        attraction = generator.assess_attraction(entities)
        targets = generator.rank_likely_targets(entities)

        summary = generator.generate_executive_summary(
            entities, sector, actors, attraction, targets,
        )
        # With exposed management + DB ports, there should be findings
        assert len(summary.key_findings) > 0
        severities = {f.severity for f in summary.key_findings}
        # Database exposure should trigger critical finding
        assert "critical" in severities

    def test_summary_recommendations_prioritized(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = _mixed_entities_with_exposure()
        sector = generator.analyze_sector(entities)
        actors = generator.profile_threat_actors(sector, entities)
        attraction = generator.assess_attraction(entities)
        targets = generator.rank_likely_targets(entities)

        summary = generator.generate_executive_summary(
            entities, sector, actors, attraction, targets,
        )
        priorities = [r.priority for r in summary.recommendations]
        assert priorities == sorted(priorities)
        assert summary.recommendations[0].priority == 1

    def test_summary_metrics_coverage(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = _mixed_entities_with_exposure()
        sector = generator.analyze_sector(entities)
        actors = generator.profile_threat_actors(sector, entities)
        attraction = generator.assess_attraction(entities)
        targets = generator.rank_likely_targets(entities)

        summary = generator.generate_executive_summary(
            entities, sector, actors, attraction, targets,
        )
        assert summary.metrics.total_entities == 3  # noqa: PLR2004
        assert "scored_entities" in summary.metrics.coverage_stats
        assert "scoring_coverage" in summary.metrics.coverage_stats

    def test_summary_with_empty_entities(
        self, generator: CisoReportGenerator,
    ) -> None:
        sector = SectorAnalysis(sector="general", confidence=0.1, indicators=())
        actors = generator.profile_threat_actors(sector, [])
        attraction = generator.assess_attraction([])
        targets = generator.rank_likely_targets([])

        summary = generator.generate_executive_summary(
            [], sector, actors, attraction, targets,
        )
        assert summary.metrics.total_entities == 0

    def test_organization_profile_sector(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = _tech_entities()
        sector = generator.analyze_sector(entities)
        actors = generator.profile_threat_actors(sector, entities)
        attraction = generator.assess_attraction(entities)
        targets = generator.rank_likely_targets(entities)

        summary = generator.generate_executive_summary(
            entities, sector, actors, attraction, targets,
        )
        assert summary.organization_profile.sector == "technology"

    def test_threat_landscape_top_threats(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = _financial_entities()
        sector = generator.analyze_sector(entities)
        actors = generator.profile_threat_actors(sector, entities)
        attraction = generator.assess_attraction(entities)
        targets = generator.rank_likely_targets(entities)

        summary = generator.generate_executive_summary(
            entities, sector, actors, attraction, targets,
        )
        assert len(summary.threat_landscape.top_threats) <= 3  # noqa: PLR2004
        assert len(summary.threat_landscape.actor_profiles) <= 5  # noqa: PLR2004


# ===========================================================================
# 7. Full report generation
# ===========================================================================


class TestFullReport:
    """End-to-end report generation via generate_report()."""

    def test_report_structure(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report(_mixed_entities_with_exposure())

        assert isinstance(report, CisoReport)
        assert report.report_version == "1.0.0"
        assert report.generated_at is not None
        assert isinstance(report.sector_analysis, SectorAnalysis)
        assert len(report.threat_actors) > 0
        assert isinstance(report.attraction_assessment, AttractionAssessment)
        assert isinstance(report.executive_summary, ExecutiveSummary)

    def test_report_with_tech_entities(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report(_tech_entities())
        assert report.sector_analysis.sector == "technology"

    def test_report_with_financial_entities(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report(_financial_entities())
        assert report.sector_analysis.sector == "financial"

    def test_report_with_empty_entities(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report([])
        assert report.sector_analysis.sector == "general"
        assert report.executive_summary.metrics.total_entities == 0

    def test_report_is_frozen(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report(_tech_entities())
        with pytest.raises(AttributeError):
            report.report_version = "2.0.0"  # type: ignore[misc]

    def test_report_targets_capped_at_10(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = []
        for i in range(25):
            entities.append({
                "canonical_identifier": f"host{i}.example.com",
                "entity_type": "domain",
                "properties": {},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
                "lead_score": 10 + i * 3,
            })
        report = generator.generate_report(entities)
        assert len(report.ranked_targets) <= 10  # noqa: PLR2004


# ===========================================================================
# 8. API endpoint tests
# ===========================================================================


class TestCisoReportAPI:
    """HTTP endpoint tests for the reports router."""

    @pytest.mark.anyio()
    async def test_get_ciso_report_200(self, client: AsyncClient) -> None:
        resp = await client.get(_CISO_URL)
        assert resp.status_code == 200

    @pytest.mark.anyio()
    async def test_ciso_report_response_structure(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_CISO_URL)
        data = resp.json()

        assert data["tenant_id"] == _TENANT_ID
        assert data["report_version"] == "1.0.0"
        assert data["is_placeholder"] is True
        assert "sector_analysis" in data
        assert "threat_actors" in data
        assert "attraction_assessment" in data
        assert "ranked_targets" in data
        assert "executive_summary" in data

    @pytest.mark.anyio()
    async def test_ciso_report_sector_analysis(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_CISO_URL)
        data = resp.json()
        sector = data["sector_analysis"]
        assert "sector" in sector
        assert "confidence" in sector
        assert "indicators" in sector

    @pytest.mark.anyio()
    async def test_ciso_report_threat_actors(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_CISO_URL)
        data = resp.json()
        actors = data["threat_actors"]
        assert isinstance(actors, list)
        assert len(actors) > 0
        for actor in actors:
            assert "name" in actor
            assert "motivation" in actor
            assert "relevance_score" in actor
            assert "typical_ttps" in actor

    @pytest.mark.anyio()
    async def test_ciso_report_attraction(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_CISO_URL)
        data = resp.json()
        attraction = data["attraction_assessment"]
        assert 0 <= attraction["overall_score"] <= 100
        assert len(attraction["factors"]) == 5  # noqa: PLR2004

    @pytest.mark.anyio()
    async def test_ciso_report_ranked_targets(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_CISO_URL)
        data = resp.json()
        targets = data["ranked_targets"]
        assert isinstance(targets, list)
        # Targets should be sorted by risk descending
        scores = [t["risk_score"] for t in targets]
        assert scores == sorted(scores, reverse=True)

    @pytest.mark.anyio()
    async def test_get_ciso_summary_200(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_SUMMARY_URL)
        assert resp.status_code == 200

    @pytest.mark.anyio()
    async def test_ciso_summary_structure(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_SUMMARY_URL)
        data = resp.json()

        assert "organization_profile" in data
        assert "threat_landscape" in data
        assert "key_findings" in data
        assert "recommendations" in data
        assert "metrics" in data
        assert data["is_placeholder"] is True

    @pytest.mark.anyio()
    async def test_ciso_summary_metrics(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_SUMMARY_URL)
        data = resp.json()
        metrics = data["metrics"]
        assert metrics["total_entities"] > 0
        assert "entities_by_tier" in metrics
        assert "coverage_stats" in metrics

    @pytest.mark.anyio()
    async def test_ciso_summary_recommendations_ordered(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_SUMMARY_URL)
        data = resp.json()
        recs = data["recommendations"]
        priorities = [r["priority"] for r in recs]
        assert priorities == sorted(priorities)

    @pytest.mark.anyio()
    async def test_invalid_tenant_id_422(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(
            "http://test/v1/tenants/not-a-uuid/reports/ciso",
        )
        assert resp.status_code == 422  # noqa: PLR2004

    @pytest.mark.anyio()
    async def test_pydantic_model_validation(
        self, client: AsyncClient,
    ) -> None:
        """Verify that the response validates against the Pydantic model."""
        resp = await client.get(_CISO_URL)
        data = resp.json()
        # Should not raise
        report = CisoReportResponse.model_validate(data)
        assert report.tenant_id == UUID(_TENANT_ID)

    @pytest.mark.anyio()
    async def test_summary_pydantic_validation(
        self, client: AsyncClient,
    ) -> None:
        """Verify summary response validates against Pydantic model."""
        resp = await client.get(_SUMMARY_URL)
        data = resp.json()
        summary = ExecutiveSummaryResponse.model_validate(data)
        assert summary.is_placeholder is True


# ===========================================================================
# 9. Edge cases and property extraction
# ===========================================================================


class TestEdgeCases:
    """Edge cases for entity parsing and scoring."""

    def test_port_extraction_from_list_of_ints(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "test.example.com",
                "entity_type": "domain",
                "properties": {"open_ports": [22, 443, 3306]},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
                "lead_score": 50,
            },
        ]
        targets = generator.rank_likely_targets(entities)
        assert len(targets) == 1
        # Management port 22 and DB port 3306 should boost exposure
        assert targets[0].risk_score > 50.0

    def test_port_extraction_from_exposure_dict(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "test.example.com",
                "entity_type": "domain",
                "properties": {
                    "exposure": {
                        "open_ports": [{"port": 22}, {"port": 5432}],
                    },
                },
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
                "lead_score": 60,
            },
        ]
        targets = generator.rank_likely_targets(entities)
        assert targets[0].risk_score > 60.0

    def test_single_entity(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "solo.example.com",
                "entity_type": "domain",
                "properties": {},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
                "lead_score": 30,
            },
        ]
        report = generator.generate_report(entities)
        assert report.executive_summary.metrics.total_entities == 1
        assert len(report.ranked_targets) == 1

    def test_invalid_lead_score_type(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "bad.example.com",
                "entity_type": "domain",
                "properties": {},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
                "lead_score": "not_a_number",
            },
        ]
        targets = generator.rank_likely_targets(entities)
        # Should fall back to default score of 10
        assert targets[0].risk_score == 10.0

    def test_surface_size_classifications(
        self, generator: CisoReportGenerator,
    ) -> None:
        assert generator._estimate_surface_size(5) == "small"
        assert generator._estimate_surface_size(10) == "small"
        assert generator._estimate_surface_size(11) == "medium"
        assert generator._estimate_surface_size(50) == "medium"
        assert generator._estimate_surface_size(51) == "large"
        assert generator._estimate_surface_size(200) == "large"
        assert generator._estimate_surface_size(201) == "very_large"

    def test_exposure_factor_capped_at_3(
        self, generator: CisoReportGenerator,
    ) -> None:
        entity = {
            "canonical_identifier": "max.example.com",
            "entity_type": "domain",
            "properties": {
                "open_ports": [
                    {"port": 22}, {"port": 3306}, {"port": 5432},
                ],
                "tls_version": "TLS1.0",
                "is_self_signed": True,
                "is_expired": True,
                "security_headers": {},
            },
            "attribution_status": "confirmed",
            "attribution_confidence": 0.9,
        }
        factor = generator._calculate_exposure_factor(entity)
        assert factor <= 3.0

    def test_metrics_entities_by_tier(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "a.example.com",
                "entity_type": "domain",
                "properties": {},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.9,
                "lead_score": 80,
            },
            {
                "canonical_identifier": "b.example.com",
                "entity_type": "domain",
                "properties": {},
                "attribution_status": "confirmed",
                "attribution_confidence": 0.85,
                "lead_score": 40,
            },
            {
                "canonical_identifier": "c.example.com",
                "entity_type": "domain",
                "properties": {},
                "attribution_status": "medium",
                "attribution_confidence": 0.60,
                "lead_score": 20,
            },
        ]
        metrics = generator._compute_metrics(entities)
        assert metrics.total_entities == 3  # noqa: PLR2004
        assert metrics.entities_by_tier["confirmed"] == 2  # noqa: PLR2004
        assert metrics.entities_by_tier["medium"] == 1
        assert metrics.coverage_stats["high_risk_entities"] == 1


# ===========================================================================
# 10. Vendor Vulnerability DNA
# ===========================================================================


def _entities_with_vendor_stack() -> list[dict[str, Any]]:
    """Entities with technology stack properties for vendor DNA testing.

    Uses current (non-EOL) versions to test vendor detection without
    triggering EOL findings.
    """
    return [
        {
            "canonical_identifier": "web.example.com",
            "entity_type": "domain",
            "properties": {
                "server_header": "Apache/2.4.59 (Ubuntu) PHP/8.3.6",
                "technologies": ["PHP", "MySQL", "Apache"],
                "open_ports": [{"port": 80}, {"port": 443}],
            },
            "attribution_status": "confirmed",
            "attribution_confidence": 0.95,
            "lead_score": 80,
        },
        {
            "canonical_identifier": "api.example.com",
            "entity_type": "domain",
            "properties": {
                "server_header": "nginx/1.24.0",
                "x_powered_by": "Express",
                "technologies": ["Node.js", "nginx"],
                "open_ports": [{"port": 443}],
            },
            "attribution_status": "confirmed",
            "attribution_confidence": 0.90,
            "lead_score": 60,
        },
        {
            "canonical_identifier": "app.example.com",
            "entity_type": "domain",
            "properties": {
                "server_header": "Microsoft-IIS/10.0",
                "x_powered_by": "ASP.NET",
                "open_ports": [{"port": 443}, {"port": 8443}],
            },
            "attribution_status": "confirmed",
            "attribution_confidence": 0.85,
            "lead_score": 70,
        },
    ]


def _entities_with_eol_products() -> list[dict[str, Any]]:
    """Entities with known EOL products for vendor DNA testing."""
    return [
        {
            "canonical_identifier": "old-php.example.com",
            "entity_type": "domain",
            "properties": {
                "server_header": "Apache/2.2.15 PHP/5.3.3",
                "technologies": ["PHP/5.3.3"],
            },
            "attribution_status": "confirmed",
            "attribution_confidence": 0.90,
            "lead_score": 85,
        },
        {
            "canonical_identifier": "old-iis.example.com",
            "entity_type": "domain",
            "properties": {
                "server_header": "Microsoft-IIS/6.0",
            },
            "attribution_status": "confirmed",
            "attribution_confidence": 0.80,
            "lead_score": 75,
        },
        {
            "canonical_identifier": "old-node.example.com",
            "entity_type": "domain",
            "properties": {
                "server_header": "Node/12.22.1",
                "technologies": ["Node/12.22.1", "Express"],
            },
            "attribution_status": "confirmed",
            "attribution_confidence": 0.85,
            "lead_score": 65,
        },
        {
            "canonical_identifier": "old-openssl.example.com",
            "entity_type": "domain",
            "properties": {
                "server_header": "Apache/2.4.41 (Ubuntu) OpenSSL/1.0.2g",
                "technologies": ["OpenSSL/1.0.2g", "Apache"],
            },
            "attribution_status": "confirmed",
            "attribution_confidence": 0.88,
            "lead_score": 70,
        },
    ]


def _entities_without_tech() -> list[dict[str, Any]]:
    """Entities with no technology fingerprint data."""
    return [
        {
            "canonical_identifier": "mystery.example.com",
            "entity_type": "domain",
            "properties": {
                "open_ports": [{"port": 443}],
            },
            "attribution_status": "confirmed",
            "attribution_confidence": 0.90,
            "lead_score": 50,
        },
    ]


def _entities_multi_vendor_high_risk() -> list[dict[str, Any]]:
    """Entity running multiple vendor stacks (compound risk > 60)."""
    return [
        {
            "canonical_identifier": "complex.example.com",
            "entity_type": "domain",
            "properties": {
                "server_header": "Apache/2.4.52",
                "x_powered_by": "PHP/8.1",
                "technologies": ["Apache", "PHP", "Java", "Spring Boot"],
            },
            "attribution_status": "confirmed",
            "attribution_confidence": 0.90,
            "lead_score": 90,
        },
    ]


class TestVendorDnaAnalysis:
    """Vendor Vulnerability DNA analysis from technology stack."""

    def test_detects_vendors_from_server_header(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_with_vendor_stack())
        vendor_names = {vp.vendor for vp in result.vendor_profiles}
        assert "apache" in vendor_names
        assert "nginx" in vendor_names
        assert "node" in vendor_names
        assert "microsoft" in vendor_names

    def test_detects_vendors_from_technologies_list(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "tech.example.com",
                "entity_type": "domain",
                "properties": {
                    "technologies": ["Django", "Python", "gunicorn"],
                },
                "attribution_status": "confirmed",
                "attribution_confidence": 0.90,
                "lead_score": 50,
            },
        ]
        result = generator.analyze_vendor_dna(entities)
        vendor_names = {vp.vendor for vp in result.vendor_profiles}
        assert "python" in vendor_names

    def test_detects_vendors_from_x_powered_by(
        self, generator: CisoReportGenerator,
    ) -> None:
        entities = [
            {
                "canonical_identifier": "express.example.com",
                "entity_type": "domain",
                "properties": {
                    "x_powered_by": "Express",
                },
                "attribution_status": "confirmed",
                "attribution_confidence": 0.90,
                "lead_score": 50,
            },
        ]
        result = generator.analyze_vendor_dna(entities)
        vendor_names = {vp.vendor for vp in result.vendor_profiles}
        assert "node" in vendor_names

    def test_vendor_profiles_have_cwe_distribution(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_with_vendor_stack())
        for vp in result.vendor_profiles:
            assert len(vp.cwe_distribution) > 0
            # CWE weights should sum to approximately 1.0
            total_weight = sum(w for _, w in vp.cwe_distribution)
            assert 0.9 <= total_weight <= 1.1

    def test_vendor_profiles_have_products(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_with_vendor_stack())
        for vp in result.vendor_profiles:
            assert len(vp.products) > 0

    def test_aggregate_risk_in_range(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_with_vendor_stack())
        for vp in result.vendor_profiles:
            assert 0.0 <= vp.aggregate_risk <= 100.0

    def test_eol_product_detection(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_with_eol_products())
        assert len(result.eol_products) > 0
        eol_product_names = {eol.product for eol in result.eol_products}
        # Should detect PHP 5.x, IIS 6.0, Node.js 12.x, OpenSSL 1.0.x
        assert any("PHP" in p for p in eol_product_names)
        assert any("IIS" in p for p in eol_product_names)
        assert any("Node" in p for p in eol_product_names)
        assert any("OpenSSL" in p for p in eol_product_names)

    def test_eol_products_have_reason(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_with_eol_products())
        for eol in result.eol_products:
            assert len(eol.eol_reason) > 0
            assert len(eol.endpoint) > 0
            assert len(eol.vendor) > 0

    def test_high_risk_endpoint_detection(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(
            _entities_multi_vendor_high_risk(),
        )
        assert len(result.high_risk_endpoints) > 0
        for ep in result.high_risk_endpoints:
            assert ep.compound_risk > 60  # noqa: PLR2004
            assert len(ep.contributing_products) > 0
            assert len(ep.top_cwes) > 0

    def test_high_risk_endpoints_sorted_descending(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(
            _entities_multi_vendor_high_risk(),
        )
        if len(result.high_risk_endpoints) > 1:
            scores = [ep.compound_risk for ep in result.high_risk_endpoints]
            assert scores == sorted(scores, reverse=True)

    def test_patch_velocity_with_eol(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_with_eol_products())
        # 4 EOL products should trigger POOR assessment
        assert result.patch_velocity_assessment.startswith("POOR")

    def test_patch_velocity_below_average(
        self, generator: CisoReportGenerator,
    ) -> None:
        # Use a single EOL entity
        entities = [_entities_with_eol_products()[0]]
        result = generator.analyze_vendor_dna(entities)
        assert result.patch_velocity_assessment.startswith("BELOW AVERAGE")

    def test_patch_velocity_no_eol(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_with_vendor_stack())
        assert "No end-of-life products detected" in result.patch_velocity_assessment

    def test_patch_velocity_no_tech(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_without_tech())
        assert "Insufficient" in result.patch_velocity_assessment

    def test_threat_actor_alignment(
        self, generator: CisoReportGenerator,
    ) -> None:
        actors = [
            ThreatActorProfile(
                name="APT41 (Double Dragon)",
                motivation="espionage",
                relevance_score=0.85,
                typical_ttps=(),
                description="Test",
            ),
            ThreatActorProfile(
                name="LockBit Ransomware",
                motivation="financial",
                relevance_score=0.60,
                typical_ttps=(),
                description="Test",
            ),
        ]
        result = generator.analyze_vendor_dna(
            _entities_with_vendor_stack(), actors,
        )
        assert len(result.threat_actor_alignment) > 0
        # Each alignment should have matching CWEs
        for alignment in result.threat_actor_alignment:
            assert len(alignment.matching_cwes) > 0
            assert 0.0 <= alignment.alignment_score <= 1.0

    def test_threat_actor_alignment_sorted_descending(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_with_vendor_stack())
        if len(result.threat_actor_alignment) > 1:
            scores = [a.alignment_score for a in result.threat_actor_alignment]
            assert scores == sorted(scores, reverse=True)

    def test_threat_actor_alignment_uses_all_actors_when_none(
        self, generator: CisoReportGenerator,
    ) -> None:
        # When threat_actors is None, all known actors should be checked
        result = generator.analyze_vendor_dna(
            _entities_with_vendor_stack(), None,
        )
        actor_names = {a.actor_name for a in result.threat_actor_alignment}
        # With apache/nginx/node/microsoft, many CWEs match many actors
        assert len(actor_names) > 0

    def test_empty_entities_returns_empty_analysis(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna([])
        assert len(result.vendor_profiles) == 0
        assert len(result.high_risk_endpoints) == 0
        assert len(result.eol_products) == 0
        assert len(result.threat_actor_alignment) == 0
        assert "Insufficient" in result.patch_velocity_assessment

    def test_no_tech_entities_returns_empty_profiles(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_without_tech())
        assert len(result.vendor_profiles) == 0
        assert len(result.high_risk_endpoints) == 0

    def test_vendor_dna_is_frozen(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_with_vendor_stack())
        with pytest.raises(AttributeError):
            result.patch_velocity_assessment = "changed"  # type: ignore[misc]

    def test_vendor_profile_is_frozen(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_with_vendor_stack())
        if result.vendor_profiles:
            with pytest.raises(AttributeError):
                result.vendor_profiles[0].vendor = "changed"  # type: ignore[misc]

    def test_eol_product_is_frozen(
        self, generator: CisoReportGenerator,
    ) -> None:
        result = generator.analyze_vendor_dna(_entities_with_eol_products())
        if result.eol_products:
            with pytest.raises(AttributeError):
                result.eol_products[0].product = "changed"  # type: ignore[misc]


class TestVendorDnaInReport:
    """Vendor DNA integration into full report and executive summary."""

    def test_report_includes_vendor_dna(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report(_entities_with_vendor_stack())
        assert report.vendor_dna is not None
        assert isinstance(report.vendor_dna, VendorDnaAnalysis)

    def test_report_vendor_dna_has_profiles(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report(_entities_with_vendor_stack())
        assert report.vendor_dna is not None
        assert len(report.vendor_dna.vendor_profiles) > 0

    def test_report_vendor_dna_with_eol(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report(_entities_with_eol_products())
        assert report.vendor_dna is not None
        assert len(report.vendor_dna.eol_products) > 0

    def test_report_empty_entities_vendor_dna_none_values(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report([])
        assert report.vendor_dna is not None
        assert len(report.vendor_dna.vendor_profiles) == 0

    def test_executive_summary_includes_vendor_dna_findings(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report(_entities_with_eol_products())
        # EOL products should generate key findings
        eol_findings = [
            f for f in report.executive_summary.key_findings
            if "end-of-life" in f.title.lower()
        ]
        assert len(eol_findings) > 0

    def test_executive_summary_vendor_dna_recommendations(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report(_entities_with_eol_products())
        eol_recs = [
            r for r in report.executive_summary.recommendations
            if "end-of-life" in r.title.lower()
                or "end-of-life" in r.description.lower()
        ]
        assert len(eol_recs) > 0

    def test_high_risk_endpoint_findings(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report(
            _entities_multi_vendor_high_risk(),
        )
        if report.vendor_dna and report.vendor_dna.high_risk_endpoints:
            hr_findings = [
                f for f in report.executive_summary.key_findings
                if "compound vendor" in f.title.lower()
            ]
            assert len(hr_findings) > 0

    def test_threat_actor_alignment_findings(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report(_entities_with_vendor_stack())
        if (
            report.vendor_dna
            and report.vendor_dna.threat_actor_alignment
            and any(
                a.alignment_score >= 0.6
                for a in report.vendor_dna.threat_actor_alignment
            )
        ):
            alignment_findings = [
                f for f in report.executive_summary.key_findings
                if "threat actor" in f.title.lower()
            ]
            assert len(alignment_findings) > 0

    def test_vendor_dna_no_tech_still_has_report(
        self, generator: CisoReportGenerator,
    ) -> None:
        report = generator.generate_report(_entities_without_tech())
        assert report.vendor_dna is not None
        assert report.vendor_dna.patch_velocity_assessment.startswith(
            "Insufficient",
        )


class TestVendorDnaAPI:
    """API endpoint tests for vendor DNA in CISO reports."""

    @pytest.mark.anyio()
    async def test_ciso_report_includes_vendor_dna(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_CISO_URL)
        assert resp.status_code == 200
        data = resp.json()
        assert "vendor_dna" in data
        # Placeholder entities have tech data, so vendor_dna should exist
        assert data["vendor_dna"] is not None

    @pytest.mark.anyio()
    async def test_vendor_dna_structure(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_CISO_URL)
        data = resp.json()
        vdna = data["vendor_dna"]
        assert "vendor_profiles" in vdna
        assert "high_risk_endpoints" in vdna
        assert "eol_products" in vdna
        assert "patch_velocity_assessment" in vdna
        assert "threat_actor_alignment" in vdna

    @pytest.mark.anyio()
    async def test_vendor_dna_profiles_populated(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_CISO_URL)
        data = resp.json()
        profiles = data["vendor_dna"]["vendor_profiles"]
        assert isinstance(profiles, list)
        assert len(profiles) > 0
        for vp in profiles:
            assert "vendor" in vp
            assert "products" in vp
            assert "cwe_distribution" in vp
            assert "aggregate_risk" in vp

    @pytest.mark.anyio()
    async def test_vendor_dna_eol_products_detected(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_CISO_URL)
        data = resp.json()
        eol = data["vendor_dna"]["eol_products"]
        assert isinstance(eol, list)
        # Placeholder has Apache/2.2 and PHP/5.x which are EOL
        assert len(eol) > 0

    @pytest.mark.anyio()
    async def test_vendor_dna_patch_velocity(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_CISO_URL)
        data = resp.json()
        pva = data["vendor_dna"]["patch_velocity_assessment"]
        assert isinstance(pva, str)
        assert len(pva) > 0

    @pytest.mark.anyio()
    async def test_vendor_dna_threat_alignment(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_CISO_URL)
        data = resp.json()
        alignment = data["vendor_dna"]["threat_actor_alignment"]
        assert isinstance(alignment, list)
        for a in alignment:
            assert "actor_name" in a
            assert "matching_cwes" in a
            assert "alignment_score" in a
            assert 0.0 <= a["alignment_score"] <= 1.0

    @pytest.mark.anyio()
    async def test_vendor_dna_pydantic_validation(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(_CISO_URL)
        data = resp.json()
        vdna = data["vendor_dna"]
        # Should not raise
        validated = VendorDnaAnalysisResponse.model_validate(vdna)
        assert len(validated.vendor_profiles) > 0
