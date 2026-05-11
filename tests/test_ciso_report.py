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
    ExecutiveSummary,
    KeyFinding,
    OrganizationProfile,
    RankedTarget,
    Recommendation,
    ReportMetrics,
    SectorAnalysis,
    ThreatActorProfile,
    ThreatLandscape,
)
from expose.api.reports import (
    CisoReportResponse,
    ExecutiveSummaryResponse,
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
