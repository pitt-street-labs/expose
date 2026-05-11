"""CISO Report generator -- executive-level threat intelligence reporting.

Analyzes entity observations, relationships, lead scores, and optional
LLM enrichment data to produce strategic reports suitable for C-suite
presentation.  This is a **pure** module: no LLM calls, no external I/O,
no database dependency.  All analysis is deterministic based on input data.

Implements issue #113.

FIPS gate compliance: This module does NOT import ``hashlib``, ``secrets``,
or ``Crypto``.  No HTTP, no network I/O.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


# ============================================================================
# Value types (frozen dataclasses per project convention)
# ============================================================================


@dataclass(frozen=True)
class SectorAnalysis:
    """Result of sector/vertical inference from discovered assets."""

    sector: str
    confidence: float  # 0.0 -- 1.0
    indicators: tuple[str, ...]


@dataclass(frozen=True)
class ThreatActorProfile:
    """A likely threat actor group targeting the organization's sector."""

    name: str
    motivation: str  # espionage, financial, hacktivism, destruction
    relevance_score: float  # 0.0 -- 1.0
    typical_ttps: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class AttractionFactor:
    """A single factor contributing to attacker attraction."""

    factor: str
    score: int  # 0 -- 100
    description: str


@dataclass(frozen=True)
class AttractionAssessment:
    """Assessment of what makes the organization attractive to attackers."""

    overall_score: int  # 0 -- 100
    factors: tuple[AttractionFactor, ...]


@dataclass(frozen=True)
class RankedTarget:
    """An entity ranked by combined risk attractiveness."""

    entity_identifier: str
    risk_score: float  # 0.0 -- 100.0
    justification: str
    recommended_action: str


@dataclass(frozen=True)
class KeyFinding:
    """A single key finding for the executive summary."""

    title: str
    severity: str  # critical, high, medium, low, info
    description: str


@dataclass(frozen=True)
class Recommendation:
    """A prioritized action item for the executive summary."""

    priority: int  # 1 = highest
    title: str
    description: str
    effort: str  # immediate, short-term, long-term


@dataclass(frozen=True)
class OrganizationProfile:
    """High-level organization profile for the executive summary."""

    sector: str
    estimated_surface_size: str  # small, medium, large, very_large
    attack_surface_summary: str


@dataclass(frozen=True)
class ThreatLandscape:
    """Threat landscape section of the executive summary."""

    top_threats: tuple[str, ...]
    actor_profiles: tuple[ThreatActorProfile, ...]


@dataclass(frozen=True)
class ReportMetrics:
    """Quantitative metrics for the executive summary."""

    total_entities: int
    entities_by_tier: dict[str, int]
    coverage_stats: dict[str, Any]


@dataclass(frozen=True)
class ExecutiveSummary:
    """Aggregated executive summary with all analysis sections."""

    organization_profile: OrganizationProfile
    threat_landscape: ThreatLandscape
    key_findings: tuple[KeyFinding, ...]
    recommendations: tuple[Recommendation, ...]
    metrics: ReportMetrics


@dataclass(frozen=True)
class CisoReport:
    """Full CISO report containing all analysis sections."""

    generated_at: datetime
    report_version: str
    sector_analysis: SectorAnalysis
    threat_actors: tuple[ThreatActorProfile, ...]
    attraction_assessment: AttractionAssessment
    ranked_targets: tuple[RankedTarget, ...]
    executive_summary: ExecutiveSummary


# ============================================================================
# Static knowledge bases
# ============================================================================

# Sector inference patterns: keyword/pattern -> sector mapping
_SECTOR_INDICATORS: dict[str, list[str]] = {
    "technology": [
        "aws.", "azure.", "gcp.", ".cloud", "api.", "dev.", "staging.",
        "github.", "gitlab.", "bitbucket.", "docker.", "kubernetes.",
        ".io", "cdn.", "saas.", "paas.", "iaas.", ".app",
        "jenkins.", "ci.", "cd.", "deploy.",
    ],
    "financial": [
        "bank.", "banking.", "pay.", "payment.", "trading.", "fintech.",
        "swift.", "ach.", "wire.", ".bank", "treasury.", "invest.",
        "compliance.", "kyc.", "aml.", "pci.", "card.",
        "merchant.", "checkout.", "billing.",
    ],
    "healthcare": [
        "hipaa.", "health.", "medical.", "ehr.", "emr.", "patient.",
        "clinical.", "pharma.", "rx.", "dicom.", "hl7.", "fhir.",
        "telehealth.", "telemedicine.", ".health", "epic.", "cerner.",
    ],
    "government": [
        ".gov", ".mil", "fedramp.", "fisma.", "nist.", "dod.",
        "federal.", "agency.", "state.", "county.", "municipal.",
        "govcloud.", "stateramp.", "itar.",
    ],
}

# Threat actor knowledge base per sector
_THREAT_ACTORS: dict[str, list[dict[str, Any]]] = {
    "technology": [
        {
            "name": "APT41 (Double Dragon)",
            "motivation": "espionage",
            "relevance_score": 0.85,
            "typical_ttps": (
                "T1190 - Exploit Public-Facing Application",
                "T1059 - Command and Scripting Interpreter",
                "T1078 - Valid Accounts",
                "T1098 - Account Manipulation",
            ),
            "description": (
                "Chinese state-sponsored group known for targeting technology "
                "companies for intellectual property theft, supply chain "
                "compromise, and financially motivated operations."
            ),
        },
        {
            "name": "Lazarus Group (HIDDEN COBRA)",
            "motivation": "financial",
            "relevance_score": 0.75,
            "typical_ttps": (
                "T1566 - Phishing",
                "T1195 - Supply Chain Compromise",
                "T1486 - Data Encrypted for Impact",
                "T1071 - Application Layer Protocol",
            ),
            "description": (
                "North Korean state-sponsored group targeting technology and "
                "cryptocurrency companies for financial gain. Known for "
                "sophisticated supply chain attacks."
            ),
        },
        {
            "name": "FIN7 (Carbanak)",
            "motivation": "financial",
            "relevance_score": 0.65,
            "typical_ttps": (
                "T1566.001 - Spearphishing Attachment",
                "T1059.001 - PowerShell",
                "T1053 - Scheduled Task/Job",
                "T1005 - Data from Local System",
            ),
            "description": (
                "Financially motivated group targeting technology companies "
                "for credential theft and data exfiltration. Evolved from "
                "point-of-sale attacks to broader enterprise targeting."
            ),
        },
    ],
    "financial": [
        {
            "name": "APT38 (Lazarus Financial)",
            "motivation": "financial",
            "relevance_score": 0.90,
            "typical_ttps": (
                "T1190 - Exploit Public-Facing Application",
                "T1133 - External Remote Services",
                "T1505 - Server Software Component",
                "T1048 - Exfiltration Over Alternative Protocol",
            ),
            "description": (
                "North Korean state-sponsored unit specializing in financial "
                "institution attacks. Known for SWIFT system compromise, ATM "
                "cash-out schemes, and cryptocurrency theft."
            ),
        },
        {
            "name": "Carbanak / FIN7",
            "motivation": "financial",
            "relevance_score": 0.85,
            "typical_ttps": (
                "T1566.001 - Spearphishing Attachment",
                "T1059.001 - PowerShell",
                "T1021 - Remote Services",
                "T1005 - Data from Local System",
            ),
            "description": (
                "Financially motivated group responsible for over $1B in "
                "losses from financial institutions. Uses sophisticated "
                "social engineering and custom backdoors."
            ),
        },
        {
            "name": "Silence Group",
            "motivation": "financial",
            "relevance_score": 0.70,
            "typical_ttps": (
                "T1566 - Phishing",
                "T1059 - Command and Scripting Interpreter",
                "T1113 - Screen Capture",
                "T1125 - Video Capture",
            ),
            "description": (
                "Russian-speaking group targeting financial institutions with "
                "focus on ATM control systems and interbank transfer networks. "
                "Known for patient reconnaissance via screen recording."
            ),
        },
    ],
    "healthcare": [
        {
            "name": "APT18 (Wekby)",
            "motivation": "espionage",
            "relevance_score": 0.75,
            "typical_ttps": (
                "T1190 - Exploit Public-Facing Application",
                "T1059 - Command and Scripting Interpreter",
                "T1078 - Valid Accounts",
                "T1005 - Data from Local System",
            ),
            "description": (
                "Chinese-linked group targeting healthcare and pharmaceutical "
                "organizations for research data and patient information. "
                "Focuses on exploiting public-facing web applications."
            ),
        },
        {
            "name": "FIN12",
            "motivation": "financial",
            "relevance_score": 0.80,
            "typical_ttps": (
                "T1078 - Valid Accounts",
                "T1486 - Data Encrypted for Impact",
                "T1021 - Remote Services",
                "T1219 - Remote Access Software",
            ),
            "description": (
                "Ransomware-focused group disproportionately targeting "
                "healthcare organizations. Known for rapid deployment (under "
                "2 days dwell time) and high-impact encryption."
            ),
        },
        {
            "name": "Orangeworm",
            "motivation": "espionage",
            "relevance_score": 0.65,
            "typical_ttps": (
                "T1133 - External Remote Services",
                "T1570 - Lateral Tool Transfer",
                "T1005 - Data from Local System",
                "T1041 - Exfiltration Over C2 Channel",
            ),
            "description": (
                "Group targeting healthcare and related sectors with custom "
                "Kwampirs backdoor. Focuses on medical device manufacturers, "
                "pharmaceuticals, and healthcare IT providers."
            ),
        },
    ],
    "government": [
        {
            "name": "APT29 (Cozy Bear)",
            "motivation": "espionage",
            "relevance_score": 0.90,
            "typical_ttps": (
                "T1195 - Supply Chain Compromise",
                "T1078 - Valid Accounts",
                "T1550 - Use Alternate Authentication Material",
                "T1114 - Email Collection",
            ),
            "description": (
                "Russian SVR-linked group targeting government agencies and "
                "critical infrastructure. Responsible for SolarWinds supply "
                "chain compromise. Known for stealth and long-term access."
            ),
        },
        {
            "name": "APT28 (Fancy Bear)",
            "motivation": "espionage",
            "relevance_score": 0.85,
            "typical_ttps": (
                "T1566 - Phishing",
                "T1190 - Exploit Public-Facing Application",
                "T1003 - OS Credential Dumping",
                "T1048 - Exfiltration Over Alternative Protocol",
            ),
            "description": (
                "Russian GRU Unit 26165 targeting government and defense "
                "organizations globally. Known for zero-day exploitation "
                "and targeted spearphishing campaigns."
            ),
        },
        {
            "name": "APT1 (Comment Crew)",
            "motivation": "espionage",
            "relevance_score": 0.70,
            "typical_ttps": (
                "T1566.001 - Spearphishing Attachment",
                "T1059 - Command and Scripting Interpreter",
                "T1005 - Data from Local System",
                "T1041 - Exfiltration Over C2 Channel",
            ),
            "description": (
                "Chinese PLA Unit 61398 targeting government contractors and "
                "agencies for defense and technology intelligence. One of the "
                "most prolific cyber espionage groups."
            ),
        },
    ],
    "general": [
        {
            "name": "LockBit Ransomware",
            "motivation": "financial",
            "relevance_score": 0.60,
            "typical_ttps": (
                "T1190 - Exploit Public-Facing Application",
                "T1486 - Data Encrypted for Impact",
                "T1021 - Remote Services",
                "T1078 - Valid Accounts",
            ),
            "description": (
                "Prolific ransomware-as-a-service operation targeting "
                "organizations across all sectors. Known for automated "
                "lateral movement and fast encryption."
            ),
        },
        {
            "name": "Scattered Spider",
            "motivation": "financial",
            "relevance_score": 0.55,
            "typical_ttps": (
                "T1566 - Phishing",
                "T1078 - Valid Accounts",
                "T1539 - Steal Web Session Cookie",
                "T1621 - Multi-Factor Authentication Request Generation",
            ),
            "description": (
                "English-speaking threat group targeting organizations via "
                "social engineering, SIM swapping, and MFA fatigue attacks. "
                "Known for targeting IT help desks."
            ),
        },
    ],
}

# Management interface indicators (ports and service names)
_MANAGEMENT_PORTS: frozenset[int] = frozenset({
    22, 23, 3389, 5900, 5901, 8080, 8443, 9090, 9200, 9443,
    161, 162, 10000, 2222, 4443, 8888,
})

# Database ports
_DATABASE_PORTS: frozenset[int] = frozenset({
    3306, 5432, 1433, 1521, 27017, 6379, 9042, 5984, 8529,
})


# ============================================================================
# Generator
# ============================================================================


class CisoReportGenerator:
    """Generate executive-level CISO reports from entity scan data.

    This is a pure analytical class: no LLM calls, no external I/O, no
    database dependency.  All methods accept plain dicts and return frozen
    dataclasses.

    Typical usage::

        gen = CisoReportGenerator()
        report = gen.generate_report(entities)

    Where ``entities`` is a list of dicts with keys:
        - ``canonical_identifier`` (str): domain, IP, etc.
        - ``entity_type`` (str): domain, ip_address, certificate, etc.
        - ``properties`` (dict): arbitrary properties including lead scores
        - ``attribution_status`` (str): confirmed, high, medium, etc.
        - ``attribution_confidence`` (float): 0.0 -- 1.0
        - ``observations`` (list[dict], optional): raw observation data
        - ``relationships`` (list[dict], optional): entity relationships
        - ``lead_score`` (int|float, optional): 0 -- 100
        - ``llm_enrichment`` (dict, optional): LLM analysis data
    """

    REPORT_VERSION = "1.0.0"

    def analyze_sector(self, entities: list[dict[str, Any]]) -> SectorAnalysis:
        """Infer the target organization's sector from discovered assets.

        Examines entity identifiers and properties for sector-specific
        patterns (cloud providers, payment gateways, .gov domains, etc.)
        and returns the best-match sector with confidence and indicators.
        """
        sector_scores: dict[str, list[str]] = {
            sector: [] for sector in _SECTOR_INDICATORS
        }

        for entity in entities:
            identifier = entity.get("canonical_identifier", "").lower()
            props = entity.get("properties", {})

            for sector, patterns in _SECTOR_INDICATORS.items():
                for pattern in patterns:
                    if pattern in identifier:
                        sector_scores[sector].append(
                            f"{identifier} matches '{pattern}'"
                        )
                        break  # one match per entity per sector

            # Also check properties for sector hints
            for key in ("sector", "industry", "vertical"):
                prop_val = str(props.get(key, "")).lower()
                if prop_val:
                    for sector in _SECTOR_INDICATORS:
                        if sector in prop_val:
                            sector_scores[sector].append(
                                f"property '{key}' contains '{sector}'"
                            )

        # Find sector with most indicators
        best_sector = "general"
        best_count = 0
        for sector, indicators in sector_scores.items():
            if len(indicators) > best_count:
                best_sector = sector
                best_count = len(indicators)

        # Confidence: 0 indicators -> 0.1 (unknown), 1 -> 0.4, 3+ -> 0.8+
        total_entities = max(len(entities), 1)
        if best_count == 0:
            confidence = 0.1
        else:
            ratio = best_count / total_entities
            confidence = min(0.95, 0.3 + ratio * 0.7)

        indicators = tuple(sector_scores.get(best_sector, []))

        return SectorAnalysis(
            sector=best_sector,
            confidence=round(confidence, 2),
            indicators=indicators,
        )

    def profile_threat_actors(
        self,
        sector_analysis: SectorAnalysis,
        entities: list[dict[str, Any]],
    ) -> list[ThreatActorProfile]:
        """Identify likely threat actor groups based on sector and surface.

        Uses a static knowledge base of APT groups mapped to sectors.
        Adjusts relevance scores based on exposed surface characteristics.
        Always includes general/cross-sector actors.
        """
        sector = sector_analysis.sector
        actors_data = list(_THREAT_ACTORS.get(sector, []))

        # Always include general actors
        if sector != "general":
            actors_data.extend(_THREAT_ACTORS.get("general", []))

        # Adjust relevance based on surface characteristics
        has_management = self._has_management_interfaces(entities)
        has_databases = self._has_database_ports(entities)
        entity_count = len(entities)

        profiles: list[ThreatActorProfile] = []
        for actor_data in actors_data:
            relevance = actor_data["relevance_score"]

            # Boost relevance for exposed management interfaces
            if has_management:
                relevance = min(1.0, relevance + 0.05)

            # Boost relevance for exposed databases
            if has_databases:
                relevance = min(1.0, relevance + 0.05)

            # Large surface area attracts more attention
            if entity_count > 50:  # noqa: PLR2004
                relevance = min(1.0, relevance + 0.05)

            # Apply sector confidence as a scaling factor
            relevance *= sector_analysis.confidence

            profiles.append(ThreatActorProfile(
                name=actor_data["name"],
                motivation=actor_data["motivation"],
                relevance_score=round(relevance, 2),
                typical_ttps=tuple(actor_data["typical_ttps"]),
                description=actor_data["description"],
            ))

        # Sort by relevance descending
        profiles.sort(key=lambda p: p.relevance_score, reverse=True)
        return profiles

    def assess_attraction(
        self,
        entities: list[dict[str, Any]],
    ) -> AttractionAssessment:
        """Score what makes the organization attractive to attackers.

        Evaluates five categories of attacker interest:
        1. External surface area size
        2. Exposed management interfaces
        3. Weak TLS / missing security headers
        4. Database ports exposed
        5. Post-acquisition / integration gap indicators
        """
        factors: list[AttractionFactor] = []

        # 1. Surface area
        surface_score = self._score_surface_area(entities)
        factors.append(AttractionFactor(
            factor="external_surface_area",
            score=surface_score,
            description=self._describe_surface_area(len(entities)),
        ))

        # 2. Management interfaces
        mgmt_score = self._score_management_exposure(entities)
        factors.append(AttractionFactor(
            factor="management_interface_exposure",
            score=mgmt_score,
            description=(
                "Exposed management interfaces provide direct operational "
                "access for attackers."
            ),
        ))

        # 3. Weak TLS / missing headers
        tls_score = self._score_tls_weakness(entities)
        factors.append(AttractionFactor(
            factor="weak_security_posture",
            score=tls_score,
            description=(
                "Weak TLS configurations and missing security headers "
                "signal low security investment to attackers."
            ),
        ))

        # 4. Database exposure
        db_score = self._score_database_exposure(entities)
        factors.append(AttractionFactor(
            factor="database_exposure",
            score=db_score,
            description=(
                "Exposed database ports present direct data exfiltration "
                "opportunities."
            ),
        ))

        # 5. Integration gaps (post-acquisition assets)
        integration_score = self._score_integration_gaps(entities)
        factors.append(AttractionFactor(
            factor="integration_gaps",
            score=integration_score,
            description=(
                "Post-acquisition assets or inconsistent security policies "
                "across the surface indicate integration gaps exploitable "
                "by attackers."
            ),
        ))

        # Overall score: weighted average
        weights = [0.20, 0.25, 0.20, 0.25, 0.10]
        overall = sum(
            f.score * w for f, w in zip(factors, weights, strict=True)
        )
        overall = max(0, min(100, round(overall)))

        return AttractionAssessment(
            overall_score=overall,
            factors=tuple(factors),
        )

    def rank_likely_targets(
        self,
        entities: list[dict[str, Any]],
    ) -> list[RankedTarget]:
        """Rank entities by combined attractiveness: lead_score * exposure.

        Returns the top 10 entities with justification and recommended
        actions for each.
        """
        scored: list[tuple[float, dict[str, Any]]] = []

        for entity in entities:
            lead_score = self._get_lead_score(entity)
            exposure = self._calculate_exposure_factor(entity)
            risk_score = min(100.0, lead_score * exposure)
            scored.append((risk_score, entity))

        # Sort by risk descending, take top 10
        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[:10]

        targets: list[RankedTarget] = []
        for risk_score, entity in top:
            identifier = entity.get("canonical_identifier", "unknown")
            justification = self._build_target_justification(entity, risk_score)
            action = self._recommend_action(entity, risk_score)

            targets.append(RankedTarget(
                entity_identifier=identifier,
                risk_score=round(risk_score, 1),
                justification=justification,
                recommended_action=action,
            ))

        return targets

    def generate_executive_summary(
        self,
        entities: list[dict[str, Any]],
        sector_analysis: SectorAnalysis,
        threat_actors: list[ThreatActorProfile],
        attraction: AttractionAssessment,
        ranked_targets: list[RankedTarget],
    ) -> ExecutiveSummary:
        """Aggregate all analyses into a structured executive summary."""
        # Organization profile
        surface_size = self._estimate_surface_size(len(entities))
        org_profile = OrganizationProfile(
            sector=sector_analysis.sector,
            estimated_surface_size=surface_size,
            attack_surface_summary=(
                f"{len(entities)} entities discovered across the external "
                f"attack surface. Sector identified as {sector_analysis.sector} "
                f"with {sector_analysis.confidence:.0%} confidence."
            ),
        )

        # Threat landscape
        top_threats = tuple(
            f"{a.name} ({a.motivation})" for a in threat_actors[:3]
        )
        threat_landscape = ThreatLandscape(
            top_threats=top_threats,
            actor_profiles=tuple(threat_actors[:5]),
        )

        # Key findings
        key_findings = self._extract_key_findings(
            entities, attraction, ranked_targets,
        )

        # Recommendations
        recommendations = self._generate_recommendations(
            entities, attraction, ranked_targets,
        )

        # Metrics
        metrics = self._compute_metrics(entities)

        return ExecutiveSummary(
            organization_profile=org_profile,
            threat_landscape=threat_landscape,
            key_findings=tuple(key_findings),
            recommendations=tuple(recommendations),
            metrics=metrics,
        )

    def generate_report(
        self,
        entities: list[dict[str, Any]],
    ) -> CisoReport:
        """Orchestrate all analyses into a complete CISO report.

        This is the primary entry point.  Call with a list of entity dicts
        (as described in the class docstring) and receive a fully populated
        ``CisoReport``.
        """
        sector = self.analyze_sector(entities)
        actors = self.profile_threat_actors(sector, entities)
        attraction = self.assess_attraction(entities)
        targets = self.rank_likely_targets(entities)
        summary = self.generate_executive_summary(
            entities, sector, actors, attraction, targets,
        )

        return CisoReport(
            generated_at=datetime.now(tz=UTC),
            report_version=self.REPORT_VERSION,
            sector_analysis=sector,
            threat_actors=tuple(actors),
            attraction_assessment=attraction,
            ranked_targets=tuple(targets),
            executive_summary=summary,
        )

    # ========================================================================
    # Private helpers
    # ========================================================================

    def _has_management_interfaces(
        self, entities: list[dict[str, Any]],
    ) -> bool:
        """Check if any entity has exposed management ports."""
        for entity in entities:
            ports = self._extract_ports(entity)
            if ports & _MANAGEMENT_PORTS:
                return True
        return False

    def _has_database_ports(
        self, entities: list[dict[str, Any]],
    ) -> bool:
        """Check if any entity has exposed database ports."""
        for entity in entities:
            ports = self._extract_ports(entity)
            if ports & _DATABASE_PORTS:
                return True
        return False

    def _extract_ports(self, entity: dict[str, Any]) -> set[int]:
        """Extract open port numbers from entity properties."""
        ports: set[int] = set()
        props = entity.get("properties", {})

        # Check open_ports property (list of dicts or ints)
        for port_entry in props.get("open_ports", []):
            if isinstance(port_entry, dict):
                port_num = port_entry.get("port")
                if isinstance(port_num, int):
                    ports.add(port_num)
            elif isinstance(port_entry, int):
                ports.add(port_entry)

        # Check exposure.open_ports (canonical artifact format)
        exposure = props.get("exposure", {})
        if isinstance(exposure, dict):
            for port_entry in exposure.get("open_ports", []):
                if isinstance(port_entry, dict):
                    port_num = port_entry.get("port")
                    if isinstance(port_num, int):
                        ports.add(port_num)

        return ports

    def _score_surface_area(self, entities: list[dict[str, Any]]) -> int:
        """Score based on total external surface area size."""
        count = len(entities)
        if count <= 5:  # noqa: PLR2004
            return 10
        if count <= 20:  # noqa: PLR2004
            return 30
        if count <= 50:  # noqa: PLR2004
            return 50
        if count <= 100:  # noqa: PLR2004
            return 70
        return 90

    def _describe_surface_area(self, count: int) -> str:
        """Human-readable description of surface area."""
        if count <= 5:  # noqa: PLR2004
            return (
                f"Small external surface ({count} entities). "
                "Limited attack surface reduces opportunistic targeting."
            )
        if count <= 20:  # noqa: PLR2004
            return (
                f"Moderate external surface ({count} entities). "
                "Typical for small-to-medium organizations."
            )
        if count <= 50:  # noqa: PLR2004
            return (
                f"Significant external surface ({count} entities). "
                "Large enough to attract automated scanning and targeted recon."
            )
        return (
            f"Large external surface ({count} entities). "
            "High visibility increases automated and targeted attack likelihood."
        )

    def _score_management_exposure(
        self, entities: list[dict[str, Any]],
    ) -> int:
        """Score based on exposed management interfaces."""
        mgmt_count = 0
        for entity in entities:
            ports = self._extract_ports(entity)
            mgmt_count += len(ports & _MANAGEMENT_PORTS)

        if mgmt_count == 0:
            return 0
        if mgmt_count <= 2:  # noqa: PLR2004
            return 40
        if mgmt_count <= 5:  # noqa: PLR2004
            return 70
        return 95

    def _score_tls_weakness(self, entities: list[dict[str, Any]]) -> int:
        """Score based on TLS weaknesses and missing security headers."""
        weak_count = 0

        for entity in entities:
            props = entity.get("properties", {})

            # Check for weak TLS indicators
            tls_version = str(props.get("tls_version", "")).lower()
            if tls_version in ("tls1.0", "tls 1.0", "tlsv1", "ssl3", "sslv3"):
                weak_count += 2
            elif tls_version in ("tls1.1", "tls 1.1", "tlsv1.1"):
                weak_count += 1

            # Check for missing security headers
            headers = props.get("security_headers", {})
            if isinstance(headers, dict):
                if not headers.get("strict_transport_security"):
                    weak_count += 1
                if not headers.get("content_security_policy"):
                    weak_count += 1

            # Check for self-signed or expired certs
            if props.get("is_self_signed"):
                weak_count += 2
            if props.get("is_expired"):
                weak_count += 2

        total = max(len(entities), 1)
        ratio = weak_count / (total * 2)  # normalize
        return max(0, min(100, round(ratio * 100)))

    def _score_database_exposure(
        self, entities: list[dict[str, Any]],
    ) -> int:
        """Score based on exposed database ports."""
        db_count = 0
        for entity in entities:
            ports = self._extract_ports(entity)
            db_count += len(ports & _DATABASE_PORTS)

        if db_count == 0:
            return 0
        if db_count == 1:
            return 60
        if db_count <= 3:  # noqa: PLR2004
            return 85
        return 100

    def _score_integration_gaps(
        self, entities: list[dict[str, Any]],
    ) -> int:
        """Score based on post-acquisition or inconsistent security signals."""
        gap_count = 0

        # Look for multiple distinct registrants, inconsistent TLS configs,
        # or properties indicating M&A activity.
        registrants: set[str] = set()
        tls_configs: set[str] = set()

        for entity in entities:
            props = entity.get("properties", {})

            registrant = str(props.get("registrant", "")).strip()
            if registrant:
                registrants.add(registrant.lower())

            tls_ver = str(props.get("tls_version", "")).strip()
            if tls_ver:
                tls_configs.add(tls_ver.lower())

            # Check for M&A-related properties
            if props.get("_ma_discovery") or props.get("acquisition"):
                gap_count += 2

        # Multiple registrants suggest acquisitions
        if len(registrants) > 2:  # noqa: PLR2004
            gap_count += len(registrants) - 1

        # Inconsistent TLS across the surface
        if len(tls_configs) > 2:  # noqa: PLR2004
            gap_count += 1

        if gap_count == 0:
            return 0
        if gap_count <= 2:  # noqa: PLR2004
            return 30
        if gap_count <= 5:  # noqa: PLR2004
            return 60
        return 85

    def _get_lead_score(self, entity: dict[str, Any]) -> float:
        """Extract lead score from entity, defaulting to 10."""
        score = entity.get("lead_score")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                pass

        # Check properties._lead_score (pipeline convention)
        props = entity.get("properties", {})
        score = props.get("_lead_score")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                pass

        return 10.0

    def _calculate_exposure_factor(self, entity: dict[str, Any]) -> float:
        """Calculate exposure multiplier (1.0 -- 3.0) for an entity."""
        factor = 1.0
        props = entity.get("properties", {})
        ports = self._extract_ports(entity)

        # Management ports boost
        if ports & _MANAGEMENT_PORTS:
            factor += 0.5

        # Database ports boost
        if ports & _DATABASE_PORTS:
            factor += 0.5

        # Weak TLS
        tls_version = str(props.get("tls_version", "")).lower()
        if tls_version in ("tls1.0", "tls 1.0", "ssl3", "sslv3"):
            factor += 0.3

        # Missing security headers (only penalize when headers were checked)
        headers = props.get("security_headers")
        if isinstance(headers, dict) and headers and not headers.get(
            "strict_transport_security",
        ):
            factor += 0.2

        # Self-signed cert
        if props.get("is_self_signed"):
            factor += 0.3

        # Expired cert
        if props.get("is_expired"):
            factor += 0.2

        return min(3.0, factor)

    def _build_target_justification(
        self,
        entity: dict[str, Any],
        risk_score: float,
    ) -> str:
        """Build a human-readable justification for a target's ranking."""
        identifier = entity.get("canonical_identifier", "unknown")
        parts: list[str] = [f"{identifier}: risk score {risk_score:.1f}."]

        ports = self._extract_ports(entity)
        mgmt = ports & _MANAGEMENT_PORTS
        dbs = ports & _DATABASE_PORTS

        if mgmt:
            parts.append(
                f"Exposed management ports: {', '.join(str(p) for p in sorted(mgmt))}."
            )
        if dbs:
            parts.append(
                f"Exposed database ports: {', '.join(str(p) for p in sorted(dbs))}."
            )

        props = entity.get("properties", {})
        if props.get("is_self_signed"):
            parts.append("Self-signed certificate detected.")
        if props.get("is_expired"):
            parts.append("Expired certificate detected.")

        return " ".join(parts)

    def _recommend_action(
        self,
        entity: dict[str, Any],
        risk_score: float,
    ) -> str:
        """Generate a recommended action based on risk profile."""
        ports = self._extract_ports(entity)
        props = entity.get("properties", {})

        if ports & _DATABASE_PORTS:
            return (
                "CRITICAL: Restrict database port access immediately. "
                "Implement network segmentation and firewall rules."
            )
        if ports & _MANAGEMENT_PORTS:
            return (
                "HIGH: Move management interfaces behind VPN or zero-trust "
                "access. Disable public exposure of SSH/RDP/admin panels."
            )
        if props.get("is_self_signed") or props.get("is_expired"):
            return (
                "MEDIUM: Replace self-signed or expired certificates with "
                "valid CA-issued certificates. Implement certificate monitoring."
            )
        if risk_score > 60:  # noqa: PLR2004
            return (
                "HIGH: Review entity exposure and implement security controls. "
                "Consider penetration testing for high-value assets."
            )
        if risk_score > 30:  # noqa: PLR2004
            return (
                "MEDIUM: Monitor entity for changes. Review security "
                "configuration and harden as needed."
            )
        return "LOW: Maintain current monitoring. No immediate action required."

    def _estimate_surface_size(self, entity_count: int) -> str:
        """Classify surface size from entity count."""
        if entity_count <= 10:  # noqa: PLR2004
            return "small"
        if entity_count <= 50:  # noqa: PLR2004
            return "medium"
        if entity_count <= 200:  # noqa: PLR2004
            return "large"
        return "very_large"

    def _extract_key_findings(
        self,
        entities: list[dict[str, Any]],
        attraction: AttractionAssessment,
        ranked_targets: list[RankedTarget],
    ) -> list[KeyFinding]:
        """Extract the most important findings for the executive summary."""
        findings: list[KeyFinding] = []

        # Finding: overall attraction level
        if attraction.overall_score >= 70:  # noqa: PLR2004
            findings.append(KeyFinding(
                title="High attacker attraction score",
                severity="critical",
                description=(
                    f"The organization's external surface scored "
                    f"{attraction.overall_score}/100 for attacker attraction. "
                    f"This indicates significant exposure warranting immediate "
                    f"remediation."
                ),
            ))
        elif attraction.overall_score >= 40:  # noqa: PLR2004
            findings.append(KeyFinding(
                title="Moderate attacker attraction score",
                severity="high",
                description=(
                    f"The organization's external surface scored "
                    f"{attraction.overall_score}/100 for attacker attraction. "
                    f"Several areas require attention to reduce exposure."
                ),
            ))

        # Finding: critical-risk targets
        critical_targets = [t for t in ranked_targets if t.risk_score >= 70]
        if critical_targets:
            findings.append(KeyFinding(
                title=f"{len(critical_targets)} critical-risk assets identified",
                severity="critical",
                description=(
                    f"{len(critical_targets)} entities scored above 70 on the "
                    f"combined risk scale. Top target: "
                    f"{critical_targets[0].entity_identifier} "
                    f"(score: {critical_targets[0].risk_score:.1f})."
                ),
            ))

        # Finding: exposed management
        for factor in attraction.factors:
            if factor.factor == "management_interface_exposure" and factor.score > 0:
                findings.append(KeyFinding(
                    title="Management interfaces exposed to internet",
                    severity="high" if factor.score >= 70 else "medium",  # noqa: PLR2004
                    description=(
                        "One or more management interfaces (SSH, RDP, admin "
                        "panels) are accessible from the public internet. "
                        "These are high-value targets for initial access."
                    ),
                ))
                break

        # Finding: database exposure
        for factor in attraction.factors:
            if factor.factor == "database_exposure" and factor.score > 0:
                findings.append(KeyFinding(
                    title="Database services exposed to internet",
                    severity="critical",
                    description=(
                        "Database ports are accessible from the public internet. "
                        "This presents a direct data exfiltration risk and "
                        "should be remediated immediately."
                    ),
                ))
                break

        # Finding: surface size
        if len(entities) > 50:  # noqa: PLR2004
            findings.append(KeyFinding(
                title="Large external attack surface",
                severity="medium",
                description=(
                    f"The organization has {len(entities)} externally visible "
                    f"entities. A large surface increases the probability of "
                    f"unmanaged or shadow IT assets."
                ),
            ))

        return findings

    def _generate_recommendations(
        self,
        entities: list[dict[str, Any]],
        attraction: AttractionAssessment,
        ranked_targets: list[RankedTarget],
    ) -> list[Recommendation]:
        """Generate prioritized action items."""
        recs: list[Recommendation] = []
        priority = 1

        # Check for database exposure
        has_db = any(
            f.factor == "database_exposure" and f.score > 0
            for f in attraction.factors
        )
        if has_db:
            recs.append(Recommendation(
                priority=priority,
                title="Restrict database access",
                description=(
                    "Immediately restrict all externally exposed database "
                    "ports. Implement network segmentation to ensure databases "
                    "are only accessible from authorized application servers."
                ),
                effort="immediate",
            ))
            priority += 1

        # Check for management exposure
        has_mgmt = any(
            f.factor == "management_interface_exposure" and f.score > 0
            for f in attraction.factors
        )
        if has_mgmt:
            recs.append(Recommendation(
                priority=priority,
                title="Secure management interfaces",
                description=(
                    "Move all management interfaces (SSH, RDP, admin panels) "
                    "behind VPN or zero-trust network access. Implement MFA "
                    "for all administrative access."
                ),
                effort="immediate",
            ))
            priority += 1

        # Check for TLS weakness
        has_weak_tls = any(
            f.factor == "weak_security_posture" and f.score > 30  # noqa: PLR2004
            for f in attraction.factors
        )
        if has_weak_tls:
            recs.append(Recommendation(
                priority=priority,
                title="Upgrade TLS and security headers",
                description=(
                    "Enforce TLS 1.2+ across all endpoints. Deploy security "
                    "headers (HSTS, CSP, X-Frame-Options) on all web services. "
                    "Replace self-signed and expired certificates."
                ),
                effort="short-term",
            ))
            priority += 1

        # Always recommend continuous monitoring
        recs.append(Recommendation(
            priority=priority,
            title="Implement continuous attack surface monitoring",
            description=(
                "Deploy automated external attack surface monitoring to "
                "detect new exposures, certificate expirations, and "
                "unauthorized services as they appear."
            ),
            effort="short-term",
        ))
        priority += 1

        # Recommend asset inventory if large surface
        if len(entities) > 20:  # noqa: PLR2004
            recs.append(Recommendation(
                priority=priority,
                title="Conduct asset inventory reconciliation",
                description=(
                    f"Reconcile the {len(entities)} discovered external "
                    f"entities against the organization's CMDB. Identify "
                    f"and remediate shadow IT and unmanaged assets."
                ),
                effort="long-term",
            ))

        return recs

    def _compute_metrics(
        self, entities: list[dict[str, Any]],
    ) -> ReportMetrics:
        """Compute quantitative metrics for the executive summary."""
        # Count entities by attribution tier
        tiers: dict[str, int] = {}
        scored_count = 0
        high_risk_count = 0

        for entity in entities:
            tier = entity.get("attribution_status", "unknown")
            tiers[tier] = tiers.get(tier, 0) + 1

            lead_score = self._get_lead_score(entity)
            if lead_score > 0:
                scored_count += 1
            if lead_score >= 70:  # noqa: PLR2004
                high_risk_count += 1

        coverage_stats: dict[str, Any] = {
            "scored_entities": scored_count,
            "high_risk_entities": high_risk_count,
            "scoring_coverage": (
                round(scored_count / max(len(entities), 1), 2)
            ),
        }

        return ReportMetrics(
            total_entities=len(entities),
            entities_by_tier=tiers,
            coverage_stats=coverage_stats,
        )


__all__ = [
    "AttractionAssessment",
    "AttractionFactor",
    "CisoReport",
    "CisoReportGenerator",
    "ExecutiveSummary",
    "KeyFinding",
    "OrganizationProfile",
    "RankedTarget",
    "Recommendation",
    "ReportMetrics",
    "SectorAnalysis",
    "ThreatActorProfile",
    "ThreatLandscape",
]
