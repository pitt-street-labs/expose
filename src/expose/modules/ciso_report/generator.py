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

# Copyright 2026 Korlogos / Pitt Street Labs. All rights reserved.
# This file is part of EXPOSE Commercial Modules and is NOT covered by the
# Apache 2.0 license that governs the core engine. Unauthorized copying,
# distribution, or use of this file is strictly prohibited. Contact
# licensing@korlogos.com for commercial licensing terms.

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
class VendorProfile:
    """Per-vendor CWE distribution and risk summary."""

    vendor: str
    products: tuple[str, ...]
    cwe_distribution: tuple[tuple[str, float], ...]  # (CWE-ID, weight)
    aggregate_risk: float  # 0.0 -- 100.0


@dataclass(frozen=True)
class HighRiskEndpoint:
    """An endpoint whose compound vendor risk exceeds threshold."""

    identifier: str
    compound_risk: float  # 0.0 -- 100.0
    contributing_products: tuple[str, ...]
    top_cwes: tuple[str, ...]


@dataclass(frozen=True)
class EolProduct:
    """A detected end-of-life product still in use."""

    product: str
    vendor: str
    endpoint: str
    eol_reason: str


@dataclass(frozen=True)
class ThreatActorCweAlignment:
    """Maps a threat actor to CWE patterns found in the vendor stack."""

    actor_name: str
    matching_cwes: tuple[str, ...]
    alignment_score: float  # 0.0 -- 1.0


@dataclass(frozen=True)
class VendorDnaAnalysis:
    """Vendor Vulnerability DNA analysis result."""

    vendor_profiles: tuple[VendorProfile, ...]
    high_risk_endpoints: tuple[HighRiskEndpoint, ...]
    eol_products: tuple[EolProduct, ...]
    patch_velocity_assessment: str
    threat_actor_alignment: tuple[ThreatActorCweAlignment, ...]


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
    vendor_dna: VendorDnaAnalysis | None = None


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

# Internal hostname patterns that should never appear in public-facing data
_INTERNAL_HOSTNAME_MARKERS: tuple[str, ...] = (
    ".int.", ".internal.", ".local.", ".corp.", ".priv.", ".lan.",
)

# DNS record names that indicate direct residential IP risk when pointing
# at an IP without CDN/proxy protection
_SENSITIVE_SERVICE_PREFIXES: tuple[str, ...] = (
    "vpn.", "mail.", "smtp.", "imap.", "pop.", "owa.", "autodiscover.",
    "remote.", "rdp.", "ssh.",
)

# ============================================================================
# Vendor DNA knowledge bases
# ============================================================================

# Technology/product fingerprints -> vendor mapping with typical CWEs
_VENDOR_CWE_MAP: dict[str, dict[str, Any]] = {
    "apache": {
        "products": ("Apache HTTP Server", "Apache Tomcat", "Apache Struts"),
        "cwes": (
            ("CWE-79", 0.25),   # XSS
            ("CWE-20", 0.20),   # Input Validation
            ("CWE-22", 0.15),   # Path Traversal
            ("CWE-502", 0.20),  # Deserialization
            ("CWE-94", 0.20),   # Code Injection
        ),
        "base_risk": 45,
    },
    "nginx": {
        "products": ("nginx", "nginx Plus", "OpenResty"),
        "cwes": (
            ("CWE-400", 0.30),  # Resource Exhaustion
            ("CWE-120", 0.25),  # Buffer Overflow
            ("CWE-79", 0.20),   # XSS (misconfiguration)
            ("CWE-918", 0.25),  # SSRF
        ),
        "base_risk": 35,
    },
    "microsoft": {
        "products": ("IIS", "ASP.NET", "Exchange", "SharePoint"),
        "cwes": (
            ("CWE-287", 0.25),  # Authentication Bypass
            ("CWE-502", 0.20),  # Deserialization
            ("CWE-79", 0.15),   # XSS
            ("CWE-94", 0.20),   # Code Injection
            ("CWE-269", 0.20),  # Privilege Escalation
        ),
        "base_risk": 50,
    },
    "php": {
        "products": ("PHP", "PHP-FPM", "WordPress", "Drupal", "Joomla"),
        "cwes": (
            ("CWE-89", 0.25),   # SQL Injection
            ("CWE-79", 0.20),   # XSS
            ("CWE-98", 0.20),   # File Inclusion
            ("CWE-434", 0.20),  # Unrestricted Upload
            ("CWE-502", 0.15),  # Deserialization
        ),
        "base_risk": 55,
    },
    "java": {
        "products": ("Java", "Spring", "Spring Boot", "JBoss", "WebLogic"),
        "cwes": (
            ("CWE-502", 0.30),  # Deserialization
            ("CWE-611", 0.20),  # XXE
            ("CWE-917", 0.20),  # Expression Language Injection
            ("CWE-94", 0.15),   # Code Injection
            ("CWE-20", 0.15),   # Input Validation
        ),
        "base_risk": 50,
    },
    "openssl": {
        "products": ("OpenSSL",),
        "cwes": (
            ("CWE-120", 0.35),  # Buffer Overflow
            ("CWE-310", 0.30),  # Cryptographic Issues
            ("CWE-400", 0.20),  # Resource Exhaustion
            ("CWE-295", 0.15),  # Certificate Validation
        ),
        "base_risk": 40,
    },
    "node": {
        "products": ("Node.js", "Express", "Next.js"),
        "cwes": (
            ("CWE-1321", 0.25),  # Prototype Pollution
            ("CWE-400", 0.20),   # Resource Exhaustion
            ("CWE-79", 0.20),    # XSS
            ("CWE-918", 0.15),   # SSRF
            ("CWE-94", 0.20),    # Code Injection
        ),
        "base_risk": 40,
    },
    "python": {
        "products": ("Python", "Django", "Flask", "FastAPI"),
        "cwes": (
            ("CWE-94", 0.25),   # Code Injection
            ("CWE-502", 0.20),  # Deserialization
            ("CWE-79", 0.20),   # XSS
            ("CWE-918", 0.20),  # SSRF
            ("CWE-20", 0.15),   # Input Validation
        ),
        "base_risk": 35,
    },
}

# Patterns to detect products/vendors from entity properties
_TECH_FINGERPRINTS: dict[str, list[str]] = {
    "apache": [
        "apache", "httpd", "tomcat", "struts",
    ],
    "nginx": [
        "nginx", "openresty",
    ],
    "microsoft": [
        "iis", "asp.net", "microsoft", "exchange", "sharepoint",
    ],
    "php": [
        "php", "wordpress", "drupal", "joomla", "wp-",
    ],
    "java": [
        "java", "spring", "jboss", "weblogic", "wildfly", "tomee",
    ],
    "openssl": [
        "openssl",
    ],
    "node": [
        "node", "express", "next.js", "koa", "npm",
    ],
    "python": [
        "python", "django", "flask", "fastapi", "gunicorn", "uvicorn",
    ],
}

# EOL product signatures: (pattern, vendor, product_name, reason)
_EOL_SIGNATURES: list[tuple[str, str, str, str]] = [
    ("apache/2.2", "apache", "Apache HTTP Server 2.2", "EOL since 2018-01"),
    ("apache/2.0", "apache", "Apache HTTP Server 2.0", "EOL since 2013-07"),
    ("php/5", "php", "PHP 5.x", "EOL since 2018-12"),
    ("php/7.0", "php", "PHP 7.0", "EOL since 2019-01"),
    ("php/7.1", "php", "PHP 7.1", "EOL since 2019-12"),
    ("php/7.2", "php", "PHP 7.2", "EOL since 2020-11"),
    ("php/7.3", "php", "PHP 7.3", "EOL since 2021-12"),
    ("php/7.4", "php", "PHP 7.4", "EOL since 2022-11"),
    ("php/8.0", "php", "PHP 8.0", "EOL since 2023-11"),
    ("iis/6", "microsoft", "IIS 6.0", "EOL (Windows Server 2003)"),
    ("iis/7", "microsoft", "IIS 7.0", "EOL (Windows Server 2008)"),
    ("iis/7.5", "microsoft", "IIS 7.5", "EOL (Windows Server 2008 R2)"),
    ("openssl/0.", "openssl", "OpenSSL 0.x", "EOL since 2015-12"),
    ("openssl/1.0", "openssl", "OpenSSL 1.0.x", "EOL since 2020-01"),
    ("openssl/1.1.0", "openssl", "OpenSSL 1.1.0", "EOL since 2019-09"),
    ("nginx/1.0.", "nginx", "nginx 1.0.x", "Legacy branch — no patches"),
    ("nginx/1.2.", "nginx", "nginx 1.2.x", "Legacy branch — no patches"),
    ("tomcat/6", "apache", "Apache Tomcat 6.x", "EOL since 2016-12"),
    ("tomcat/7", "apache", "Apache Tomcat 7.x", "EOL since 2023-03"),
    ("node/8", "node", "Node.js 8.x", "EOL since 2019-12"),
    ("node/10", "node", "Node.js 10.x", "EOL since 2021-04"),
    ("node/12", "node", "Node.js 12.x", "EOL since 2022-04"),
    ("node/14", "node", "Node.js 14.x", "EOL since 2023-04"),
    ("node/16", "node", "Node.js 16.x", "EOL since 2023-09"),
    ("python/2.", "python", "Python 2.x", "EOL since 2020-01"),
    ("python/3.6", "python", "Python 3.6", "EOL since 2021-12"),
    ("python/3.7", "python", "Python 3.7", "EOL since 2023-06"),
]

# Threat actor -> CWE affinities (which CWEs each actor group tends to
# exploit, for alignment scoring)
_ACTOR_CWE_PREFERENCES: dict[str, list[str]] = {
    "APT41 (Double Dragon)": [
        "CWE-94", "CWE-502", "CWE-287", "CWE-78", "CWE-20",
    ],
    "Lazarus Group (HIDDEN COBRA)": [
        "CWE-502", "CWE-94", "CWE-79", "CWE-20", "CWE-434",
    ],
    "FIN7 (Carbanak)": [
        "CWE-94", "CWE-89", "CWE-79", "CWE-502", "CWE-269",
    ],
    "APT38 (Lazarus Financial)": [
        "CWE-287", "CWE-502", "CWE-94", "CWE-78", "CWE-269",
    ],
    "Carbanak / FIN7": [
        "CWE-94", "CWE-89", "CWE-79", "CWE-502", "CWE-269",
    ],
    "Silence Group": [
        "CWE-94", "CWE-79", "CWE-89", "CWE-434", "CWE-78",
    ],
    "APT18 (Wekby)": [
        "CWE-94", "CWE-20", "CWE-287", "CWE-79", "CWE-22",
    ],
    "FIN12": [
        "CWE-287", "CWE-269", "CWE-502", "CWE-78", "CWE-94",
    ],
    "Orangeworm": [
        "CWE-94", "CWE-20", "CWE-502", "CWE-22", "CWE-78",
    ],
    "APT29 (Cozy Bear)": [
        "CWE-287", "CWE-502", "CWE-94", "CWE-269", "CWE-295",
    ],
    "APT28 (Fancy Bear)": [
        "CWE-94", "CWE-79", "CWE-20", "CWE-287", "CWE-78",
    ],
    "APT1 (Comment Crew)": [
        "CWE-94", "CWE-79", "CWE-20", "CWE-502", "CWE-78",
    ],
    "LockBit Ransomware": [
        "CWE-287", "CWE-269", "CWE-502", "CWE-78", "CWE-94",
    ],
    "Scattered Spider": [
        "CWE-287", "CWE-79", "CWE-269", "CWE-94", "CWE-308",
    ],
}


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

    def analyze_vendor_dna(
        self,
        entities: list[dict[str, Any]],
        threat_actors: list[ThreatActorProfile] | None = None,
    ) -> VendorDnaAnalysis:
        """Analyze vendor vulnerability DNA from technology stack properties.

        For each entity with technology indicators (``technologies``,
        ``server_header``, or ``server`` properties), builds a vendor
        profile with CWE distribution, computes compound risk per
        endpoint, detects EOL products, assesses patch velocity, and
        maps threat actors to predicted CWE weaknesses.

        If the ``expose.pipeline.vendor_vulnerability`` module is
        available, its enrichment data is incorporated.  Otherwise the
        analysis uses the built-in static knowledge base only.
        """
        # Attempt conditional import of pipeline module (may not exist yet)
        _pipeline_enrich = None
        try:
            from expose.pipeline.vendor_vulnerability import (  # noqa: PLC0415
                enrich_vendor_data,
            )
            _pipeline_enrich = enrich_vendor_data
        except ImportError:
            logger.debug(
                "expose.pipeline.vendor_vulnerability not available; "
                "using built-in knowledge base only"
            )

        # --- Phase 1: Detect vendors per entity ---
        # entity_identifier -> set of detected vendor keys
        entity_vendors: dict[str, set[str]] = {}
        # entity_identifier -> list of raw tech strings (for EOL check)
        entity_tech_strings: dict[str, list[str]] = {}

        for entity in entities:
            identifier = entity.get("canonical_identifier", "unknown")
            props = entity.get("properties", {})

            tech_signals: list[str] = []

            # Collect technology signals from various property fields
            technologies = props.get("technologies")
            if isinstance(technologies, list):
                tech_signals.extend(str(t).lower() for t in technologies)
            elif isinstance(technologies, str):
                tech_signals.append(technologies.lower())

            server_header = props.get("server_header", "")
            if isinstance(server_header, str) and server_header:
                tech_signals.append(server_header.lower())

            server = props.get("server", "")
            if isinstance(server, str) and server:
                tech_signals.append(server.lower())

            powered_by = props.get("x_powered_by", "")
            if isinstance(powered_by, str) and powered_by:
                tech_signals.append(powered_by.lower())

            if not tech_signals:
                continue

            entity_tech_strings[identifier] = tech_signals

            detected: set[str] = set()
            for vendor_key, patterns in _TECH_FINGERPRINTS.items():
                for signal in tech_signals:
                    if any(p in signal for p in patterns):
                        detected.add(vendor_key)
                        break

            if detected:
                entity_vendors[identifier] = detected

        # If pipeline enrichment is available, attempt to augment
        if _pipeline_enrich is not None:
            try:
                enriched = _pipeline_enrich(entities)
                # Merge any additional vendor detections from pipeline
                if isinstance(enriched, dict):
                    for eid, vendors in enriched.items():
                        if isinstance(vendors, set):
                            existing = entity_vendors.get(eid, set())
                            existing |= vendors
                            entity_vendors[eid] = existing
            except Exception:
                logger.debug(
                    "vendor_vulnerability pipeline enrichment failed; "
                    "continuing with built-in detections",
                    exc_info=True,
                )

        # --- Phase 2: Build vendor profiles ---
        # Aggregate across all entities to produce per-vendor summaries
        vendor_entity_count: dict[str, int] = {}
        vendor_all_products: dict[str, set[str]] = {}
        for _eid, vendors in entity_vendors.items():
            for v in vendors:
                vendor_entity_count[v] = vendor_entity_count.get(v, 0) + 1
                info = _VENDOR_CWE_MAP.get(v)
                if info:
                    existing = vendor_all_products.get(v, set())
                    existing |= set(info["products"])
                    vendor_all_products[v] = existing

        vendor_profiles: list[VendorProfile] = []
        for vendor_key in sorted(vendor_entity_count, key=lambda k: -vendor_entity_count[k]):
            info = _VENDOR_CWE_MAP.get(vendor_key)
            if not info:
                continue
            # Scale risk by prevalence (more endpoints = higher aggregate)
            count = vendor_entity_count[vendor_key]
            total = max(len(entities), 1)
            prevalence_factor = min(1.5, 1.0 + (count / total) * 0.5)
            aggregate_risk = min(
                100.0,
                float(info["base_risk"]) * prevalence_factor,
            )

            vendor_profiles.append(VendorProfile(
                vendor=vendor_key,
                products=tuple(sorted(vendor_all_products.get(vendor_key, set()))),
                cwe_distribution=tuple(info["cwes"]),
                aggregate_risk=round(aggregate_risk, 1),
            ))

        # --- Phase 3: Compute compound risk per endpoint ---
        high_risk_endpoints: list[HighRiskEndpoint] = []
        for identifier, vendors in entity_vendors.items():
            # Compound risk: combine base risks from all detected vendors
            compound = 0.0
            products: list[str] = []
            cwe_set: set[str] = set()

            for v in vendors:
                info = _VENDOR_CWE_MAP.get(v)
                if info:
                    compound += float(info["base_risk"])
                    products.extend(info["products"])
                    for cwe_id, _weight in info["cwes"]:
                        cwe_set.add(cwe_id)

            # Cap at 100
            compound = min(100.0, compound)

            if compound > 60:  # noqa: PLR2004
                # Sort CWEs by total weight across vendors for this endpoint
                cwe_weights: dict[str, float] = {}
                for v in vendors:
                    info = _VENDOR_CWE_MAP.get(v)
                    if info:
                        for cwe_id, weight in info["cwes"]:
                            cwe_weights[cwe_id] = (
                                cwe_weights.get(cwe_id, 0.0) + weight
                            )
                top_cwes = sorted(
                    cwe_weights, key=lambda c: -cwe_weights[c],
                )[:5]

                high_risk_endpoints.append(HighRiskEndpoint(
                    identifier=identifier,
                    compound_risk=round(compound, 1),
                    contributing_products=tuple(sorted(set(products))),
                    top_cwes=tuple(top_cwes),
                ))

        # Sort by compound risk descending
        high_risk_endpoints.sort(
            key=lambda e: e.compound_risk, reverse=True,
        )

        # --- Phase 4: Detect EOL products ---
        eol_products: list[EolProduct] = []
        seen_eol: set[tuple[str, str]] = set()  # (endpoint, product)

        for identifier, tech_strings in entity_tech_strings.items():
            for sig_pattern, sig_vendor, sig_product, sig_reason in _EOL_SIGNATURES:
                for ts in tech_strings:
                    if sig_pattern in ts:
                        key = (identifier, sig_product)
                        if key not in seen_eol:
                            seen_eol.add(key)
                            eol_products.append(EolProduct(
                                product=sig_product,
                                vendor=sig_vendor,
                                endpoint=identifier,
                                eol_reason=sig_reason,
                            ))

        # --- Phase 5: Patch velocity assessment ---
        patch_velocity_assessment = self._assess_patch_velocity(
            entity_vendors, entity_tech_strings, eol_products, entities,
        )

        # --- Phase 6: Threat actor alignment ---
        # Collect all CWEs present in the detected vendor stack
        all_stack_cwes: set[str] = set()
        for v_key in set().union(*(entity_vendors.values())) if entity_vendors else set():
            info = _VENDOR_CWE_MAP.get(v_key)
            if info:
                for cwe_id, _w in info["cwes"]:
                    all_stack_cwes.add(cwe_id)

        actor_alignment: list[ThreatActorCweAlignment] = []
        actors_to_check = (
            [a.name for a in threat_actors] if threat_actors
            else list(_ACTOR_CWE_PREFERENCES.keys())
        )

        for actor_name in actors_to_check:
            prefs = _ACTOR_CWE_PREFERENCES.get(actor_name, [])
            if not prefs:
                continue
            matching = [c for c in prefs if c in all_stack_cwes]
            if matching:
                score = len(matching) / len(prefs)
                actor_alignment.append(ThreatActorCweAlignment(
                    actor_name=actor_name,
                    matching_cwes=tuple(matching),
                    alignment_score=round(score, 2),
                ))

        # Sort by alignment score descending
        actor_alignment.sort(
            key=lambda a: a.alignment_score, reverse=True,
        )

        return VendorDnaAnalysis(
            vendor_profiles=tuple(vendor_profiles),
            high_risk_endpoints=tuple(high_risk_endpoints),
            eol_products=tuple(eol_products),
            patch_velocity_assessment=patch_velocity_assessment,
            threat_actor_alignment=tuple(actor_alignment),
        )

    def _assess_patch_velocity(
        self,
        entity_vendors: dict[str, set[str]],
        entity_tech_strings: dict[str, list[str]],
        eol_products: list[EolProduct],
        entities: list[dict[str, Any]],
    ) -> str:
        """Produce a qualitative patch velocity assessment string."""
        if not entity_vendors:
            return (
                "Insufficient technology fingerprint data to assess patch "
                "velocity. No vendor-identifiable technology was detected in "
                "the scanned entities."
            )

        total_endpoints = max(len(entities), 1)
        vendor_endpoints = len(entity_vendors)
        eol_count = len(eol_products)
        unique_vendors = set()
        for vendors in entity_vendors.values():
            unique_vendors |= vendors

        if eol_count > 3:  # noqa: PLR2004
            return (
                f"POOR: {eol_count} end-of-life products detected across "
                f"{vendor_endpoints} of {total_endpoints} endpoints. "
                f"Multiple unpatched components indicate systemic patch "
                f"management failures. Immediate remediation required for "
                f"all EOL products."
            )
        if eol_count > 0:
            return (
                f"BELOW AVERAGE: {eol_count} end-of-life product(s) detected. "
                f"{vendor_endpoints} of {total_endpoints} endpoints expose "
                f"vendor-identifiable technology across {len(unique_vendors)} "
                f"vendor(s). EOL products should be upgraded or replaced as "
                f"part of a regular patch cycle."
            )
        if vendor_endpoints / total_endpoints > 0.5:  # noqa: PLR2004
            return (
                f"MODERATE: No end-of-life products detected. "
                f"{vendor_endpoints} of {total_endpoints} endpoints expose "
                f"vendor-identifiable technology across {len(unique_vendors)} "
                f"vendor(s). Current versions detected but version currency "
                f"should be validated against vendor advisories."
            )
        return (
            f"ADEQUATE: No end-of-life products detected. "
            f"{vendor_endpoints} of {total_endpoints} endpoints expose "
            f"vendor-identifiable technology. Limited vendor exposure "
            f"reduces patch-related risk surface."
        )

    def generate_executive_summary(
        self,
        entities: list[dict[str, Any]],
        sector_analysis: SectorAnalysis,
        threat_actors: list[ThreatActorProfile],
        attraction: AttractionAssessment,
        ranked_targets: list[RankedTarget],
        vendor_dna: VendorDnaAnalysis | None = None,
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

        # Vendor DNA findings (injected into key findings)
        if vendor_dna is not None:
            key_findings.extend(
                self._extract_vendor_dna_findings(vendor_dna),
            )

        # Recommendations
        recommendations = self._generate_recommendations(
            entities, attraction, ranked_targets,
        )

        # Vendor DNA recommendations
        if vendor_dna is not None:
            vendor_recs = self._generate_vendor_dna_recommendations(
                vendor_dna,
                start_priority=len(recommendations) + 1,
            )
            recommendations.extend(vendor_recs)

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
        vendor_dna = self.analyze_vendor_dna(entities, actors)
        summary = self.generate_executive_summary(
            entities, sector, actors, attraction, targets, vendor_dna,
        )

        return CisoReport(
            generated_at=datetime.now(tz=UTC),
            report_version=self.REPORT_VERSION,
            sector_analysis=sector,
            threat_actors=tuple(actors),
            attraction_assessment=attraction,
            ranked_targets=tuple(targets),
            executive_summary=summary,
            vendor_dna=vendor_dna,
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
        props = entity.get("properties", {})
        entity_type = entity.get("entity_type", "")
        identifier = entity.get("canonical_identifier", "unknown")
        parts: list[str] = []

        ports = self._extract_ports(entity)
        mgmt = ports & _MANAGEMENT_PORTS
        dbs = ports & _DATABASE_PORTS

        registrar = (
            props.get("registrar")
            or props.get("registrar_name")
            or props.get("rdap_registrar")
            or ""
        )
        if isinstance(registrar, str):
            registrar = registrar.strip()

        nameservers = props.get("nameservers") or props.get("name_servers") or []
        has_cdn = props.get("cdn_provider") or props.get("is_cdn")
        has_proxy = props.get("is_proxied") or props.get("waf_detected")
        tls_version = str(props.get("tls_version", "")).lower()
        is_internal = any(m in identifier.lower() for m in _INTERNAL_HOSTNAME_MARKERS)

        if entity_type == "domain" and registrar:
            ns_detail = ""
            if nameservers:
                ns_domains = {s.rstrip(".").rsplit(".", 2)[-2] + "." + s.rstrip(".").rsplit(".", 1)[-1]
                              for s in nameservers if isinstance(s, str) and "." in s}
                if len(ns_domains) == 1:
                    ns_detail = f" All nameservers on {next(iter(ns_domains))}."
            parts.append(f"Registered with {registrar}.{ns_detail}")
        elif entity_type == "domain" and is_internal:
            parts.append("Internal hostname pattern exposed in public records.")

        if entity_type == "ip_address":
            if not has_cdn and not has_proxy:
                parts.append("IP directly exposed with no CDN or proxy protection.")
            elif has_cdn:
                cdn_name = props.get("cdn_provider", "CDN")
                parts.append(f"Behind {cdn_name} but directly resolvable.")

        if is_internal and entity_type != "domain":
            parts.append("Internal naming convention leaked in public data.")

        if props.get("_ma_discovery") or props.get("acquisition"):
            parts.append("Discovered via M&A activity — likely inherited asset.")

        if dbs:
            port_names = ", ".join(str(p) for p in sorted(dbs))
            parts.append(f"Database ports exposed ({port_names}).")
        if mgmt:
            port_names = ", ".join(str(p) for p in sorted(mgmt))
            parts.append(f"Management ports exposed ({port_names}).")
        if ports and not dbs and not mgmt:
            parts.append(f"{len(ports)} open port(s) detected.")

        tls_parts: list[str] = []
        if tls_version in ("tls1.0", "tls 1.0", "tlsv1", "ssl3", "sslv3"):
            tls_parts.append(f"deprecated TLS ({tls_version.upper()})")
        if props.get("is_self_signed"):
            tls_parts.append("self-signed certificate")
        if props.get("is_expired"):
            tls_parts.append("expired certificate")
        if tls_parts:
            parts.append(f"TLS issues: {', '.join(tls_parts)}.")

        headers = props.get("security_headers")
        if isinstance(headers, dict) and headers and not headers.get("strict_transport_security"):
            parts.append("Missing HSTS header.")

        if not parts:
            if risk_score >= 70:
                parts.append("High composite risk from lead score and exposure factors.")
            elif risk_score >= 40:
                parts.append("Moderate risk based on external exposure profile.")
            else:
                parts.append("Low individual risk; included for surface completeness.")

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

        # Finding: internal hostname leakage in public data
        leaked_internal: list[str] = []
        for entity in entities:
            identifier = entity.get("canonical_identifier", "").lower()
            for marker in _INTERNAL_HOSTNAME_MARKERS:
                if marker in identifier:
                    leaked_internal.append(
                        entity.get("canonical_identifier", identifier),
                    )
                    break
        if leaked_internal:
            examples = ", ".join(leaked_internal[:5])
            suffix = (
                f" (and {len(leaked_internal) - 5} more)"
                if len(leaked_internal) > 5  # noqa: PLR2004
                else ""
            )
            findings.append(KeyFinding(
                title="Internal hostnames exposed in public data",
                severity="high",
                description=(
                    f"{len(leaked_internal)} internal hostname(s) appeared in "
                    f"publicly visible records (CT logs, DNS, WHOIS): "
                    f"{examples}{suffix}. Internal naming conventions leak "
                    f"network topology and make targeted attacks easier."
                ),
            ))

        # Finding: direct residential IP exposure
        exposed_ips: list[str] = []
        for entity in entities:
            if entity.get("entity_type") != "ip_address":
                continue
            props = entity.get("properties", {})
            relationships = entity.get("relationships", [])
            dns_names: list[str] = []
            for rel in relationships:
                rel_target = str(rel.get("target", "")).lower()
                for prefix in _SENSITIVE_SERVICE_PREFIXES:
                    if rel_target.startswith(prefix):
                        dns_names.append(rel_target)
                        break
            if not dns_names:
                dns_records = props.get("dns_records", [])
                for rec in dns_records:
                    name = str(rec if isinstance(rec, str) else
                               rec.get("name", "")).lower()
                    for prefix in _SENSITIVE_SERVICE_PREFIXES:
                        if name.startswith(prefix):
                            dns_names.append(name)
                            break
            has_cdn = props.get("cdn_provider") or props.get("is_cdn")
            has_proxy = props.get("is_proxied") or props.get("waf_detected")
            if dns_names and not has_cdn and not has_proxy:
                exposed_ips.append(
                    f"{entity.get('canonical_identifier', '?')} "
                    f"({', '.join(dns_names[:3])})",
                )
        if exposed_ips:
            findings.append(KeyFinding(
                title="Sensitive services on unprotected IP address",
                severity="medium",
                description=(
                    f"{len(exposed_ips)} IP address(es) host sensitive services "
                    f"(VPN, mail, remote access) with no CDN or proxy "
                    f"protection: {'; '.join(exposed_ips[:3])}. Direct IP "
                    f"exposure to residential or unshielded addresses enables "
                    f"targeted scanning and DDoS."
                ),
            ))

        # Finding: no HTTPS on primary (apex) domain
        domains = [
            e for e in entities
            if e.get("entity_type") == "domain"
        ]
        if domains:
            apex_candidates = [
                e for e in domains
                if e.get("canonical_identifier", "").count(".") == 1
            ]
            for apex in apex_candidates:
                props = apex.get("properties", {})
                has_tls = bool(
                    props.get("tls_version")
                    or props.get("certificate")
                    or props.get("ssl_cert")
                )
                has_cert_obs = False
                for obs in apex.get("observations", []):
                    obs_type = str(
                        obs.get("observation_type", obs.get("type", "")),
                    ).lower()
                    if "tls" in obs_type or "certificate" in obs_type:
                        has_cert_obs = True
                        break
                cert_entities = [
                    e for e in entities
                    if e.get("entity_type") == "certificate"
                    and apex.get("canonical_identifier", "").lower()
                    in str(e.get("canonical_identifier", "")).lower()
                ]
                if not has_tls and not has_cert_obs and not cert_entities:
                    findings.append(KeyFinding(
                        title=(
                            f"No HTTPS detected on "
                            f"{apex.get('canonical_identifier', 'apex domain')}"
                        ),
                        severity="medium",
                        description=(
                            f"The primary domain "
                            f"{apex.get('canonical_identifier', '')} has no "
                            f"TLS certificate or HTTPS configuration detected. "
                            f"All public-facing domains should enforce HTTPS to "
                            f"protect visitor traffic and prevent downgrade "
                            f"attacks."
                        ),
                    ))

        # Finding: single registrar dependency
        registrars: set[str] = set()
        domain_count = 0
        for entity in entities:
            if entity.get("entity_type") != "domain":
                continue
            props = entity.get("properties", {})
            registrar = (
                props.get("registrar")
                or props.get("registrar_name")
                or props.get("rdap_registrar")
            )
            if registrar:
                registrars.add(str(registrar).strip().lower())
                domain_count += 1
        if len(registrars) == 1 and domain_count >= 2:  # noqa: PLR2004
            registrar_name = next(iter(registrars)).title()
            findings.append(KeyFinding(
                title="Single registrar dependency",
                severity="low",
                description=(
                    f"All {domain_count} domains with registrar data use the "
                    f"same provider ({registrar_name}). A single registrar "
                    f"compromise or account takeover could affect all domains "
                    f"simultaneously. Consider distributing critical domains "
                    f"across multiple registrars."
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

    def _extract_vendor_dna_findings(
        self,
        vendor_dna: VendorDnaAnalysis,
    ) -> list[KeyFinding]:
        """Extract key findings from vendor DNA analysis."""
        findings: list[KeyFinding] = []

        # EOL products
        if len(vendor_dna.eol_products) > 0:
            severity = "critical" if len(vendor_dna.eol_products) > 2 else "high"  # noqa: PLR2004
            product_names = sorted({p.product for p in vendor_dna.eol_products})
            findings.append(KeyFinding(
                title=(
                    f"{len(vendor_dna.eol_products)} end-of-life product(s) "
                    f"detected in technology stack"
                ),
                severity=severity,
                description=(
                    f"The following EOL products were detected: "
                    f"{', '.join(product_names)}. End-of-life software "
                    f"receives no security patches and represents an "
                    f"unmitigated vulnerability surface."
                ),
            ))

        # High-risk endpoints
        if len(vendor_dna.high_risk_endpoints) > 0:
            findings.append(KeyFinding(
                title=(
                    f"{len(vendor_dna.high_risk_endpoints)} endpoint(s) with "
                    f"high compound vendor risk"
                ),
                severity="high",
                description=(
                    f"{len(vendor_dna.high_risk_endpoints)} endpoint(s) have "
                    f"a compound vendor vulnerability risk score exceeding 60. "
                    f"These endpoints run multiple technology stacks with "
                    f"overlapping CWE exposure patterns, increasing the "
                    f"probability of exploitable vulnerabilities."
                ),
            ))

        # Threat actor alignment
        high_alignment = [
            a for a in vendor_dna.threat_actor_alignment
            if a.alignment_score >= 0.6  # noqa: PLR2004
        ]
        if high_alignment:
            actor_names = [a.actor_name for a in high_alignment[:3]]
            findings.append(KeyFinding(
                title="Vendor stack aligns with known threat actor TTPs",
                severity="high",
                description=(
                    f"The detected technology stack's CWE profile aligns with "
                    f"known exploitation patterns of: "
                    f"{', '.join(actor_names)}. "
                    f"These threat actors have demonstrated capability and "
                    f"intent to exploit the vulnerability classes present in "
                    f"the organization's vendor stack."
                ),
            ))

        return findings

    def _generate_vendor_dna_recommendations(
        self,
        vendor_dna: VendorDnaAnalysis,
        start_priority: int,
    ) -> list[Recommendation]:
        """Generate recommendations from vendor DNA analysis."""
        recs: list[Recommendation] = []
        priority = start_priority

        # EOL product remediation
        if vendor_dna.eol_products:
            eol_vendors = sorted({p.vendor for p in vendor_dna.eol_products})
            recs.append(Recommendation(
                priority=priority,
                title="Replace end-of-life software components",
                description=(
                    f"{len(vendor_dna.eol_products)} EOL product(s) detected "
                    f"from vendor(s): {', '.join(eol_vendors)}. Upgrade to "
                    f"vendor-supported versions immediately. EOL software "
                    f"receives no security patches and is a primary target "
                    f"for automated exploitation."
                ),
                effort="immediate",
            ))
            priority += 1

        # High-risk endpoint remediation
        if vendor_dna.high_risk_endpoints:
            recs.append(Recommendation(
                priority=priority,
                title="Reduce compound vendor risk on high-exposure endpoints",
                description=(
                    f"{len(vendor_dna.high_risk_endpoints)} endpoint(s) have "
                    f"compound vendor risk above 60. Reduce technology stack "
                    f"complexity, apply vendor-specific hardening guides, and "
                    f"implement WAF rules targeting the dominant CWE patterns "
                    f"for these endpoints."
                ),
                effort="short-term",
            ))
            priority += 1

        # Vendor diversity
        if len(vendor_dna.vendor_profiles) > 3:  # noqa: PLR2004
            recs.append(Recommendation(
                priority=priority,
                title="Consolidate technology vendor footprint",
                description=(
                    f"{len(vendor_dna.vendor_profiles)} distinct technology "
                    f"vendors detected across the attack surface. High vendor "
                    f"diversity increases the patch management burden and "
                    f"expands the CWE exposure surface. Consider standardizing "
                    f"on fewer technology stacks where operationally feasible."
                ),
                effort="long-term",
            ))

        return recs


__all__ = [
    "AttractionAssessment",
    "AttractionFactor",
    "CisoReport",
    "CisoReportGenerator",
    "EolProduct",
    "ExecutiveSummary",
    "HighRiskEndpoint",
    "KeyFinding",
    "OrganizationProfile",
    "RankedTarget",
    "Recommendation",
    "ReportMetrics",
    "SectorAnalysis",
    "ThreatActorCweAlignment",
    "ThreatActorProfile",
    "ThreatLandscape",
    "VendorDnaAnalysis",
    "VendorProfile",
]
