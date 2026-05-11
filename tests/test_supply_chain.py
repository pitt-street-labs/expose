"""Tests for supply chain inference — provider detection from DNS records.

Covers:
 1. CNAME-based provider detection (Cloudflare, AWS, Azure, etc.)
 2. MX-based provider detection (Google Workspace, Microsoft 365)
 3. SPF include-based provider detection
 4. NS-based provider detection
 5. TXT-based provider detection
 6. Unknown patterns produce no detections
 7. Deduplication — same provider from multiple records on one entity
 8. Multiple providers from single entity
 9. Multiple entities detecting same provider (separate detections)
10. Custom provider_db override
11. Case-insensitive matching
12. Trailing-dot stripping
13. Empty entities list
14. Entity with empty properties
15. SPF record parsing (full string with include: directives)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import uuid4

import pytest

from expose.pipeline.supply_chain import (
    PROVIDER_DB,
    ProviderDetection,
    detect_providers,
)


# ---------------------------------------------------------------------------
# Helpers — lightweight stand-in for Entity ORM objects
# ---------------------------------------------------------------------------


@dataclass
class MockEntity:
    """Minimal Entity-like object for supply chain tests.

    Only needs ``canonical_identifier`` and ``properties`` since
    ``detect_providers`` reads only those two fields from each entity.
    """

    canonical_identifier: str
    properties: dict[str, Any]
    entity_type: str = "domain"
    id: Any = None

    def __post_init__(self) -> None:
        if self.id is None:
            self.id = uuid4()


# === 1. CNAME-based provider detection ========================================


def test_cname_cloudflare_detection() -> None:
    """Cloudflare CNAME (*.cdn.cloudflare.net) should be detected."""
    entity = MockEntity(
        canonical_identifier="app.example.com",
        properties={
            "record_type": "CNAME",
            "target": "app.example.com.cdn.cloudflare.net",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    d = detections[0]
    assert d.provider_id == "cloudflare"
    assert d.provider_name == "Cloudflare"
    assert d.category == "cdn_waf"
    assert d.evidence_type == "cname"
    assert d.evidence_value == "app.example.com.cdn.cloudflare.net"
    assert d.source_entity == "app.example.com"
    assert "proxy" in d.risk_notes.lower() or "CDN" in d.risk_notes


def test_cname_aws_detection() -> None:
    """AWS CNAME (*.amazonaws.com) should be detected."""
    entity = MockEntity(
        canonical_identifier="api.example.com",
        properties={
            "record_type": "CNAME",
            "target": "d111111abcdef8.cloudfront.net",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "aws"
    assert detections[0].evidence_type == "cname"


def test_cname_azure_detection() -> None:
    """Azure CNAME (*.azurewebsites.net) should be detected."""
    entity = MockEntity(
        canonical_identifier="portal.example.com",
        properties={
            "record_type": "CNAME",
            "target": "myapp.azurewebsites.net",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "azure"


def test_cname_chain_detection() -> None:
    """CNAME chain entries from subdomain_enum should also be scanned."""
    entity = MockEntity(
        canonical_identifier="blog.example.com",
        properties={
            "cname_chain": ["something.herokuapp.com"],
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "heroku"
    assert detections[0].evidence_type == "cname"


# === 2. MX-based provider detection ==========================================


def test_mx_google_workspace() -> None:
    """Google Workspace MX (aspmx.l.google.com) should be detected."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "exchanges": [
                {"exchange": "aspmx.l.google.com", "priority": 1},
                {"exchange": "alt1.aspmx.l.google.com", "priority": 5},
            ],
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "google_workspace"
    assert detections[0].category == "email"
    assert detections[0].evidence_type == "mx"


def test_mx_microsoft_365() -> None:
    """Microsoft 365 MX (*.mail.protection.outlook.com) should be detected."""
    entity = MockEntity(
        canonical_identifier="corp.example.com",
        properties={
            "exchanges": [
                {"exchange": "corp-example-com.mail.protection.outlook.com"},
            ],
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "microsoft_365"
    assert detections[0].evidence_type == "mx"


def test_mx_mailgun() -> None:
    """Mailgun MX (*.mailgun.org) should be detected."""
    entity = MockEntity(
        canonical_identifier="notifications.example.com",
        properties={
            "exchanges": [
                {"exchange": "mxa.mailgun.org"},
            ],
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "mailgun"


# === 3. SPF include-based provider detection ==================================


def test_spf_google() -> None:
    """SPF include:_spf.google.com should detect Google Workspace."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "spf_record": "v=spf1 include:_spf.google.com ~all",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "google_workspace"
    assert detections[0].evidence_type == "spf"


def test_spf_microsoft() -> None:
    """SPF include:spf.protection.outlook.com should detect Microsoft 365."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "spf_record": "v=spf1 include:spf.protection.outlook.com -all",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "microsoft_365"
    assert detections[0].evidence_type == "spf"


def test_spf_includes_list() -> None:
    """Pre-parsed spf_includes list should also be scanned."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "spf_includes": ["sendgrid.net"],
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "sendgrid"


def test_spf_aws_ses() -> None:
    """SPF include:amazonses.com should detect AWS."""
    entity = MockEntity(
        canonical_identifier="mail.example.com",
        properties={
            "spf_record": "v=spf1 include:amazonses.com ~all",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "aws"
    assert detections[0].evidence_type == "spf"


# === 4. NS-based provider detection ==========================================


def test_ns_cloudflare() -> None:
    """Cloudflare NS (*.ns.cloudflare.com) should be detected."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "nameservers": [
                "asa.ns.cloudflare.com",
                "brad.ns.cloudflare.com",
            ],
        },
    )
    detections = detect_providers([entity])
    # Should detect cloudflare and/or cloudflare_dns (both match *.ns.cloudflare.com)
    provider_ids = {d.provider_id for d in detections}
    assert "cloudflare" in provider_ids or "cloudflare_dns" in provider_ids
    assert all(d.evidence_type == "ns" for d in detections)


def test_ns_route53() -> None:
    """AWS Route 53 NS (*.awsdns-*) should be detected."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "nameservers": [
                "ns-1234.awsdns-56.org",
                "ns-789.awsdns-01.co.uk",
            ],
        },
    )
    detections = detect_providers([entity])
    provider_ids = {d.provider_id for d in detections}
    assert "aws" in provider_ids or "route53" in provider_ids


# === 5. TXT-based provider detection =========================================


def test_txt_google_verification() -> None:
    """google-site-verification TXT should detect Google Workspace."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "record_type": "TXT",
            "values": ["google-site-verification=abc123xyz"],
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "google_workspace"
    assert detections[0].evidence_type == "txt"


def test_txt_ms_verification() -> None:
    """MS= or ms= TXT should detect Microsoft 365."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "record_type": "TXT",
            "values": ["MS=ms12345678"],
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "microsoft_365"
    assert detections[0].evidence_type == "txt"


# === 6. Unknown patterns produce no detections ================================


def test_no_detection_for_unknown_cname() -> None:
    """CNAME to an unknown domain should produce no detections."""
    entity = MockEntity(
        canonical_identifier="app.example.com",
        properties={
            "record_type": "CNAME",
            "target": "lb.internalinfra.example.net",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 0


def test_no_detection_for_unknown_mx() -> None:
    """MX to an unknown mail server should produce no detections."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "exchanges": [
                {"exchange": "mail.example.com"},
            ],
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 0


def test_no_detection_for_empty_properties() -> None:
    """Entity with empty properties should produce no detections."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={},
    )
    detections = detect_providers([entity])
    assert len(detections) == 0


def test_no_detection_for_unrelated_properties() -> None:
    """Entity with properties that don't contain DNS data should be skipped."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "http_status": 200,
            "server": "nginx",
            "title": "Example Domain",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 0


# === 7. Deduplication — same provider from multiple records ==================


def test_deduplication_same_provider_multiple_records() -> None:
    """Same provider detected from CNAME + NS on one entity = one detection."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "record_type": "CNAME",
            "target": "example.com.cdn.cloudflare.net",
            "nameservers": [
                "asa.ns.cloudflare.com",
            ],
        },
    )
    detections = detect_providers([entity])
    cloudflare_detections = [
        d for d in detections if d.provider_id == "cloudflare"
    ]
    # At most one cloudflare detection per entity
    assert len(cloudflare_detections) <= 1


# === 8. Multiple providers from single entity ================================


def test_multiple_providers_from_single_entity() -> None:
    """One entity can depend on multiple providers."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "exchanges": [
                {"exchange": "aspmx.l.google.com"},
            ],
            "nameservers": [
                "asa.ns.cloudflare.com",
            ],
        },
    )
    detections = detect_providers([entity])
    provider_ids = {d.provider_id for d in detections}
    assert "google_workspace" in provider_ids
    # Cloudflare or cloudflare_dns
    assert "cloudflare" in provider_ids or "cloudflare_dns" in provider_ids


# === 9. Multiple entities detecting same provider ============================


def test_same_provider_from_multiple_entities() -> None:
    """Same provider from different entities → separate detections."""
    entities = [
        MockEntity(
            canonical_identifier="app.example.com",
            properties={
                "record_type": "CNAME",
                "target": "app.cdn.cloudflare.net",
            },
        ),
        MockEntity(
            canonical_identifier="api.example.com",
            properties={
                "record_type": "CNAME",
                "target": "api.cdn.cloudflare.net",
            },
        ),
    ]
    detections = detect_providers(entities)
    cloudflare = [d for d in detections if d.provider_id == "cloudflare"]
    assert len(cloudflare) == 2
    sources = {d.source_entity for d in cloudflare}
    assert sources == {"app.example.com", "api.example.com"}


# === 10. Custom provider_db override =========================================


def test_custom_provider_db() -> None:
    """A custom provider_db should be used instead of the default."""
    custom_db = {
        "custom_cdn": {
            "name": "Custom CDN",
            "category": "cdn",
            "patterns": {
                "cname": ["*.customcdn.example.com"],
            },
            "risk_notes": "Custom CDN provider.",
        },
    }
    entity = MockEntity(
        canonical_identifier="site.example.com",
        properties={
            "record_type": "CNAME",
            "target": "edge.customcdn.example.com",
        },
    )
    detections = detect_providers([entity], provider_db=custom_db)
    assert len(detections) == 1
    assert detections[0].provider_id == "custom_cdn"
    assert detections[0].provider_name == "Custom CDN"

    # The default DB should not match
    detections_default = detect_providers([entity])
    custom_in_default = [
        d for d in detections_default if d.provider_id == "custom_cdn"
    ]
    assert len(custom_in_default) == 0


# === 11. Case-insensitive matching ============================================


def test_case_insensitive_cname() -> None:
    """Provider patterns should match case-insensitively."""
    entity = MockEntity(
        canonical_identifier="app.example.com",
        properties={
            "record_type": "CNAME",
            "target": "App.Example.Com.CDN.CloudFlare.Net",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "cloudflare"


def test_case_insensitive_mx() -> None:
    """MX records should match case-insensitively."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "exchanges": [
                {"exchange": "ASPMX.L.GOOGLE.COM"},
            ],
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "google_workspace"


# === 12. Trailing-dot stripping ===============================================


def test_trailing_dot_stripped() -> None:
    """DNS record values with trailing dots should still match."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "record_type": "CNAME",
            "target": "app.cdn.cloudflare.net.",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "cloudflare"


# === 13. Empty entities list ==================================================


def test_empty_entities() -> None:
    """Empty entity list should produce no detections."""
    detections = detect_providers([])
    assert detections == []


# === 14. Entity with None properties ==========================================


def test_none_properties() -> None:
    """Entity with properties=None should not crash."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties=None,  # type: ignore[arg-type]
    )
    # Should handle gracefully (properties is None, not dict)
    detections = detect_providers([entity])
    assert detections == []


# === 15. SPF record parsing (full string) =====================================


def test_spf_multiple_includes() -> None:
    """SPF record with multiple include: directives → detect all matching."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "spf_record": (
                "v=spf1 include:_spf.google.com "
                "include:sendgrid.net "
                "include:mailgun.org ~all"
            ),
        },
    )
    detections = detect_providers([entity])
    provider_ids = {d.provider_id for d in detections}
    assert "google_workspace" in provider_ids
    assert "sendgrid" in provider_ids
    assert "mailgun" in provider_ids


# === 16. ProviderDetection is frozen ==========================================


def test_provider_detection_frozen() -> None:
    """ProviderDetection should be immutable (frozen dataclass)."""
    d = ProviderDetection(
        provider_id="test",
        provider_name="Test",
        category="test",
        evidence_type="cname",
        evidence_value="test.example.com",
        source_entity="example.com",
        risk_notes="test risk",
    )
    with pytest.raises(AttributeError):
        d.provider_id = "changed"  # type: ignore[misc]


# === 17. PROVIDER_DB structure validation =====================================


def test_provider_db_has_required_keys() -> None:
    """Every entry in PROVIDER_DB must have name, category, patterns, risk_notes."""
    for provider_id, info in PROVIDER_DB.items():
        assert "name" in info, f"{provider_id} missing 'name'"
        assert "category" in info, f"{provider_id} missing 'category'"
        assert "patterns" in info, f"{provider_id} missing 'patterns'"
        assert "risk_notes" in info, f"{provider_id} missing 'risk_notes'"
        assert isinstance(info["patterns"], dict), (
            f"{provider_id} 'patterns' should be dict"
        )
        for evidence_type, patterns in info["patterns"].items():
            assert evidence_type in ("cname", "mx", "spf", "ns", "txt"), (
                f"{provider_id} has unknown evidence_type: {evidence_type}"
            )
            assert isinstance(patterns, list), (
                f"{provider_id}.patterns.{evidence_type} should be list"
            )
            assert len(patterns) > 0, (
                f"{provider_id}.patterns.{evidence_type} is empty"
            )


# === 18. GCP detection ======================================================


def test_cname_gcp_appspot() -> None:
    """GCP CNAME (*.appspot.com) should be detected."""
    entity = MockEntity(
        canonical_identifier="app.example.com",
        properties={
            "record_type": "CNAME",
            "target": "myproject.appspot.com",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "gcp"


# === 19. Hosting providers via CNAME =========================================


def test_cname_vercel() -> None:
    """Vercel CNAME should be detected."""
    entity = MockEntity(
        canonical_identifier="www.example.com",
        properties={
            "record_type": "CNAME",
            "target": "cname.vercel-dns.com",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "vercel"


def test_cname_netlify() -> None:
    """Netlify CNAME should be detected."""
    entity = MockEntity(
        canonical_identifier="blog.example.com",
        properties={
            "record_type": "CNAME",
            "target": "mysite.netlify.app",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "netlify"


def test_cname_github_pages() -> None:
    """GitHub Pages CNAME should be detected."""
    entity = MockEntity(
        canonical_identifier="docs.example.com",
        properties={
            "record_type": "CNAME",
            "target": "myorg.github.io",
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "github_pages"


# === 20. Email security providers ============================================


def test_mx_proofpoint() -> None:
    """Proofpoint MX should be detected."""
    entity = MockEntity(
        canonical_identifier="secure.example.com",
        properties={
            "exchanges": [
                {"exchange": "mx1.secure.example.com.pphosted.com"},
            ],
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "proofpoint"
    assert detections[0].category == "email_security"


def test_mx_mimecast() -> None:
    """Mimecast MX should be detected."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "exchanges": [
                {"exchange": "us-smtp-inbound-1.mimecast.com"},
            ],
        },
    )
    detections = detect_providers([entity])
    assert len(detections) == 1
    assert detections[0].provider_id == "mimecast"
    assert detections[0].category == "email_security"
