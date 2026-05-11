"""Tests for subdomain takeover detection (Issue #95).

Covers:
 1. CNAME to herokuapp.com + NXDOMAIN = critical risk
 2. CNAME to herokuapp.com + resolves = no risk (service still active)
 3. CNAME to non-vulnerable service = no detection
 4. Multiple vulnerable CNAME targets on separate entities
 5. CNAME chain (dns_subdomain_enum format) detection
 6. cname_target standalone property detection
 7. Case-insensitive matching
 8. Trailing-dot stripping
 9. Entity with empty properties = no detection
10. Entity with no CNAME properties = no detection
11. Wildcard fingerprint matching (*.s3.amazonaws.com, *.firebaseapp.com)
12. Suffix matching (herokuapp.com matches foo.herokuapp.com)
13. TakeoverRisk is frozen (immutable)
14. TAKEOVER_FINGERPRINTS database completeness
15. Multiple CNAME targets from one entity (cname_chain)
16. dns_check=False mode (skip network, return high risk)
17. Azure, GitHub Pages, Netlify, Vercel provider detection
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import pytest

from expose.pipeline.takeover_detection import (
    TAKEOVER_FINGERPRINTS,
    TakeoverRisk,
    detect_takeover_risks,
)


# ---------------------------------------------------------------------------
# Helpers — lightweight stand-in for Entity ORM objects
# ---------------------------------------------------------------------------


@dataclass
class MockEntity:
    """Minimal Entity-like object for takeover detection tests.

    Only needs ``canonical_identifier`` and ``properties`` since
    ``detect_takeover_risks`` reads only those two fields from each entity.
    """

    canonical_identifier: str
    properties: dict[str, Any]
    entity_type: str = "domain"
    id: Any = None

    def __post_init__(self) -> None:
        if self.id is None:
            self.id = uuid4()


# === 1. CNAME to herokuapp.com + NXDOMAIN = critical risk ===================


@pytest.mark.asyncio
async def test_heroku_nxdomain_critical(monkeypatch: pytest.MonkeyPatch) -> None:
    """CNAME to herokuapp.com with NXDOMAIN should produce critical risk."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entity = MockEntity(
        canonical_identifier="staging.cyberark.com",
        properties={
            "record_type": "CNAME",
            "target": "cyberark.herokuapp.com",
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 1
    risk = risks[0]
    assert risk.subdomain == "staging.cyberark.com"
    assert risk.cname_target == "cyberark.herokuapp.com"
    assert risk.provider == "heroku"
    assert risk.risk_level == "critical"
    assert "NXDOMAIN" in risk.evidence


# === 2. CNAME to herokuapp.com + resolves = no risk =========================


@pytest.mark.asyncio
async def test_heroku_resolves_no_risk(monkeypatch: pytest.MonkeyPatch) -> None:
    """CNAME to herokuapp.com that resolves should produce no risk."""

    def _succeed_resolve(host, port, family=0, type_=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("54.1.2.3", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _succeed_resolve)

    entity = MockEntity(
        canonical_identifier="app.example.com",
        properties={
            "record_type": "CNAME",
            "target": "myapp.herokuapp.com",
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 0


# === 3. CNAME to non-vulnerable service = no detection ======================


@pytest.mark.asyncio
async def test_non_vulnerable_cname_no_detection() -> None:
    """CNAME to a non-vulnerable service should produce no detection."""
    entity = MockEntity(
        canonical_identifier="www.example.com",
        properties={
            "record_type": "CNAME",
            "target": "www.example.com.cdn.cloudflare.net",
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 0


# === 4. Multiple vulnerable targets on separate entities ====================


@pytest.mark.asyncio
async def test_multiple_entities_multiple_risks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple entities with dangling CNAMEs should produce separate risks."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entities = [
        MockEntity(
            canonical_identifier="staging.example.com",
            properties={
                "record_type": "CNAME",
                "target": "staging.herokuapp.com",
            },
        ),
        MockEntity(
            canonical_identifier="old-app.example.com",
            properties={
                "record_type": "CNAME",
                "target": "old-app.azurewebsites.net",
            },
        ),
    ]

    risks = await detect_takeover_risks(entities)

    assert len(risks) == 2
    subdomains = {r.subdomain for r in risks}
    assert subdomains == {"staging.example.com", "old-app.example.com"}
    providers = {r.provider for r in risks}
    assert "heroku" in providers
    assert "azure" in providers


# === 5. CNAME chain detection ================================================


@pytest.mark.asyncio
async def test_cname_chain_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    """CNAME targets in cname_chain (dns_subdomain_enum) should be checked."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entity = MockEntity(
        canonical_identifier="blog.example.com",
        properties={
            "cname_chain": ["something.herokuapp.com"],
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 1
    assert risks[0].subdomain == "blog.example.com"
    assert risks[0].cname_target == "something.herokuapp.com"
    assert risks[0].provider == "heroku"


# === 6. cname_target standalone property =====================================


@pytest.mark.asyncio
async def test_cname_target_standalone_property(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cname_target as a standalone property should be checked."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entity = MockEntity(
        canonical_identifier="docs.example.com",
        properties={
            "cname_target": "docs-example.github.io",
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 1
    assert risks[0].provider == "github_pages"


# === 7. Case-insensitive matching ============================================


@pytest.mark.asyncio
async def test_case_insensitive_matching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fingerprint matching should be case-insensitive."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entity = MockEntity(
        canonical_identifier="app.example.com",
        properties={
            "record_type": "CNAME",
            "target": "MyApp.HerokuApp.Com",
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 1
    assert risks[0].provider == "heroku"


# === 8. Trailing-dot stripping ================================================


@pytest.mark.asyncio
async def test_trailing_dot_stripping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CNAME targets with trailing dots should still match fingerprints."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entity = MockEntity(
        canonical_identifier="app.example.com",
        properties={
            "record_type": "CNAME",
            "target": "myapp.herokuapp.com.",
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 1
    assert risks[0].provider == "heroku"


# === 9. Empty properties = no detection ======================================


@pytest.mark.asyncio
async def test_empty_properties_no_detection() -> None:
    """Entity with empty properties should produce no detections."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={},
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 0


# === 10. No CNAME properties = no detection ==================================


@pytest.mark.asyncio
async def test_no_cname_properties_no_detection() -> None:
    """Entity with non-CNAME properties should produce no detections."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties={
            "record_type": "A",
            "values": ["93.184.216.34"],
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 0


# === 11. Wildcard fingerprint matching =======================================


@pytest.mark.asyncio
async def test_wildcard_s3_matching(monkeypatch: pytest.MonkeyPatch) -> None:
    """*.s3.amazonaws.com should match bucket-name.s3.amazonaws.com."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entity = MockEntity(
        canonical_identifier="assets.example.com",
        properties={
            "record_type": "CNAME",
            "target": "deleted-bucket.s3.amazonaws.com",
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 1
    assert risks[0].provider == "aws_s3"


@pytest.mark.asyncio
async def test_wildcard_firebase_matching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """*.firebaseapp.com should match myapp.firebaseapp.com."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entity = MockEntity(
        canonical_identifier="app.example.com",
        properties={
            "record_type": "CNAME",
            "target": "old-project.firebaseapp.com",
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 1
    assert risks[0].provider == "firebase"


# === 12. Suffix matching =====================================================


@pytest.mark.asyncio
async def test_suffix_heroku_matching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """herokuapp.com suffix match should work for subdomains."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entity = MockEntity(
        canonical_identifier="staging.example.com",
        properties={
            "record_type": "CNAME",
            "target": "my-staging-app.herokuapp.com",
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 1
    assert risks[0].provider == "heroku"


# === 13. TakeoverRisk is frozen (immutable) ==================================


def test_takeover_risk_frozen() -> None:
    """TakeoverRisk should be immutable (frozen dataclass)."""
    risk = TakeoverRisk(
        subdomain="test.example.com",
        cname_target="test.herokuapp.com",
        provider="heroku",
        risk_level="critical",
        evidence="test evidence",
    )
    with pytest.raises(AttributeError):
        risk.provider = "changed"  # type: ignore[misc]


# === 14. TAKEOVER_FINGERPRINTS database completeness =========================


def test_fingerprints_have_required_keys() -> None:
    """Every entry in TAKEOVER_FINGERPRINTS must have provider and check."""
    for pattern, fingerprint in TAKEOVER_FINGERPRINTS.items():
        assert "provider" in fingerprint, f"{pattern} missing 'provider'"
        assert "check" in fingerprint, f"{pattern} missing 'check'"
        assert isinstance(fingerprint["provider"], str), (
            f"{pattern} provider must be str"
        )
        assert isinstance(fingerprint["check"], str), (
            f"{pattern} check must be str"
        )


def test_fingerprints_minimum_count() -> None:
    """The fingerprint database should contain at least 15 providers."""
    assert len(TAKEOVER_FINGERPRINTS) >= 15


# === 15. Multiple CNAME targets from one entity =============================


@pytest.mark.asyncio
async def test_multiple_cname_chain_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Entity with multiple cname_chain entries should check all."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entity = MockEntity(
        canonical_identifier="multi.example.com",
        properties={
            "cname_chain": [
                "step1.herokuapp.com",
                "step2.netlify.app",
            ],
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 2
    providers = {r.provider for r in risks}
    assert providers == {"heroku", "netlify"}
    # All risks should point to the same subdomain
    assert all(r.subdomain == "multi.example.com" for r in risks)


# === 16. dns_check=False mode ================================================


@pytest.mark.asyncio
async def test_dns_check_disabled() -> None:
    """With dns_check=False, matches should return high risk without DNS lookup."""
    entity = MockEntity(
        canonical_identifier="app.example.com",
        properties={
            "record_type": "CNAME",
            "target": "gone.herokuapp.com",
        },
    )

    risks = await detect_takeover_risks([entity], dns_check=False)

    assert len(risks) == 1
    assert risks[0].risk_level == "high"
    assert "takeover-vulnerable" in risks[0].evidence


# === 17. Azure, GitHub Pages, Netlify, Vercel provider detection =============


@pytest.mark.asyncio
async def test_azure_provider_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Azure azurewebsites.net CNAME should detect azure provider."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entity = MockEntity(
        canonical_identifier="portal.example.com",
        properties={
            "record_type": "CNAME",
            "target": "old-portal.azurewebsites.net",
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 1
    assert risks[0].provider == "azure"
    assert risks[0].risk_level == "critical"


@pytest.mark.asyncio
async def test_github_pages_provider_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitHub Pages CNAME should detect github_pages provider."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entity = MockEntity(
        canonical_identifier="docs.example.com",
        properties={
            "record_type": "CNAME",
            "target": "deleted-org.github.io",
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 1
    assert risks[0].provider == "github_pages"
    assert risks[0].risk_level == "critical"


@pytest.mark.asyncio
async def test_netlify_provider_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Netlify CNAME should detect netlify provider."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entity = MockEntity(
        canonical_identifier="preview.example.com",
        properties={
            "record_type": "CNAME",
            "target": "old-site.netlify.app",
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 1
    assert risks[0].provider == "netlify"
    assert risks[0].risk_level == "critical"


@pytest.mark.asyncio
async def test_vercel_provider_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vercel CNAME should detect vercel provider."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entity = MockEntity(
        canonical_identifier="app.example.com",
        properties={
            "record_type": "CNAME",
            "target": "my-app.vercel.app",
        },
    )

    risks = await detect_takeover_risks([entity])

    assert len(risks) == 1
    assert risks[0].provider == "vercel"
    assert risks[0].risk_level == "critical"


# === 18. Empty entities list =================================================


@pytest.mark.asyncio
async def test_empty_entities_list() -> None:
    """Empty entity list should produce no risks."""
    risks = await detect_takeover_risks([])

    assert risks == []


# === 19. None properties handled gracefully ==================================


@pytest.mark.asyncio
async def test_none_properties_handled() -> None:
    """Entity with properties=None should not crash."""
    entity = MockEntity(
        canonical_identifier="example.com",
        properties=None,  # type: ignore[arg-type]
    )

    risks = await detect_takeover_risks([entity])

    assert risks == []


# === 20. Mixed vulnerable and non-vulnerable ================================


@pytest.mark.asyncio
async def test_mixed_vulnerable_and_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only vulnerable CNAME targets should produce risks; safe ones ignored."""

    def _fail_resolve(host, port, family=0, type_=0):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_resolve)

    entities = [
        MockEntity(
            canonical_identifier="safe.example.com",
            properties={
                "record_type": "CNAME",
                "target": "safe.cdn.cloudflare.net",
            },
        ),
        MockEntity(
            canonical_identifier="danger.example.com",
            properties={
                "record_type": "CNAME",
                "target": "gone.herokuapp.com",
            },
        ),
        MockEntity(
            canonical_identifier="also-safe.example.com",
            properties={
                "record_type": "A",
                "values": ["1.2.3.4"],
            },
        ),
    ]

    risks = await detect_takeover_risks(entities)

    assert len(risks) == 1
    assert risks[0].subdomain == "danger.example.com"
    assert risks[0].provider == "heroku"


# === 21. Selective DNS resolution — some resolve, some don't =================


@pytest.mark.asyncio
async def test_selective_dns_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only dangling CNAMEs (NXDOMAIN) should produce risks."""
    call_count = 0

    def _selective_resolve(host, port, family=0, type_=0):
        nonlocal call_count
        call_count += 1
        # First call resolves (service active), second fails (dangling)
        if "active" in host:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("54.1.2.3", 0))]
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _selective_resolve)

    entities = [
        MockEntity(
            canonical_identifier="active.example.com",
            properties={
                "record_type": "CNAME",
                "target": "active-app.herokuapp.com",
            },
        ),
        MockEntity(
            canonical_identifier="dead.example.com",
            properties={
                "record_type": "CNAME",
                "target": "dead-app.herokuapp.com",
            },
        ),
    ]

    risks = await detect_takeover_risks(entities)

    assert len(risks) == 1
    assert risks[0].subdomain == "dead.example.com"
    assert call_count == 2  # Both were checked via DNS
