"""Tests for the security-txt (RFC 9116) collector.

Exercises all code paths with mocked HTTP -- no live network requests.

Coverage:
    1. Happy path -- domain with full security.txt at well-known path
    2. Legacy fallback -- security.txt at /security.txt when well-known 404s
    3. No security.txt found -- both paths 404
    4. Domain extraction from Contact/Policy/Hiring URLs
    5. Seed domain self-reference filtering
    6. Non-domain seed skipped
    7. HTTP error handling (timeouts, server errors)
    8. Health check success and failure
    9. Field parsing edge cases (comments, blank lines, multi-value)
   10. Registration in default registry
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
from uuid import UUID

import httpx
import pytest

from expose.collectors.base import (
    CollectorConfig,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.security_txt import (
    SecurityTxtCollector,
    extract_domains_from_urls,
    parse_security_txt,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000E001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000E002")


def _config() -> CollectorConfig:
    """Build a minimal CollectorConfig for test use."""
    return CollectorConfig(tenant_id=TENANT_ID, run_id=RUN_ID)


# === Mock helpers =============================================================


def _mock_response(
    status_code: int = 200,
    text: str = "",
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Build a mock httpx.Response."""
    request = httpx.Request("GET", "https://example.com/test")
    resp = httpx.Response(
        status_code=status_code,
        text=text,
        request=request,
        headers=headers or {},
    )
    return resp


# === Tests ====================================================================


class TestSecurityTxtHappyPath:
    """Test 1: Full security.txt at well-known path."""

    async def test_full_security_txt(self) -> None:
        body = (
            "# Example Corp security.txt\n"
            "Contact: https://hackerone.com/example\n"
            "Contact: mailto:security@example.com\n"
            "Expires: 2027-01-01T00:00:00.000Z\n"
            "Encryption: https://keys.example.com/pgp-key.txt\n"
            "Policy: https://example.com/security-policy\n"
            "Hiring: https://careers.example.com/security\n"
            "Acknowledgments: https://example.com/hall-of-fame\n"
            "Preferred-Languages: en, fr\n"
            "Canonical: https://example.com/.well-known/security.txt\n"
        )

        collector = SecurityTxtCollector(_config())

        async def mock_fetch(url: str) -> str | None:
            if "/.well-known/security.txt" in url:
                return body
            return None

        collector._fetch_security_txt = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations: list[Observation] = [
            obs async for obs in collector.expand(seed)
        ]

        # Expect: 1 summary + domain observations for hackerone.com,
        # keys.example.com, careers.example.com.
        # example.com self-references are filtered out.
        assert len(observations) >= 1
        summary = observations[0]
        assert summary.collector_id == "security-txt"
        assert summary.observation_type == ObservationType.HTTP_RESPONSE
        assert summary.subject.identifier_type == IdentifierType.DOMAIN
        assert summary.subject.identifier_value == "example.com"

        p = summary.structured_payload
        assert p["source"] == "security_txt"
        assert "contact" in p["fields"]
        assert len(p["fields"]["contact"]) == 2
        assert p["field_count"] >= 8

        # Check that discovered domains are emitted (not self-refs).
        discovered_domains = [
            obs.subject.identifier_value
            for obs in observations[1:]
        ]
        assert "hackerone.com" in discovered_domains
        assert "keys.example.com" in discovered_domains
        assert "careers.example.com" in discovered_domains
        # Self-references should be filtered.
        assert "example.com" not in discovered_domains


class TestSecurityTxtLegacyFallback:
    """Test 2: Legacy fallback path when well-known returns 404."""

    async def test_fallback_to_root_security_txt(self) -> None:
        body = "Contact: https://bugcrowd.com/testcorp\n"

        collector = SecurityTxtCollector(_config())

        call_count = 0

        async def mock_fetch(url: str) -> str | None:
            nonlocal call_count
            call_count += 1
            if "/.well-known/security.txt" in url:
                return None  # 404
            if url.endswith("/security.txt"):
                return body
            return None

        collector._fetch_security_txt = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="fallback.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert call_count == 2  # Both URLs tried
        assert len(observations) >= 1
        summary = observations[0]
        assert summary.structured_payload["source"] == "security_txt"


class TestSecurityTxtNotFound:
    """Test 3: No security.txt found at either path."""

    async def test_no_security_txt_yields_nothing(self) -> None:
        collector = SecurityTxtCollector(_config())

        async def mock_fetch(url: str) -> str | None:
            return None  # 404 on both paths

        collector._fetch_security_txt = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="nosecuritytxt.com")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []


class TestSecurityTxtDomainExtraction:
    """Test 4: Domain extraction from various URL fields."""

    async def test_domains_extracted_from_urls(self) -> None:
        body = (
            "Contact: https://hackerone.com/acme\n"
            "Policy: https://security.acme.org/disclosure\n"
            "Hiring: https://careers.acme.org/infosec\n"
        )

        collector = SecurityTxtCollector(_config())

        async def mock_fetch(url: str) -> str | None:
            if "/.well-known/security.txt" in url:
                return body
            return None

        collector._fetch_security_txt = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = [obs async for obs in collector.expand(seed)]

        discovered = {obs.subject.identifier_value for obs in observations[1:]}
        assert "hackerone.com" in discovered
        assert "security.acme.org" in discovered
        assert "careers.acme.org" in discovered

        # Verify structured_payload has field context.
        for obs in observations[1:]:
            assert obs.structured_payload["source"] == "security_txt"
            assert "field" in obs.structured_payload
            assert "raw_value" in obs.structured_payload


class TestSecurityTxtSelfReferenceFiltering:
    """Test 5: Seed domain self-references filtered out."""

    async def test_self_domain_not_emitted(self) -> None:
        body = (
            "Contact: https://selfref.com/security\n"
            "Policy: https://selfref.com/policy\n"
            "Hiring: https://external.com/jobs\n"
        )

        collector = SecurityTxtCollector(_config())

        async def mock_fetch(url: str) -> str | None:
            if "/.well-known/security.txt" in url:
                return body
            return None

        collector._fetch_security_txt = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="selfref.com")
        observations = [obs async for obs in collector.expand(seed)]

        discovered_domains = [
            obs.subject.identifier_value for obs in observations[1:]
        ]
        assert "selfref.com" not in discovered_domains
        assert "external.com" in discovered_domains


class TestSecurityTxtNonDomainSeed:
    """Test 6: Non-domain seeds are silently skipped."""

    async def test_ip_seed_skipped(self) -> None:
        collector = SecurityTxtCollector(_config())
        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_organization_seed_skipped(self) -> None:
        collector = SecurityTxtCollector(_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="ACME Corp")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []


class TestSecurityTxtHttpErrors:
    """Test 7: HTTP error handling."""

    async def test_http_error_handled_gracefully(self) -> None:
        collector = SecurityTxtCollector(_config())

        async def mock_fetch(url: str) -> str | None:
            raise httpx.ConnectError("Connection refused")

        collector._fetch_security_txt = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="unreachable.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_server_error_handled_gracefully(self) -> None:
        collector = SecurityTxtCollector(_config())

        async def mock_fetch(url: str) -> str | None:
            resp = _mock_response(status_code=500, text="Internal Server Error")
            raise httpx.HTTPStatusError(
                "Server Error", request=resp.request, response=resp
            )

        collector._fetch_security_txt = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="broken.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []


class TestSecurityTxtHealthCheck:
    """Test 8: Health check success and failure."""

    async def test_health_check_success(self) -> None:
        collector = SecurityTxtCollector(_config())

        mock_resp = _mock_response(status_code=404)

        with patch("httpx.AsyncClient.head", new_callable=AsyncMock) as mock_head:
            mock_head.return_value = mock_resp
            result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "security-txt"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    async def test_health_check_failure(self) -> None:
        collector = SecurityTxtCollector(_config())

        with patch("httpx.AsyncClient.head", new_callable=AsyncMock) as mock_head:
            mock_head.side_effect = httpx.ConnectError("Connection refused")
            result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None


# === Unit tests for parsing helpers ==========================================


class TestParseSecurityTxt:
    """Test 9: Field parsing edge cases."""

    def test_basic_parsing(self) -> None:
        body = (
            "Contact: https://example.com/security\n"
            "Expires: 2027-01-01T00:00:00.000Z\n"
        )
        result = parse_security_txt(body)
        assert result["contact"] == ["https://example.com/security"]
        assert result["expires"] == ["2027-01-01T00:00:00.000Z"]

    def test_comments_and_blank_lines_skipped(self) -> None:
        body = (
            "# This is a comment\n"
            "\n"
            "Contact: https://example.com/sec\n"
            "# Another comment\n"
            "\n"
        )
        result = parse_security_txt(body)
        assert result["contact"] == ["https://example.com/sec"]
        assert len(result) == 1

    def test_multi_value_fields(self) -> None:
        body = (
            "Contact: https://hackerone.com/corp\n"
            "Contact: mailto:sec@corp.com\n"
            "Contact: tel:+1-555-0100\n"
        )
        result = parse_security_txt(body)
        assert len(result["contact"]) == 3

    def test_case_insensitive_field_names(self) -> None:
        body = (
            "CONTACT: https://example.com/security\n"
            "Policy: https://example.com/policy\n"
            "HIRING: https://example.com/jobs\n"
        )
        result = parse_security_txt(body)
        assert "contact" in result
        assert "policy" in result
        assert "hiring" in result

    def test_empty_body(self) -> None:
        result = parse_security_txt("")
        assert result == {}

    def test_unrecognized_fields_ignored(self) -> None:
        body = (
            "Contact: https://example.com/security\n"
            "X-Custom: some-value\n"
            "NotAField: garbage\n"
        )
        result = parse_security_txt(body)
        assert "contact" in result
        assert "x-custom" not in result
        assert "notafield" not in result

    def test_value_with_colon(self) -> None:
        """Fields with colons in the value (e.g., URLs) parse correctly."""
        body = "Contact: https://example.com:8443/security\n"
        result = parse_security_txt(body)
        assert result["contact"] == ["https://example.com:8443/security"]


class TestExtractDomainsFromUrls:
    """Unit tests for extract_domains_from_urls helper."""

    def test_basic_extraction(self) -> None:
        urls = [
            "https://hackerone.com/acme",
            "https://security.acme.org/policy",
        ]
        result = extract_domains_from_urls(urls)
        domains = [d for d, _ in result]
        assert "hackerone.com" in domains
        assert "security.acme.org" in domains

    def test_deduplication(self) -> None:
        urls = [
            "https://hackerone.com/acme",
            "https://hackerone.com/other",
        ]
        result = extract_domains_from_urls(urls)
        assert len(result) == 1

    def test_invalid_urls_skipped(self) -> None:
        urls = [
            "https://valid.com/path",
            "not-a-url",
            "",
        ]
        result = extract_domains_from_urls(urls)
        domains = [d for d, _ in result]
        assert "valid.com" in domains


# === Registration tests ======================================================


class TestSecurityTxtRegistration:
    """Test 10: Verify the collector registers correctly."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("security-txt")
        cls = DEFAULT_REGISTRY.get("security-txt")
        assert cls is SecurityTxtCollector

    def test_metadata_correct(self) -> None:
        assert SecurityTxtCollector.collector_id == "security-txt"
        assert SecurityTxtCollector.collector_version == "0.1.0"
        assert SecurityTxtCollector.tier == CollectorTier.TIER_1
        assert SecurityTxtCollector.requires_credentials is False
