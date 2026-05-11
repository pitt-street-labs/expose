"""Tests for the dns-chaos (ProjectDiscovery Chaos) collector.

Exercises all code paths with mocked HTTP -- no live network requests.

Coverage:
    1. Happy path -- domain with subdomains in Chaos dataset
    2. Empty subdomains list -- domain exists but no subdomains
    3. Domain not in Chaos dataset (404)
    4. Access denied (403) -- graceful degradation
    5. Non-domain seed skipped
    6. HTTP error handling
    7. Health check success and failure
    8. Response format variations (dict with/without domain key, plain list)
    9. API key credential handling
   10. Registration in default registry
   11. Subdomain label edge cases (empty, "@")
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch
from uuid import UUID

import httpx
import pytest

from expose.collectors.base import (
    CollectorConfig,
    CollectorCredential,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.dns_chaos import DnsChaosCollector
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000E001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000E002")


def _config(
    credentials: dict[str, CollectorCredential] | None = None,
) -> CollectorConfig:
    """Build a minimal CollectorConfig for test use."""
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        credentials=credentials or {},
    )


# === Mock helpers =============================================================


def _mock_response(
    status_code: int = 200,
    json_data: dict | list | None = None,
    text: str = "",
) -> httpx.Response:
    """Build a mock httpx.Response with JSON content."""
    request = httpx.Request(
        "GET", "https://dns.projectdiscovery.io/dns/example.com/subdomains"
    )
    if json_data is not None:
        content = json.dumps(json_data).encode("utf-8")
        headers = {"content-type": "application/json"}
    else:
        content = text.encode("utf-8")
        headers = {"content-type": "text/plain"}
    return httpx.Response(
        status_code=status_code,
        content=content,
        request=request,
        headers=headers,
    )


# === Tests ====================================================================


class TestDnsChaosHappyPath:
    """Test 1: Domain with subdomains in Chaos dataset."""

    async def test_subdomains_discovered(self) -> None:
        subdomains = ["www", "mail", "api", "staging", "dev"]
        response_data = {
            "domain": "example.com",
            "subdomains": subdomains,
        }

        collector = DnsChaosCollector(_config())

        async def mock_fetch(url: str) -> list[str]:
            return subdomains

        collector._fetch_subdomains = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations: list[Observation] = [
            obs async for obs in collector.expand(seed)
        ]

        assert len(observations) == 5
        fqdns = {obs.subject.identifier_value for obs in observations}
        assert "www.example.com" in fqdns
        assert "mail.example.com" in fqdns
        assert "api.example.com" in fqdns
        assert "staging.example.com" in fqdns
        assert "dev.example.com" in fqdns

        # Verify all observations have correct structure.
        for obs in observations:
            assert obs.collector_id == "dns-chaos"
            assert obs.observation_type == ObservationType.DNS_RECORD
            assert obs.subject.identifier_type == IdentifierType.DOMAIN
            p = obs.structured_payload
            assert p["source"] == "projectdiscovery_chaos"
            assert p["seed_domain"] == "example.com"
            assert "subdomain_label" in p


class TestDnsChaosEmptySubdomains:
    """Test 2: Domain exists in dataset but no subdomains returned."""

    async def test_no_subdomains_yields_nothing(self) -> None:
        collector = DnsChaosCollector(_config())

        async def mock_fetch(url: str) -> list[str]:
            return []

        collector._fetch_subdomains = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="empty.example.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []


class TestDnsChaosNotFound:
    """Test 3: Domain not in Chaos dataset (404)."""

    async def test_404_yields_nothing(self) -> None:
        collector = DnsChaosCollector(_config())

        async def mock_fetch(url: str) -> list[str]:
            resp = _mock_response(status_code=404, text="Not Found")
            raise httpx.HTTPStatusError(
                "Not Found", request=resp.request, response=resp
            )

        collector._fetch_subdomains = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="unknown.example.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []


class TestDnsChaosAccessDenied:
    """Test 4: Access denied (403) -- graceful degradation."""

    async def test_403_yields_nothing(self) -> None:
        collector = DnsChaosCollector(_config())

        async def mock_fetch(url: str) -> list[str]:
            resp = _mock_response(status_code=403, text="Forbidden")
            raise httpx.HTTPStatusError(
                "Forbidden", request=resp.request, response=resp
            )

        collector._fetch_subdomains = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="restricted.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []


class TestDnsChaosNonDomainSeed:
    """Test 5: Non-domain seeds are silently skipped."""

    async def test_ip_seed_skipped(self) -> None:
        collector = DnsChaosCollector(_config())
        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_organization_seed_skipped(self) -> None:
        collector = DnsChaosCollector(_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="ACME Corp")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_cidr_seed_skipped(self) -> None:
        collector = DnsChaosCollector(_config())
        seed = Seed(seed_type=SeedType.CIDR, value="192.0.2.0/24")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []


class TestDnsChaosHttpErrors:
    """Test 6: HTTP error handling."""

    async def test_connection_error_handled_gracefully(self) -> None:
        collector = DnsChaosCollector(_config())

        async def mock_fetch(url: str) -> list[str]:
            raise httpx.ConnectError("Connection refused")

        collector._fetch_subdomains = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="unreachable.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    async def test_server_error_re_raised(self) -> None:
        """5xx errors other than handled status codes should propagate."""
        collector = DnsChaosCollector(_config())

        async def mock_fetch(url: str) -> list[str]:
            resp = _mock_response(status_code=500, text="Server Error")
            raise httpx.HTTPStatusError(
                "Server Error", request=resp.request, response=resp
            )

        collector._fetch_subdomains = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="broken.com")
        with pytest.raises(httpx.HTTPStatusError):
            _ = [obs async for obs in collector.expand(seed)]


class TestDnsChaosHealthCheck:
    """Test 7: Health check success and failure."""

    async def test_health_check_success(self) -> None:
        collector = DnsChaosCollector(_config())
        mock_resp = _mock_response(status_code=200, json_data={"subdomains": []})

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "dns-chaos"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    async def test_health_check_failure(self) -> None:
        collector = DnsChaosCollector(_config())

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ConnectError("Connection refused")
            result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None


class TestDnsChaosResponseFormats:
    """Test 8: Response format variations."""

    async def test_dict_with_domain_key(self) -> None:
        """Standard format: {"domain": "...", "subdomains": [...]}"""
        collector = DnsChaosCollector(_config())

        async def mock_fetch(url: str) -> list[str]:
            return ["www", "api"]

        collector._fetch_subdomains = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="format1.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert len(observations) == 2

    async def test_dict_without_domain_key(self) -> None:
        """Format: {"subdomains": [...]}"""
        collector = DnsChaosCollector(_config())

        async def mock_fetch(url: str) -> list[str]:
            return ["mail"]

        collector._fetch_subdomains = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="format2.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert len(observations) == 1
        assert observations[0].subject.identifier_value == "mail.format2.com"


class TestDnsChaosApiKey:
    """Test 9: API key credential handling."""

    def test_no_api_key_returns_empty_headers(self) -> None:
        collector = DnsChaosCollector(_config())
        assert collector._get_auth_headers() == {}

    def test_api_key_returns_authorization_header(self) -> None:
        creds = {
            "chaos_api_key": CollectorCredential(
                name="chaos_api_key", secret_value="test-key-12345"
            )
        }
        collector = DnsChaosCollector(_config(credentials=creds))
        headers = collector._get_auth_headers()
        assert headers == {"Authorization": "test-key-12345"}

    def test_empty_api_key_returns_empty_headers(self) -> None:
        creds = {
            "chaos_api_key": CollectorCredential(name="chaos_api_key", secret_value="")
        }
        collector = DnsChaosCollector(_config(credentials=creds))
        assert collector._get_auth_headers() == {}


class TestDnsChaosSubdomainEdgeCases:
    """Test 11: Subdomain label edge cases."""

    async def test_at_sign_label_skipped(self) -> None:
        """The '@' label (apex record) should be skipped."""
        collector = DnsChaosCollector(_config())

        async def mock_fetch(url: str) -> list[str]:
            return ["@", "www", ""]

        collector._fetch_subdomains = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="apex.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert len(observations) == 1
        assert observations[0].subject.identifier_value == "www.apex.com"

    async def test_empty_label_skipped(self) -> None:
        """Empty string labels should be skipped."""
        collector = DnsChaosCollector(_config())

        async def mock_fetch(url: str) -> list[str]:
            return ["", "valid"]

        collector._fetch_subdomains = mock_fetch  # type: ignore[assignment]

        seed = Seed(seed_type=SeedType.DOMAIN, value="empty.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert len(observations) == 1
        assert observations[0].subject.identifier_value == "valid.empty.com"


# === Registration tests ======================================================


class TestDnsChaosRegistration:
    """Test 10: Verify the collector registers correctly."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("dns-chaos")
        cls = DEFAULT_REGISTRY.get("dns-chaos")
        assert cls is DnsChaosCollector

    def test_metadata_correct(self) -> None:
        assert DnsChaosCollector.collector_id == "dns-chaos"
        assert DnsChaosCollector.collector_version == "0.1.0"
        assert DnsChaosCollector.tier == CollectorTier.TIER_1
        assert DnsChaosCollector.requires_credentials is False
