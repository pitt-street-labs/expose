"""Tests for the scan-shodan collector (Tier 1).

Exercises Shodan API logic via ``respx`` mocks — no live network calls.
Coverage:

 1.  Collector ID, tier, requires_credentials correct
 2.  IP seed → host lookup → PORT_SCAN_RESULT + SCANNER_HOST observations
 3.  Domain seed → DNS resolve + host lookup → observations
 4.  Domain seed with no resolution → graceful empty
 5.  No credentials → empty list (graceful degradation)
 6.  HTTP 401 → graceful degradation
 7.  HTTP 429 → graceful degradation
 8.  HTTP 500 → graceful degradation
 9.  Connection error → graceful degradation
10.  Non-matching seed types skipped
11.  Observation field correctness (_collector_id, source_url, source)
12.  Vulnerability (CVE) data parsed
13.  SSL certificate info parsed
14.  Host summary includes ISP, org, hostnames
15.  Health check: success
16.  Health check: failure (no credentials)
17.  Health check: failure (API error)
18.  Registration in default registry
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorCredential,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.scan_shodan import ShodanScanCollector
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000c0d01")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000c0d02")

_SHODAN_BASE = "https://api.shodan.io"


def _config(
    api_key: str | None = None,
) -> CollectorConfig:
    creds: dict[str, CollectorCredential] = {}
    if api_key:
        creds["shodan_api_key"] = CollectorCredential(name="shodan_api_key", secret_value=api_key)
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
        credentials=creds,
    )


async def _collect(
    seed: Seed,
    config: CollectorConfig | None = None,
) -> list[Observation]:
    cfg = config or _config(api_key="test-key")
    collector = ShodanScanCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === Canned API responses =====================================================

_HOST_RESPONSE: dict[str, Any] = {
    "ip_str": "93.184.216.34",
    "ports": [80, 443],
    "os": "Linux",
    "isp": "Edgecast",
    "org": "Verizon Digital Media",
    "hostnames": ["example.com"],
    "vulns": ["CVE-2021-44228", "CVE-2023-12345"],
    "last_update": "2025-06-01T00:00:00Z",
    "data": [
        {
            "port": 80,
            "transport": "tcp",
            "product": "nginx",
            "data": "HTTP/1.1 200 OK\r\nServer: nginx",
            "_shodan": {"module": "http"},
        },
        {
            "port": 443,
            "transport": "tcp",
            "product": "nginx",
            "data": "HTTP/1.1 200 OK",
            "_shodan": {"module": "https"},
            "vulns": {"CVE-2021-44228": {"verified": True}},
            "ssl": {
                "cert": {
                    "subject": {"CN": "example.com"},
                    "issuer": {"CN": "DigiCert"},
                    "serial": 12345,
                    "fingerprint": {"sha256": "abcdef"},
                    "expires": "2026-01-01",
                },
            },
        },
    ],
}

_DNS_RESOLVE_RESPONSE: dict[str, Any] = {
    "example.com": "93.184.216.34",
}

_DNS_RESOLVE_EMPTY: dict[str, Any] = {
    "example.com": None,
}


# ==============================================================================
# 1. Collector metadata
# ==============================================================================
class TestCollectorMetadata:
    def test_collector_id(self) -> None:
        assert ShodanScanCollector.collector_id == "scan-shodan"

    def test_collector_version(self) -> None:
        assert ShodanScanCollector.collector_version == "0.1.0"

    def test_tier_is_tier_1(self) -> None:
        assert ShodanScanCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials(self) -> None:
        assert ShodanScanCollector.requires_credentials is True

    def test_is_subclass_of_collector_abc(self) -> None:
        assert issubclass(ShodanScanCollector, Collector)


# ==============================================================================
# 2. IP seed → host lookup
# ==============================================================================
class TestIpSeedHostLookup:
    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_yields_observations(self) -> None:
        """IP seed triggers direct host lookup and yields observations."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        # 2 services + 1 host summary = 3.
        assert len(observations) == 3

    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_port_scan_results(self) -> None:
        """IP seed yields PORT_SCAN_RESULT for each service."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        port_obs = [
            o for o in observations if o.observation_type == ObservationType.PORT_SCAN_RESULT
        ]
        assert len(port_obs) == 2
        ports = {o.structured_payload["port"] for o in port_obs}
        assert ports == {80, 443}

    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_subject_is_ip(self) -> None:
        """IP seed observations have IP identifier type."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.subject.identifier_type == IdentifierType.IP
            assert obs.subject.identifier_value == "93.184.216.34"


# ==============================================================================
# 3. Domain seed → DNS resolve + host lookup
# ==============================================================================
class TestDomainSeed:
    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_seed_resolves_and_queries(self) -> None:
        """Domain seed resolves to IP, then performs host lookup."""
        respx.get(f"{_SHODAN_BASE}/dns/resolve").mock(
            return_value=httpx.Response(200, json=_DNS_RESOLVE_RESPONSE)
        )
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        # 2 services + 1 host summary = 3.
        assert len(observations) == 3

    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_seed_subject_is_domain(self) -> None:
        """Domain seed observations have DOMAIN identifier type."""
        respx.get(f"{_SHODAN_BASE}/dns/resolve").mock(
            return_value=httpx.Response(200, json=_DNS_RESOLVE_RESPONSE)
        )
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.subject.identifier_type == IdentifierType.DOMAIN
            assert obs.subject.identifier_value == "example.com"

    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_resolved_ip_in_payload(self) -> None:
        """Domain seed carries resolved_ip in payload."""
        respx.get(f"{_SHODAN_BASE}/dns/resolve").mock(
            return_value=httpx.Response(200, json=_DNS_RESOLVE_RESPONSE)
        )
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.structured_payload.get("resolved_ip") == "93.184.216.34"


# ==============================================================================
# 4. Domain seed with no resolution
# ==============================================================================
class TestDomainNoResolution:
    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_no_ip_yields_nothing(self) -> None:
        """Domain that doesn't resolve yields nothing."""
        respx.get(f"{_SHODAN_BASE}/dns/resolve").mock(
            return_value=httpx.Response(200, json=_DNS_RESOLVE_EMPTY)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert observations == []


# ==============================================================================
# 5. No credentials → graceful degradation
# ==============================================================================
class TestNoCredentials:
    @pytest.mark.asyncio
    async def test_no_key_yields_nothing(self) -> None:
        """With no API key, expand yields nothing."""
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config()
        observations = await _collect(seed, cfg)
        assert observations == []


# ==============================================================================
# 6. HTTP 401 → graceful degradation
# ==============================================================================
class TestHttp401:
    @respx.mock
    @pytest.mark.asyncio
    async def test_401_yields_nothing(self) -> None:
        """Shodan 401 is caught gracefully."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/1.2.3.4").mock(
            return_value=httpx.Response(401, json={"error": "unauthorized"})
        )

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 7. HTTP 429 → graceful degradation
# ==============================================================================
class TestHttp429:
    @respx.mock
    @pytest.mark.asyncio
    async def test_429_yields_nothing(self) -> None:
        """Shodan 429 rate limit is caught gracefully."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/1.2.3.4").mock(
            return_value=httpx.Response(429, json={"error": "rate limit"})
        )

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 8. HTTP 500 → graceful degradation
# ==============================================================================
class TestHttp500:
    @respx.mock
    @pytest.mark.asyncio
    async def test_500_yields_nothing(self) -> None:
        """Shodan 500 is caught gracefully."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/1.2.3.4").mock(return_value=httpx.Response(500))

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 9. Connection error → graceful degradation
# ==============================================================================
class TestConnectionError:
    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_error_yields_nothing(self) -> None:
        """Network-level failure is caught gracefully."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/1.2.3.4").mock(
            side_effect=httpx.ConnectError("DNS failed")
        )

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_dns_resolve_error_yields_nothing(self) -> None:
        """DNS resolve failure for domain seed yields nothing."""
        respx.get(f"{_SHODAN_BASE}/dns/resolve").mock(side_effect=httpx.ConnectError("timeout"))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 10. Non-matching seed types skipped
# ==============================================================================
class TestSeedTypeFiltering:
    @pytest.mark.asyncio
    async def test_organization_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_cidr_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.CIDR, value="192.0.2.0/24")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_asn_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 11. Observation field correctness
# ==============================================================================
class TestObservationFields:
    @respx.mock
    @pytest.mark.asyncio
    async def test_collector_id_in_payload(self) -> None:
        """_collector_id is present in structured_payload."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.structured_payload["_collector_id"] == "scan-shodan"

    @respx.mock
    @pytest.mark.asyncio
    async def test_source_url_in_payload(self) -> None:
        """source_url is present in structured_payload."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert "source_url" in obs.structured_payload
            assert _SHODAN_BASE in obs.structured_payload["source_url"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_source_is_shodan(self) -> None:
        """source field is 'shodan'."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.structured_payload["source"] == "shodan"

    @respx.mock
    @pytest.mark.asyncio
    async def test_tenant_id_propagated(self) -> None:
        """Observation carries the configured tenant_id."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.tenant_id == TENANT_ID


# ==============================================================================
# 12. Vulnerability data parsed
# ==============================================================================
class TestVulnerabilityParsing:
    @respx.mock
    @pytest.mark.asyncio
    async def test_vulns_in_service_observation(self) -> None:
        """Service with vulns includes CVE list."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        https_obs = [
            o
            for o in observations
            if o.observation_type == ObservationType.PORT_SCAN_RESULT
            and o.structured_payload.get("port") == 443
        ]
        assert len(https_obs) == 1
        vulns = https_obs[0].structured_payload["vulns"]
        assert "CVE-2021-44228" in vulns

    @respx.mock
    @pytest.mark.asyncio
    async def test_vulns_in_host_summary(self) -> None:
        """Host summary includes top-level vuln list."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        host_obs = [o for o in observations if o.observation_type == ObservationType.SCANNER_HOST]
        assert len(host_obs) == 1
        vulns = host_obs[0].structured_payload["vulns"]
        assert "CVE-2021-44228" in vulns
        assert "CVE-2023-12345" in vulns


# ==============================================================================
# 13. SSL certificate info parsed
# ==============================================================================
class TestSslCertParsing:
    @respx.mock
    @pytest.mark.asyncio
    async def test_ssl_info_in_https_service(self) -> None:
        """HTTPS service includes SSL certificate data."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        https_obs = [
            o
            for o in observations
            if o.observation_type == ObservationType.PORT_SCAN_RESULT
            and o.structured_payload.get("port") == 443
        ]
        assert len(https_obs) == 1
        ssl = https_obs[0].structured_payload.get("ssl", {})
        assert ssl["subject"] == {"CN": "example.com"}
        assert ssl["issuer"] == {"CN": "DigiCert"}


# ==============================================================================
# 14. Host summary includes ISP, org, hostnames
# ==============================================================================
class TestHostSummary:
    @respx.mock
    @pytest.mark.asyncio
    async def test_host_summary_fields(self) -> None:
        """SCANNER_HOST observation includes ISP, org, hostnames, OS."""
        respx.get(f"{_SHODAN_BASE}/shodan/host/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        host_obs = [o for o in observations if o.observation_type == ObservationType.SCANNER_HOST]
        assert len(host_obs) == 1
        payload = host_obs[0].structured_payload
        assert payload["os"] == "Linux"
        assert payload["isp"] == "Edgecast"
        assert payload["org"] == "Verizon Digital Media"
        assert "example.com" in payload["hostnames"]
        assert payload["ports"] == [80, 443]


# ==============================================================================
# 15. Health check: success
# ==============================================================================
class TestHealthCheckSuccess:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Successful API call returns SUCCESS status."""
        respx.get(f"{_SHODAN_BASE}/api-info").mock(
            return_value=httpx.Response(200, json={"query_credits": 100})
        )

        collector = ShodanScanCollector(_config(api_key="test-key"))
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "scan-shodan"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0


# ==============================================================================
# 16. Health check: failure (no credentials)
# ==============================================================================
class TestHealthCheckNoCreds:
    @pytest.mark.asyncio
    async def test_health_check_no_key(self) -> None:
        """No API key → FAILURE health check."""
        collector = ShodanScanCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "not configured" in result.error_message


# ==============================================================================
# 17. Health check: failure (API error)
# ==============================================================================
class TestHealthCheckApiError:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_api_error(self) -> None:
        """API error during health check returns FAILURE."""
        respx.get(f"{_SHODAN_BASE}/api-info").mock(return_value=httpx.Response(500))

        collector = ShodanScanCollector(_config(api_key="test-key"))
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_connection_error(self) -> None:
        """Connection error during health check returns FAILURE."""
        respx.get(f"{_SHODAN_BASE}/api-info").mock(side_effect=httpx.ConnectError("timeout"))

        collector = ShodanScanCollector(_config(api_key="test-key"))
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None


# ==============================================================================
# 18. Registration in default registry
# ==============================================================================
class TestRegistration:
    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("scan-shodan")
        cls = DEFAULT_REGISTRY.get("scan-shodan")
        assert cls is ShodanScanCollector
