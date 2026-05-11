"""Tests for the scan-censys collector (Tier 1).

Exercises Censys Search API v2 logic via ``respx`` mocks — no live network
calls. Coverage:

 1.  Collector ID, tier, requires_credentials correct
 2.  IP seed → host lookup → PORT_SCAN_RESULT + SCANNER_HOST observations
 3.  Domain seed → certificate search → observations
 4.  No credentials → empty list (graceful degradation)
 5.  Missing API ID only → graceful degradation
 6.  Missing API secret only → graceful degradation
 7.  HTTP 401 → graceful degradation
 8.  HTTP 429 → graceful degradation
 9.  HTTP 500 → graceful degradation
10.  Connection error → graceful degradation
11.  Non-matching seed types skipped
12.  Observation field correctness (_collector_id, source_url, source)
13.  TLS certificate info parsed into observation
14.  Health check: success
15.  Health check: failure (no credentials)
16.  Health check: failure (API error)
17.  Registration in default registry
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
from expose.collectors.builtin.scan_censys import CensysScanCollector
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000c0d01")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000c0d02")

_CENSYS_BASE = "https://search.censys.io/api/v2"


def _config(
    api_id: str | None = None,
    api_sec: str | None = None,
) -> CollectorConfig:
    creds: dict[str, CollectorCredential] = {}
    if api_id:
        creds["censys_api_id"] = CollectorCredential(name="censys_api_id", secret_value=api_id)
    if api_sec:
        creds["censys_api_secret"] = CollectorCredential(
            name="censys_api_secret", secret_value=api_sec
        )
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
    cfg = config or _config(api_id="test-id", api_sec="test-sec")
    collector = CensysScanCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === Canned API responses =====================================================

_HOST_RESPONSE = {
    "result": {
        "ip": "93.184.216.34",
        "services": [
            {
                "port": 80,
                "service_name": "HTTP",
                "transport_protocol": "TCP",
                "banner": "HTTP/1.1 200 OK",
            },
            {
                "port": 443,
                "service_name": "HTTPS",
                "transport_protocol": "TCP",
                "banner": "",
                "tls": {
                    "certificates": {
                        "leaf_data": {
                            "subject_dn": "CN=example.com",
                            "issuer_dn": "CN=DigiCert",
                            "names": ["example.com", "www.example.com"],
                            "fingerprint": "abcdef1234567890",
                        },
                    },
                },
            },
        ],
        "operating_system": {"product": "Linux", "version": "5.x"},
        "location": {"country": "US", "city": "Los Angeles"},
        "autonomous_system": {
            "asn": 15169,
            "name": "EDGECAST",
            "bgp_prefix": "93.184.216.0/24",
        },
        "last_updated_at": "2025-06-01T00:00:00Z",
    },
}

_SEARCH_RESPONSE = {
    "result": {
        "hits": [
            {
                "ip": "93.184.216.34",
                "services": [
                    {
                        "port": 443,
                        "service_name": "HTTPS",
                        "transport_protocol": "TCP",
                        "banner": "",
                    },
                ],
                "operating_system": {"product": "Linux"},
                "location": {"country": "US", "city": "Los Angeles"},
                "autonomous_system": {"asn": 15169, "name": "EDGECAST"},
            },
        ],
    },
}

_EMPTY_SEARCH_RESPONSE: dict[str, Any] = {"result": {"hits": []}}


# ==============================================================================
# 1. Collector metadata
# ==============================================================================
class TestCollectorMetadata:
    def test_collector_id(self) -> None:
        assert CensysScanCollector.collector_id == "scan-censys"

    def test_collector_version(self) -> None:
        assert CensysScanCollector.collector_version == "0.1.0"

    def test_tier_is_tier_1(self) -> None:
        assert CensysScanCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials(self) -> None:
        assert CensysScanCollector.requires_credentials is True

    def test_is_subclass_of_collector_abc(self) -> None:
        assert issubclass(CensysScanCollector, Collector)


# ==============================================================================
# 2. IP seed → host lookup
# ==============================================================================
class TestIpSeedHostLookup:
    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_yields_observations(self) -> None:
        """IP seed triggers direct host lookup and yields observations."""
        respx.get(f"{_CENSYS_BASE}/hosts/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        # 2 services + 1 host summary = 3 observations.
        assert len(observations) == 3

    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_port_scan_results(self) -> None:
        """IP seed yields PORT_SCAN_RESULT for each service."""
        respx.get(f"{_CENSYS_BASE}/hosts/93.184.216.34").mock(
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
    async def test_ip_seed_scanner_host_summary(self) -> None:
        """IP seed yields a SCANNER_HOST summary observation."""
        respx.get(f"{_CENSYS_BASE}/hosts/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        host_obs = [o for o in observations if o.observation_type == ObservationType.SCANNER_HOST]
        assert len(host_obs) == 1
        payload = host_obs[0].structured_payload
        assert payload["ip"] == "93.184.216.34"
        assert 80 in payload["ports"]
        assert 443 in payload["ports"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_subject_is_ip(self) -> None:
        """IP seed observations have IP identifier type."""
        respx.get(f"{_CENSYS_BASE}/hosts/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.subject.identifier_type == IdentifierType.IP
            assert obs.subject.identifier_value == "93.184.216.34"


# ==============================================================================
# 3. Domain seed → certificate search
# ==============================================================================
class TestDomainSeedSearch:
    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_seed_yields_observations(self) -> None:
        """Domain seed searches by TLS certificate name."""
        respx.get(
            f"{_CENSYS_BASE}/hosts/search",
        ).mock(return_value=httpx.Response(200, json=_SEARCH_RESPONSE))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        # 1 service + 1 host summary = 2 observations.
        assert len(observations) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_seed_subject_is_domain(self) -> None:
        """Domain seed observations have DOMAIN identifier type."""
        respx.get(
            f"{_CENSYS_BASE}/hosts/search",
        ).mock(return_value=httpx.Response(200, json=_SEARCH_RESPONSE))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.subject.identifier_type == IdentifierType.DOMAIN
            assert obs.subject.identifier_value == "example.com"

    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_search_empty_results(self) -> None:
        """Domain search with no hits yields no observations."""
        respx.get(
            f"{_CENSYS_BASE}/hosts/search",
        ).mock(return_value=httpx.Response(200, json=_EMPTY_SEARCH_RESPONSE))

        seed = Seed(seed_type=SeedType.DOMAIN, value="noresults.example.com")
        observations = await _collect(seed)

        assert observations == []


# ==============================================================================
# 4. No credentials → graceful degradation
# ==============================================================================
class TestNoCredentials:
    @pytest.mark.asyncio
    async def test_no_creds_yields_nothing(self) -> None:
        """With no API credentials, expand yields nothing."""
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config()  # No credentials.
        observations = await _collect(seed, cfg)
        assert observations == []


# ==============================================================================
# 5. Missing API ID only
# ==============================================================================
class TestMissingApiId:
    @pytest.mark.asyncio
    async def test_no_api_id_yields_nothing(self) -> None:
        """With only api_secret, expand yields nothing."""
        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        cfg = _config(api_sec="sec-only")
        observations = await _collect(seed, cfg)
        assert observations == []


# ==============================================================================
# 6. Missing API secret only
# ==============================================================================
class TestMissingApiSecret:
    @pytest.mark.asyncio
    async def test_no_api_secret_yields_nothing(self) -> None:
        """With only api_id, expand yields nothing."""
        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        cfg = _config(api_id="id-only")
        observations = await _collect(seed, cfg)
        assert observations == []


# ==============================================================================
# 7. HTTP 401 → graceful degradation
# ==============================================================================
class TestHttp401:
    @respx.mock
    @pytest.mark.asyncio
    async def test_401_yields_nothing(self) -> None:
        """Censys 401 is caught gracefully."""
        respx.get(f"{_CENSYS_BASE}/hosts/1.2.3.4").mock(
            return_value=httpx.Response(401, json={"error": "unauthorized"})
        )

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 8. HTTP 429 → graceful degradation
# ==============================================================================
class TestHttp429:
    @respx.mock
    @pytest.mark.asyncio
    async def test_429_yields_nothing(self) -> None:
        """Censys 429 rate limit is caught gracefully."""
        respx.get(f"{_CENSYS_BASE}/hosts/1.2.3.4").mock(
            return_value=httpx.Response(429, json={"error": "rate limit"})
        )

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 9. HTTP 500 → graceful degradation
# ==============================================================================
class TestHttp500:
    @respx.mock
    @pytest.mark.asyncio
    async def test_500_yields_nothing(self) -> None:
        """Censys 500 is caught gracefully."""
        respx.get(f"{_CENSYS_BASE}/hosts/1.2.3.4").mock(return_value=httpx.Response(500))

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 10. Connection error → graceful degradation
# ==============================================================================
class TestConnectionError:
    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_error_yields_nothing(self) -> None:
        """Network-level failure is caught gracefully."""
        respx.get(f"{_CENSYS_BASE}/hosts/1.2.3.4").mock(
            side_effect=httpx.ConnectError("DNS failed")
        )

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 11. Non-matching seed types skipped
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
# 12. Observation field correctness
# ==============================================================================
class TestObservationFields:
    @respx.mock
    @pytest.mark.asyncio
    async def test_collector_id_in_payload(self) -> None:
        """_collector_id is present in structured_payload."""
        respx.get(f"{_CENSYS_BASE}/hosts/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.structured_payload["_collector_id"] == "scan-censys"

    @respx.mock
    @pytest.mark.asyncio
    async def test_source_url_in_payload(self) -> None:
        """source_url is present in structured_payload."""
        respx.get(f"{_CENSYS_BASE}/hosts/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert "source_url" in obs.structured_payload
            assert _CENSYS_BASE in obs.structured_payload["source_url"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_source_is_censys(self) -> None:
        """source field is 'censys'."""
        respx.get(f"{_CENSYS_BASE}/hosts/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.structured_payload["source"] == "censys"

    @respx.mock
    @pytest.mark.asyncio
    async def test_collector_id_on_observation(self) -> None:
        """Observation.collector_id matches class attribute."""
        respx.get(f"{_CENSYS_BASE}/hosts/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.collector_id == "scan-censys"

    @respx.mock
    @pytest.mark.asyncio
    async def test_tenant_id_propagated(self) -> None:
        """Observation carries the configured tenant_id."""
        respx.get(f"{_CENSYS_BASE}/hosts/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_HOST_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.tenant_id == TENANT_ID


# ==============================================================================
# 13. TLS certificate info parsed
# ==============================================================================
class TestTlsCertParsing:
    @respx.mock
    @pytest.mark.asyncio
    async def test_tls_info_in_https_service(self) -> None:
        """HTTPS service includes TLS certificate data."""
        respx.get(f"{_CENSYS_BASE}/hosts/93.184.216.34").mock(
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
        tls = https_obs[0].structured_payload.get("tls", {})
        assert tls["subject_dn"] == "CN=example.com"
        assert tls["issuer_dn"] == "CN=DigiCert"
        assert "example.com" in tls["names"]


# ==============================================================================
# 14. Health check: success
# ==============================================================================
class TestHealthCheckSuccess:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Successful API call returns SUCCESS status."""
        respx.get(f"{_CENSYS_BASE}/hosts/search").mock(
            return_value=httpx.Response(200, json={"result": {"hits": []}})
        )

        collector = CensysScanCollector(_config(api_id="test-id", api_sec="test-sec"))
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "scan-censys"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0


# ==============================================================================
# 15. Health check: failure (no credentials)
# ==============================================================================
class TestHealthCheckNoCreds:
    @pytest.mark.asyncio
    async def test_health_check_no_creds(self) -> None:
        """No credentials → FAILURE health check."""
        collector = CensysScanCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "not configured" in result.error_message


# ==============================================================================
# 16. Health check: failure (API error)
# ==============================================================================
class TestHealthCheckApiError:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_api_error(self) -> None:
        """API error during health check returns FAILURE."""
        respx.get(f"{_CENSYS_BASE}/hosts/search").mock(return_value=httpx.Response(500))

        collector = CensysScanCollector(_config(api_id="test-id", api_sec="test-sec"))
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_connection_error(self) -> None:
        """Connection error during health check returns FAILURE."""
        respx.get(f"{_CENSYS_BASE}/hosts/search").mock(side_effect=httpx.ConnectError("timeout"))

        collector = CensysScanCollector(_config(api_id="test-id", api_sec="test-sec"))
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None


# ==============================================================================
# 17. Registration in default registry
# ==============================================================================
class TestRegistration:
    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("scan-censys")
        cls = DEFAULT_REGISTRY.get("scan-censys")
        assert cls is CensysScanCollector
