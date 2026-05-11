"""Tests for the scan-binaryedge collector (Tier 1).

Exercises BinaryEdge API v2 logic via ``respx`` mocks — no live network
calls. Coverage:

 1.  Collector ID, tier, requires_credentials correct
 2.  IP seed → host query → PORT_SCAN_RESULT + SCANNER_HOST observations
 3.  Domain seed → subdomain enumeration → DNS_RECORD observations
 4.  No credentials → empty list (graceful degradation)
 5.  HTTP 401 → graceful degradation
 6.  HTTP 429 → graceful degradation
 7.  HTTP 500 → graceful degradation
 8.  Connection error → graceful degradation
 9.  Non-matching seed types skipped
10.  Observation field correctness (_collector_id, source_url, source)
11.  Certificate info parsed
12.  Torrent activity parsed
13.  Subdomain seed_expansion flag
14.  Empty events list handled
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
from expose.collectors.builtin.scan_binaryedge import BinaryEdgeScanCollector
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000c0d01")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000c0d02")

_BE_BASE = "https://api.binaryedge.io/v2"


def _config(
    api_key: str | None = None,
) -> CollectorConfig:
    creds: dict[str, CollectorCredential] = {}
    if api_key:
        creds["binaryedge_api_key"] = CollectorCredential(
            name="binaryedge_api_key", secret_value=api_key
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
    cfg = config or _config(api_key="test-key")
    collector = BinaryEdgeScanCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === Canned API responses =====================================================

_IP_RESPONSE: dict[str, Any] = {
    "events": [
        {
            "port": 80,
            "results": [
                {
                    "target": {"ip": "93.184.216.34", "port": 80, "protocol": "tcp"},
                    "origin": {"type": "scan", "module": "http", "country": "US"},
                    "result": {
                        "data": {
                            "service": {"name": "http", "banner": "HTTP/1.1 200 OK"},
                        },
                    },
                },
            ],
        },
        {
            "port": 443,
            "results": [
                {
                    "target": {"ip": "93.184.216.34", "port": 443, "protocol": "tcp"},
                    "origin": {"type": "scan", "module": "https", "country": "US"},
                    "result": {
                        "data": {
                            "service": {"name": "https", "banner": ""},
                            "cert_info": {
                                "subject": {"CN": "example.com"},
                                "issuer": {"CN": "DigiCert"},
                                "not_before": "2024-01-01",
                                "not_after": "2026-01-01",
                            },
                        },
                    },
                },
            ],
        },
    ],
}

_IP_RESPONSE_WITH_TORRENT: dict[str, Any] = {
    "events": [
        {
            "port": 6881,
            "results": [
                {
                    "target": {"ip": "1.2.3.4", "port": 6881, "protocol": "tcp"},
                    "origin": {"type": "scan", "module": "torrent", "country": "US"},
                    "result": {
                        "data": {
                            "service": {"name": "bittorrent", "banner": ""},
                            "torrents": [
                                {"hash": "abc123", "name": "test-file.iso"},
                            ],
                        },
                    },
                },
            ],
        },
    ],
}

_SUBDOMAIN_RESPONSE: dict[str, Any] = {
    "events": [
        "www.example.com",
        "mail.example.com",
        "api.example.com",
        "dev.example.com",
    ],
}

_SUBDOMAIN_EMPTY: dict[str, Any] = {"events": []}

_IP_EMPTY: dict[str, Any] = {"events": []}


# ==============================================================================
# 1. Collector metadata
# ==============================================================================
class TestCollectorMetadata:
    def test_collector_id(self) -> None:
        assert BinaryEdgeScanCollector.collector_id == "scan-binaryedge"

    def test_collector_version(self) -> None:
        assert BinaryEdgeScanCollector.collector_version == "0.1.0"

    def test_tier_is_tier_1(self) -> None:
        assert BinaryEdgeScanCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials(self) -> None:
        assert BinaryEdgeScanCollector.requires_credentials is True

    def test_is_subclass_of_collector_abc(self) -> None:
        assert issubclass(BinaryEdgeScanCollector, Collector)


# ==============================================================================
# 2. IP seed → host query
# ==============================================================================
class TestIpSeedQuery:
    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_yields_observations(self) -> None:
        """IP seed queries host data and yields observations."""
        respx.get(f"{_BE_BASE}/query/ip/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_IP_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        # 2 scan results + 1 host summary = 3.
        assert len(observations) == 3

    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_port_scan_results(self) -> None:
        """IP seed yields PORT_SCAN_RESULT for each service."""
        respx.get(f"{_BE_BASE}/query/ip/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_IP_RESPONSE)
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
        respx.get(f"{_BE_BASE}/query/ip/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_IP_RESPONSE)
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
        respx.get(f"{_BE_BASE}/query/ip/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_IP_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.subject.identifier_type == IdentifierType.IP
            assert obs.subject.identifier_value == "93.184.216.34"


# ==============================================================================
# 3. Domain seed → subdomain enumeration
# ==============================================================================
class TestDomainSeedSubdomains:
    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_seed_yields_subdomain_observations(self) -> None:
        """Domain seed enumerates subdomains."""
        respx.get(f"{_BE_BASE}/query/domains/subdomain/example.com").mock(
            return_value=httpx.Response(200, json=_SUBDOMAIN_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert len(observations) == 4
        fqdns = {o.structured_payload["subdomain"] for o in observations}
        assert fqdns == {
            "www.example.com",
            "mail.example.com",
            "api.example.com",
            "dev.example.com",
        }

    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_subdomain_observation_type(self) -> None:
        """Subdomain observations are DNS_RECORD type."""
        respx.get(f"{_BE_BASE}/query/domains/subdomain/example.com").mock(
            return_value=httpx.Response(200, json=_SUBDOMAIN_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.observation_type == ObservationType.DNS_RECORD

    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_subdomain_identifier_type(self) -> None:
        """Subdomain observations have SUBDOMAIN identifier type."""
        respx.get(f"{_BE_BASE}/query/domains/subdomain/example.com").mock(
            return_value=httpx.Response(200, json=_SUBDOMAIN_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.subject.identifier_type == IdentifierType.SUBDOMAIN

    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_empty_subdomains(self) -> None:
        """Domain with no subdomains yields nothing."""
        respx.get(f"{_BE_BASE}/query/domains/subdomain/example.com").mock(
            return_value=httpx.Response(200, json=_SUBDOMAIN_EMPTY)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert observations == []


# ==============================================================================
# 4. No credentials → graceful degradation
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
# 5. HTTP 401 → graceful degradation
# ==============================================================================
class TestHttp401:
    @respx.mock
    @pytest.mark.asyncio
    async def test_401_yields_nothing(self) -> None:
        """BinaryEdge 401 is caught gracefully."""
        respx.get(f"{_BE_BASE}/query/ip/1.2.3.4").mock(
            return_value=httpx.Response(401, json={"message": "unauthorized"})
        )

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 6. HTTP 429 → graceful degradation
# ==============================================================================
class TestHttp429:
    @respx.mock
    @pytest.mark.asyncio
    async def test_429_yields_nothing(self) -> None:
        """BinaryEdge 429 rate limit is caught gracefully."""
        respx.get(f"{_BE_BASE}/query/ip/1.2.3.4").mock(
            return_value=httpx.Response(429, json={"message": "rate limit"})
        )

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 7. HTTP 500 → graceful degradation
# ==============================================================================
class TestHttp500:
    @respx.mock
    @pytest.mark.asyncio
    async def test_500_yields_nothing(self) -> None:
        """BinaryEdge 500 is caught gracefully."""
        respx.get(f"{_BE_BASE}/query/ip/1.2.3.4").mock(return_value=httpx.Response(500))

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 8. Connection error → graceful degradation
# ==============================================================================
class TestConnectionError:
    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_error_ip_yields_nothing(self) -> None:
        """Network-level failure on IP query is caught gracefully."""
        respx.get(f"{_BE_BASE}/query/ip/1.2.3.4").mock(side_effect=httpx.ConnectError("DNS failed"))

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_error_domain_yields_nothing(self) -> None:
        """Network-level failure on domain query is caught gracefully."""
        respx.get(f"{_BE_BASE}/query/domains/subdomain/example.com").mock(
            side_effect=httpx.ConnectError("DNS failed")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 9. Non-matching seed types skipped
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
# 10. Observation field correctness
# ==============================================================================
class TestObservationFields:
    @respx.mock
    @pytest.mark.asyncio
    async def test_collector_id_in_payload(self) -> None:
        """_collector_id is present in structured_payload."""
        respx.get(f"{_BE_BASE}/query/ip/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_IP_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.structured_payload["_collector_id"] == "scan-binaryedge"

    @respx.mock
    @pytest.mark.asyncio
    async def test_source_url_in_payload(self) -> None:
        """source_url is present in structured_payload."""
        respx.get(f"{_BE_BASE}/query/ip/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_IP_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert "source_url" in obs.structured_payload
            assert _BE_BASE in obs.structured_payload["source_url"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_source_is_binaryedge(self) -> None:
        """source field is 'binaryedge'."""
        respx.get(f"{_BE_BASE}/query/ip/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_IP_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.structured_payload["source"] == "binaryedge"

    @respx.mock
    @pytest.mark.asyncio
    async def test_tenant_id_propagated(self) -> None:
        """Observation carries the configured tenant_id."""
        respx.get(f"{_BE_BASE}/query/ip/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_IP_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.tenant_id == TENANT_ID


# ==============================================================================
# 11. Certificate info parsed
# ==============================================================================
class TestCertParsing:
    @respx.mock
    @pytest.mark.asyncio
    async def test_cert_info_in_https_service(self) -> None:
        """HTTPS service includes certificate data."""
        respx.get(f"{_BE_BASE}/query/ip/93.184.216.34").mock(
            return_value=httpx.Response(200, json=_IP_RESPONSE)
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
        cert = https_obs[0].structured_payload.get("cert_info", {})
        assert cert["subject"] == {"CN": "example.com"}
        assert cert["issuer"] == {"CN": "DigiCert"}
        assert cert["not_after"] == "2026-01-01"


# ==============================================================================
# 12. Torrent activity parsed
# ==============================================================================
class TestTorrentParsing:
    @respx.mock
    @pytest.mark.asyncio
    async def test_torrent_data_in_observation(self) -> None:
        """Torrent activity is included in observation payload."""
        respx.get(f"{_BE_BASE}/query/ip/1.2.3.4").mock(
            return_value=httpx.Response(200, json=_IP_RESPONSE_WITH_TORRENT)
        )

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)

        port_obs = [
            o for o in observations if o.observation_type == ObservationType.PORT_SCAN_RESULT
        ]
        assert len(port_obs) == 1
        torrents = port_obs[0].structured_payload.get("torrents", [])
        assert len(torrents) == 1
        assert torrents[0]["hash"] == "abc123"


# ==============================================================================
# 13. Subdomain seed_expansion flag
# ==============================================================================
class TestSubdomainSeedExpansion:
    @respx.mock
    @pytest.mark.asyncio
    async def test_subdomain_seed_expansion_flag(self) -> None:
        """Subdomain observations carry seed_expansion=True."""
        respx.get(f"{_BE_BASE}/query/domains/subdomain/example.com").mock(
            return_value=httpx.Response(
                200,
                json={"events": ["www.example.com"]},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["seed_expansion"] is True
        assert observations[0].structured_payload["parent_domain"] == "example.com"


# ==============================================================================
# 14. Empty events list handled
# ==============================================================================
class TestEmptyEvents:
    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_empty_events_yields_summary_only(self) -> None:
        """IP with no events still yields a host summary."""
        respx.get(f"{_BE_BASE}/query/ip/1.2.3.4").mock(
            return_value=httpx.Response(200, json=_IP_EMPTY)
        )

        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)

        # Just the host summary observation.
        assert len(observations) == 1
        assert observations[0].observation_type == ObservationType.SCANNER_HOST
        assert observations[0].structured_payload["ports"] == []


# ==============================================================================
# 15. Health check: success
# ==============================================================================
class TestHealthCheckSuccess:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Successful API call returns SUCCESS status."""
        respx.get(f"{_BE_BASE}/user/subscription").mock(
            return_value=httpx.Response(
                200,
                json={"subscription": {"type": "free"}},
            )
        )

        collector = BinaryEdgeScanCollector(_config(api_key="test-key"))
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "scan-binaryedge"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0


# ==============================================================================
# 16. Health check: failure (no credentials)
# ==============================================================================
class TestHealthCheckNoCreds:
    @pytest.mark.asyncio
    async def test_health_check_no_key(self) -> None:
        """No API key → FAILURE health check."""
        collector = BinaryEdgeScanCollector(_config())
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
        respx.get(f"{_BE_BASE}/user/subscription").mock(return_value=httpx.Response(500))

        collector = BinaryEdgeScanCollector(_config(api_key="test-key"))
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_connection_error(self) -> None:
        """Connection error during health check returns FAILURE."""
        respx.get(f"{_BE_BASE}/user/subscription").mock(side_effect=httpx.ConnectError("timeout"))

        collector = BinaryEdgeScanCollector(_config(api_key="test-key"))
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None


# ==============================================================================
# 18. Registration in default registry
# ==============================================================================
class TestRegistration:
    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("scan-binaryedge")
        cls = DEFAULT_REGISTRY.get("scan-binaryedge")
        assert cls is BinaryEdgeScanCollector
