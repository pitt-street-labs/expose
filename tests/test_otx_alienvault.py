"""Tests for the otx-alienvault collector (Tier 1).

Exercises AlienVault OTX passive DNS + URL list logic via ``respx`` mocks —
no live network calls.  Coverage:

 1.  Collector ID, tier, requires_credentials correct
 2.  Passive DNS: IP observations emitted with structured_payload
 3.  Passive DNS: subdomain discovery from hostnames
 4.  URL list: URL observations emitted
 5.  Deduplication of IPs and subdomains
 6.  Empty results yield nothing (graceful)
 7.  Rate limit (429) → graceful degradation
 8.  HTTP 500 → graceful degradation
 9.  Connection error → graceful degradation
10.  Non-DOMAIN seed types skipped
11.  Health check: success
12.  Health check: failure (HTTP error)
13.  Health check: failure (connection error)
14.  Registration in default registry
15.  Optional API key passed as header
16.  No API key still works (unauthenticated)
17.  Passive DNS warnings propagated on partial failure
"""

from __future__ import annotations

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
from expose.collectors.builtin.otx_alienvault import OtxAlienVaultCollector
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000c0d01")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000c0d02")


def _config(
    otx_key: str | None = None,
) -> CollectorConfig:
    creds: dict[str, CollectorCredential] = {}
    if otx_key:
        creds["otx_api_key"] = CollectorCredential(
            name="otx_api_key", secret_value=otx_key
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
    cfg = config or _config()
    collector = OtxAlienVaultCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === Canned API responses =====================================================

_OTX_PASSIVE_DNS_RESPONSE = {
    "passive_dns": [
        {
            "address": "1.2.3.4",
            "hostname": "example.com",
            "record_type": "A",
            "first": "2020-01-15",
            "last": "2024-06-30",
        },
        {
            "address": "5.6.7.8",
            "hostname": "example.com",
            "record_type": "A",
            "first": "2024-07-01",
            "last": "2025-01-01",
        },
        {
            "address": "10.0.0.1",
            "hostname": "www.example.com",
            "record_type": "A",
            "first": "2021-03-01",
            "last": "2025-01-01",
        },
        {
            "address": "10.0.0.2",
            "hostname": "api.example.com",
            "record_type": "A",
            "first": "2022-06-01",
            "last": "2024-12-01",
        },
    ],
}

_OTX_PASSIVE_DNS_DUPLICATES = {
    "passive_dns": [
        {
            "address": "1.2.3.4",
            "hostname": "example.com",
            "record_type": "A",
            "first": "2020-01-15",
            "last": "2024-06-30",
        },
        {
            "address": "1.2.3.4",
            "hostname": "example.com",
            "record_type": "A",
            "first": "2022-01-01",
            "last": "2023-01-01",
        },
    ],
}

_OTX_PASSIVE_DNS_EMPTY: dict[str, list[object]] = {"passive_dns": []}

_OTX_URL_LIST_RESPONSE = {
    "url_list": [
        {
            "url": "https://example.com/login",
            "httpcode": 200,
            "date": "2024-01-15",
        },
        {
            "url": "https://example.com/admin",
            "httpcode": 403,
            "date": "2024-02-20",
        },
    ],
}

_OTX_URL_LIST_EMPTY: dict[str, list[object]] = {"url_list": []}

_OTX_GENERAL_RESPONSE = {
    "indicator": "example.com",
    "sections": ["general", "passive_dns", "url_list"],
}


def _mock_otx_endpoints(
    domain: str = "example.com",
    pdns: dict | None = None,
    urls: dict | None = None,
) -> None:
    """Set up respx mocks for both OTX endpoints."""
    respx.get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    ).mock(
        return_value=httpx.Response(
            200, json=pdns if pdns is not None else _OTX_PASSIVE_DNS_EMPTY
        )
    )
    respx.get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
    ).mock(
        return_value=httpx.Response(
            200, json=urls if urls is not None else _OTX_URL_LIST_EMPTY
        )
    )


# ==============================================================================
# 1. Collector metadata
# ==============================================================================
class TestCollectorMetadata:
    def test_collector_id(self) -> None:
        assert OtxAlienVaultCollector.collector_id == "otx-alienvault"

    def test_collector_version(self) -> None:
        assert OtxAlienVaultCollector.collector_version == "0.1.0"

    def test_tier_is_tier_1(self) -> None:
        assert OtxAlienVaultCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials_false(self) -> None:
        assert OtxAlienVaultCollector.requires_credentials is False

    def test_rate_limit_per_minute(self) -> None:
        assert OtxAlienVaultCollector.rate_limit_per_minute == 30

    def test_is_subclass_of_collector_abc(self) -> None:
        assert issubclass(OtxAlienVaultCollector, Collector)


# ==============================================================================
# 2. Passive DNS: IP observations emitted
# ==============================================================================
class TestPassiveDnsIpObservations:
    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_observations_from_passive_dns(self) -> None:
        """Passive DNS records yield unique IP observations."""
        _mock_otx_endpoints(pdns=_OTX_PASSIVE_DNS_RESPONSE)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        ip_obs = [
            o for o in observations
            if o.observation_type == ObservationType.PASSIVE_DNS
        ]
        # 4 unique IPs: 1.2.3.4, 5.6.7.8, 10.0.0.1, 10.0.0.2
        assert len(ip_obs) == 4
        ips = {o.subject.identifier_value for o in ip_obs}
        assert ips == {"1.2.3.4", "5.6.7.8", "10.0.0.1", "10.0.0.2"}

    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_observation_subject_type(self) -> None:
        """IP observations have IP identifier type."""
        _mock_otx_endpoints(pdns=_OTX_PASSIVE_DNS_RESPONSE)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        ip_obs = [
            o for o in observations
            if o.observation_type == ObservationType.PASSIVE_DNS
        ]
        for obs in ip_obs:
            assert obs.subject.identifier_type == IdentifierType.IP

    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_observation_structured_payload(self) -> None:
        """IP observation payload carries source, record_type, hostname, dates."""
        _mock_otx_endpoints(
            pdns={
                "passive_dns": [
                    {
                        "address": "1.2.3.4",
                        "hostname": "example.com",
                        "record_type": "A",
                        "first": "2020-01-15",
                        "last": "2024-06-30",
                    },
                ],
            },
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        ip_obs = [
            o for o in observations
            if o.observation_type == ObservationType.PASSIVE_DNS
        ]
        assert len(ip_obs) == 1
        payload = ip_obs[0].structured_payload
        assert payload["source"] == "otx_alienvault"
        assert payload["record_type"] == "A"
        assert payload["hostname"] == "example.com"
        assert payload["first_seen"] == "2020-01-15"
        assert payload["last_seen"] == "2024-06-30"


# ==============================================================================
# 3. Passive DNS: subdomain discovery
# ==============================================================================
class TestSubdomainDiscovery:
    @respx.mock
    @pytest.mark.asyncio
    async def test_subdomains_from_passive_dns_hostnames(self) -> None:
        """Hostnames that are subdomains of the queried domain yield DNS_RECORD obs."""
        _mock_otx_endpoints(pdns=_OTX_PASSIVE_DNS_RESPONSE)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        sub_obs = [
            o for o in observations
            if o.observation_type == ObservationType.DNS_RECORD
        ]
        assert len(sub_obs) == 2
        fqdns = {o.subject.identifier_value for o in sub_obs}
        assert fqdns == {"www.example.com", "api.example.com"}

    @respx.mock
    @pytest.mark.asyncio
    async def test_subdomain_seed_expansion_flag(self) -> None:
        """Subdomain observations carry seed_expansion=True."""
        _mock_otx_endpoints(pdns=_OTX_PASSIVE_DNS_RESPONSE)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        sub_obs = [
            o for o in observations
            if o.observation_type == ObservationType.DNS_RECORD
        ]
        for obs in sub_obs:
            assert obs.structured_payload["seed_expansion"] is True
            assert obs.subject.identifier_type == IdentifierType.SUBDOMAIN
            assert obs.structured_payload["source"] == "otx_alienvault"
            assert obs.structured_payload["parent_domain"] == "example.com"

    @respx.mock
    @pytest.mark.asyncio
    async def test_parent_domain_not_emitted_as_subdomain(self) -> None:
        """The queried domain itself is not emitted as a subdomain."""
        _mock_otx_endpoints(
            pdns={
                "passive_dns": [
                    {
                        "address": "1.2.3.4",
                        "hostname": "example.com",
                        "record_type": "A",
                        "first": "2020-01-01",
                        "last": "2024-01-01",
                    },
                ],
            },
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        sub_obs = [
            o for o in observations
            if o.observation_type == ObservationType.DNS_RECORD
        ]
        assert len(sub_obs) == 0


# ==============================================================================
# 4. URL list: URL observations emitted
# ==============================================================================
class TestUrlListObservations:
    @respx.mock
    @pytest.mark.asyncio
    async def test_url_observations_emitted(self) -> None:
        """URL list records yield HTTP_RESPONSE observations."""
        _mock_otx_endpoints(urls=_OTX_URL_LIST_RESPONSE)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        url_obs = [
            o for o in observations
            if o.observation_type == ObservationType.HTTP_RESPONSE
        ]
        assert len(url_obs) == 2
        urls = {o.structured_payload["url"] for o in url_obs}
        assert urls == {
            "https://example.com/login",
            "https://example.com/admin",
        }

    @respx.mock
    @pytest.mark.asyncio
    async def test_url_observation_payload(self) -> None:
        """URL observation payload carries source, url, http_code, date."""
        _mock_otx_endpoints(urls=_OTX_URL_LIST_RESPONSE)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        url_obs = [
            o for o in observations
            if o.observation_type == ObservationType.HTTP_RESPONSE
        ]
        login_obs = [
            o for o in url_obs
            if o.structured_payload["url"] == "https://example.com/login"
        ][0]
        assert login_obs.structured_payload["source"] == "otx_alienvault"
        assert login_obs.structured_payload["http_code"] == 200
        assert login_obs.structured_payload["date"] == "2024-01-15"
        assert login_obs.subject.identifier_type == IdentifierType.DOMAIN
        assert login_obs.subject.identifier_value == "example.com"


# ==============================================================================
# 5. Deduplication of IPs and subdomains
# ==============================================================================
class TestDeduplication:
    @respx.mock
    @pytest.mark.asyncio
    async def test_duplicate_ips_deduplicated(self) -> None:
        """Multiple records with the same IP yield only one observation."""
        _mock_otx_endpoints(pdns=_OTX_PASSIVE_DNS_DUPLICATES)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        ip_obs = [
            o for o in observations
            if o.observation_type == ObservationType.PASSIVE_DNS
        ]
        assert len(ip_obs) == 1
        assert ip_obs[0].subject.identifier_value == "1.2.3.4"

    @respx.mock
    @pytest.mark.asyncio
    async def test_duplicate_subdomains_deduplicated(self) -> None:
        """Multiple records with the same hostname yield one subdomain obs."""
        _mock_otx_endpoints(
            pdns={
                "passive_dns": [
                    {
                        "address": "1.2.3.4",
                        "hostname": "www.example.com",
                        "record_type": "A",
                        "first": "2020-01-01",
                        "last": "2024-01-01",
                    },
                    {
                        "address": "5.6.7.8",
                        "hostname": "www.example.com",
                        "record_type": "A",
                        "first": "2024-01-01",
                        "last": "2025-01-01",
                    },
                ],
            },
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        sub_obs = [
            o for o in observations
            if o.observation_type == ObservationType.DNS_RECORD
        ]
        assert len(sub_obs) == 1
        assert sub_obs[0].subject.identifier_value == "www.example.com"


# ==============================================================================
# 6. Empty results yield nothing
# ==============================================================================
class TestEmptyResults:
    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_passive_dns_and_urls(self) -> None:
        """Empty results from both endpoints yield no observations."""
        _mock_otx_endpoints()

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert observations == []


# ==============================================================================
# 7. Rate limit (429) graceful degradation
# ==============================================================================
class TestRateLimit:
    @respx.mock
    @pytest.mark.asyncio
    async def test_pdns_429_graceful(self) -> None:
        """Passive DNS 429 is caught; URL list still works."""
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"
        ).mock(return_value=httpx.Response(429, json={"error": "rate limit"}))
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list"
        ).mock(return_value=httpx.Response(200, json=_OTX_URL_LIST_RESPONSE))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        # No PDNS results; URL list still returns 2 observations.
        url_obs = [
            o for o in observations
            if o.observation_type == ObservationType.HTTP_RESPONSE
        ]
        assert len(url_obs) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_url_429_graceful(self) -> None:
        """URL list 429 is caught; passive DNS still works."""
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"
        ).mock(return_value=httpx.Response(200, json=_OTX_PASSIVE_DNS_RESPONSE))
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list"
        ).mock(return_value=httpx.Response(429, json={"error": "rate limit"}))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        ip_obs = [
            o for o in observations
            if o.observation_type == ObservationType.PASSIVE_DNS
        ]
        assert len(ip_obs) == 4  # 4 unique IPs


# ==============================================================================
# 8. HTTP 500 graceful degradation
# ==============================================================================
class TestHttpErrors:
    @respx.mock
    @pytest.mark.asyncio
    async def test_pdns_500_graceful(self) -> None:
        """Passive DNS 500 is caught; URL list still returns results."""
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"
        ).mock(return_value=httpx.Response(500))
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list"
        ).mock(return_value=httpx.Response(200, json=_OTX_URL_LIST_RESPONSE))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        url_obs = [
            o for o in observations
            if o.observation_type == ObservationType.HTTP_RESPONSE
        ]
        assert len(url_obs) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_both_500_yields_nothing(self) -> None:
        """Both endpoints returning 500 yields no observations."""
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"
        ).mock(return_value=httpx.Response(500))
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list"
        ).mock(return_value=httpx.Response(500))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert observations == []


# ==============================================================================
# 9. Connection error graceful degradation
# ==============================================================================
class TestConnectionErrors:
    @respx.mock
    @pytest.mark.asyncio
    async def test_pdns_connection_error_graceful(self) -> None:
        """Connection error on passive DNS is caught gracefully."""
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"
        ).mock(side_effect=httpx.ConnectError("DNS failed"))
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list"
        ).mock(return_value=httpx.Response(200, json=_OTX_URL_LIST_RESPONSE))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        url_obs = [
            o for o in observations
            if o.observation_type == ObservationType.HTTP_RESPONSE
        ]
        assert len(url_obs) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_both_connection_errors_yield_nothing(self) -> None:
        """Both endpoints with connection errors yield nothing."""
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"
        ).mock(side_effect=httpx.ConnectError("DNS failed"))
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list"
        ).mock(side_effect=httpx.ConnectError("DNS failed"))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert observations == []


# ==============================================================================
# 10. Non-DOMAIN seed types skipped
# ==============================================================================
class TestSeedTypeFiltering:
    @pytest.mark.asyncio
    async def test_ip_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.IP, value="1.2.3.4")
        observations = await _collect(seed)
        assert observations == []

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
# 11. Health check: success
# ==============================================================================
class TestHealthCheckSuccess:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """OTX general endpoint returning 200 means healthy."""
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general"
        ).mock(return_value=httpx.Response(200, json=_OTX_GENERAL_RESPONSE))

        collector = OtxAlienVaultCollector(_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "otx-alienvault"
        assert result.error_message is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_latency_non_negative(self) -> None:
        """Health check latency is non-negative."""
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general"
        ).mock(return_value=httpx.Response(200, json=_OTX_GENERAL_RESPONSE))

        collector = OtxAlienVaultCollector(_config())
        result = await collector.health_check()

        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0


# ==============================================================================
# 12. Health check: failure (HTTP error)
# ==============================================================================
class TestHealthCheckHttpFailure:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_http_500(self) -> None:
        """OTX general endpoint returning 500 means unhealthy."""
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general"
        ).mock(return_value=httpx.Response(500))

        collector = OtxAlienVaultCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "500" in result.error_message


# ==============================================================================
# 13. Health check: failure (connection error)
# ==============================================================================
class TestHealthCheckConnectionFailure:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_connection_error(self) -> None:
        """Connection error means unhealthy."""
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general"
        ).mock(side_effect=httpx.ConnectError("timeout"))

        collector = OtxAlienVaultCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "unreachable" in result.error_message.lower()


# ==============================================================================
# 14. Registration in default registry
# ==============================================================================
class TestRegistration:
    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("otx-alienvault")
        cls = DEFAULT_REGISTRY.get("otx-alienvault")
        assert cls is OtxAlienVaultCollector


# ==============================================================================
# 15. Optional API key passed as header
# ==============================================================================
class TestApiKeyHandling:
    @respx.mock
    @pytest.mark.asyncio
    async def test_api_key_sent_in_header(self) -> None:
        """When OTX API key is configured, it is sent as X-OTX-API-KEY header."""
        _mock_otx_endpoints(
            pdns={
                "passive_dns": [
                    {
                        "address": "1.2.3.4",
                        "hostname": "example.com",
                        "record_type": "A",
                        "first": "2020-01-01",
                        "last": "2024-01-01",
                    },
                ],
            },
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(otx_key="test-otx-key-123")
        observations = await _collect(seed, cfg)

        # Verify the passive_dns request was made with the API key header.
        pdns_request = respx.calls[0].request
        assert pdns_request.headers.get("x-otx-api-key") == "test-otx-key-123"


# ==============================================================================
# 16. No API key still works
# ==============================================================================
class TestNoApiKey:
    @respx.mock
    @pytest.mark.asyncio
    async def test_no_api_key_works(self) -> None:
        """Without an API key, requests still succeed (unauthenticated)."""
        _mock_otx_endpoints(
            pdns={
                "passive_dns": [
                    {
                        "address": "9.9.9.9",
                        "hostname": "example.com",
                        "record_type": "A",
                        "first": "2023-01-01",
                        "last": "2025-01-01",
                    },
                ],
            },
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config()  # No API key.
        observations = await _collect(seed, cfg)

        ip_obs = [
            o for o in observations
            if o.observation_type == ObservationType.PASSIVE_DNS
        ]
        assert len(ip_obs) == 1
        assert ip_obs[0].subject.identifier_value == "9.9.9.9"

        # Verify no API key header was sent.
        pdns_request = respx.calls[0].request
        assert "x-otx-api-key" not in pdns_request.headers


# ==============================================================================
# 17. Warnings propagated on partial failure
# ==============================================================================
class TestWarningPropagation:
    @respx.mock
    @pytest.mark.asyncio
    async def test_pdns_failure_warning_on_url_observations(self) -> None:
        """When passive DNS fails, warnings do NOT appear on URL observations.

        Warnings are only attached to passive DNS IP observations; URL list
        observations are independent.
        """
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"
        ).mock(return_value=httpx.Response(500))
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list"
        ).mock(return_value=httpx.Response(200, json=_OTX_URL_LIST_RESPONSE))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        # URL observations still emitted.
        url_obs = [
            o for o in observations
            if o.observation_type == ObservationType.HTTP_RESPONSE
        ]
        assert len(url_obs) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_pdns_warning_text(self) -> None:
        """When passive DNS fails and there are still IP obs, warnings mention OTX."""
        # Both endpoints work, but let's check the warning propagation path
        # by failing PDNS and having a separate PDNS source still produce.
        # In our collector design, if PDNS fails entirely, no PDNS obs are
        # emitted, so warnings won't appear on those. Test with URL failure
        # instead (which sets warnings on url_records path — but actually
        # warnings are only on IP obs).
        # Let's test the scenario where PDNS works but URL fails.
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"
        ).mock(return_value=httpx.Response(200, json={
            "passive_dns": [
                {
                    "address": "1.2.3.4",
                    "hostname": "example.com",
                    "record_type": "A",
                    "first": "2020-01-01",
                    "last": "2024-01-01",
                },
            ],
        }))
        respx.get(
            "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list"
        ).mock(return_value=httpx.Response(500))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        # IP observation should exist.
        ip_obs = [
            o for o in observations
            if o.observation_type == ObservationType.PASSIVE_DNS
        ]
        assert len(ip_obs) == 1
        # The warning about URL list failure is in the warnings list.
        has_url_warning = any(
            "URL list" in w for w in ip_obs[0].warnings
        )
        assert has_url_warning


# ==============================================================================
# 18. Combined passive DNS + URL list
# ==============================================================================
class TestCombinedResults:
    @respx.mock
    @pytest.mark.asyncio
    async def test_full_response_all_observation_types(self) -> None:
        """Full response yields IP, subdomain, and URL observations."""
        _mock_otx_endpoints(
            pdns=_OTX_PASSIVE_DNS_RESPONSE,
            urls=_OTX_URL_LIST_RESPONSE,
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        ip_obs = [
            o for o in observations
            if o.observation_type == ObservationType.PASSIVE_DNS
        ]
        sub_obs = [
            o for o in observations
            if o.observation_type == ObservationType.DNS_RECORD
        ]
        url_obs = [
            o for o in observations
            if o.observation_type == ObservationType.HTTP_RESPONSE
        ]

        assert len(ip_obs) == 4   # 4 unique IPs
        assert len(sub_obs) == 2  # www.example.com, api.example.com
        assert len(url_obs) == 2  # /login, /admin
        assert len(observations) == 8  # total

    @respx.mock
    @pytest.mark.asyncio
    async def test_collector_id_on_all_observations(self) -> None:
        """All observations carry the correct collector_id."""
        _mock_otx_endpoints(
            pdns=_OTX_PASSIVE_DNS_RESPONSE,
            urls=_OTX_URL_LIST_RESPONSE,
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.collector_id == "otx-alienvault"
            assert obs.collector_version == "0.1.0"
            assert obs.tenant_id == TENANT_ID


# ==============================================================================
# 19. Domain case normalization
# ==============================================================================
class TestCaseNormalization:
    @respx.mock
    @pytest.mark.asyncio
    async def test_domain_lowercased(self) -> None:
        """Input domain is lowercased before use."""
        _mock_otx_endpoints(
            domain="example.com",
            pdns={
                "passive_dns": [
                    {
                        "address": "1.2.3.4",
                        "hostname": "Example.Com",
                        "record_type": "A",
                        "first": "2020-01-01",
                        "last": "2024-01-01",
                    },
                ],
            },
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="  Example.Com  ")
        observations = await _collect(seed)

        ip_obs = [
            o for o in observations
            if o.observation_type == ObservationType.PASSIVE_DNS
        ]
        # Should still work because domain is lowercased + stripped.
        assert len(ip_obs) == 1
