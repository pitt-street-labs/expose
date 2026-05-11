"""Tests for the ct-censys Certificate Transparency collector.

Exercises Censys Certificates API v2 logic via ``respx`` mocks — no live
network calls. Coverage:

 1.  Collector ID, tier, requires_credentials correct
 2.  Domain seed -> certificate search -> CT_LOG_ENTRY observations
 3.  No credentials -> empty list (graceful degradation)
 4.  Missing API ID only -> graceful degradation
 5.  Missing API secret only -> graceful degradation
 6.  HTTP 401 -> graceful degradation
 7.  HTTP 429 -> graceful degradation
 8.  HTTP 500 -> graceful degradation
 9.  Connection error -> graceful degradation
10.  Non-matching seed types skipped
11.  Observation field correctness
12.  SAN extraction from parsed.names
13.  Health check: success
14.  Health check: failure (no credentials)
15.  Health check: failure (API error)
16.  Registration in default registry
17.  Empty search results -> no observations
18.  Wildcard names included in SANs (CT collector preserves all names)
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
from expose.collectors.builtin.ct_censys import CensysCertCollector
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000ce001")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000ce002")

_CENSYS_BASE = "https://search.censys.io/api/v2"
_CERTS_URL = f"{_CENSYS_BASE}/certificates/search"


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
    collector = CensysCertCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === Canned API responses =====================================================

_CERT_SEARCH_RESPONSE: dict[str, Any] = {
    "result": {
        "hits": [
            {
                "fingerprint_sha256": "aabbccdd11223344556677889900aabbccddeeff00112233445566778899aabb",
                "parsed": {
                    "names": [
                        "example.com",
                        "www.example.com",
                        "api.example.com",
                    ],
                    "subject_dn": "CN=example.com",
                    "issuer_dn": "CN=R3, O=Let's Encrypt, C=US",
                    "validity": {
                        "start": "2025-01-01T00:00:00Z",
                        "end": "2025-04-01T00:00:00Z",
                    },
                },
            },
            {
                "fingerprint_sha256": "1122334455667788990011223344556677889900aabbccddeeff001122334455",
                "parsed": {
                    "names": [
                        "mail.example.com",
                        "*.internal.example.com",
                    ],
                    "subject_dn": "CN=mail.example.com",
                    "issuer_dn": "CN=DigiCert SHA2, O=DigiCert Inc, C=US",
                    "validity": {
                        "start": "2025-02-01T00:00:00Z",
                        "end": "2025-05-01T00:00:00Z",
                    },
                },
            },
        ],
    },
}

_EMPTY_CERT_RESPONSE: dict[str, Any] = {"result": {"hits": []}}


# ==============================================================================
# 1. Collector metadata
# ==============================================================================
class TestCollectorMetadata:
    def test_collector_id(self) -> None:
        assert CensysCertCollector.collector_id == "ct-censys"

    def test_collector_version(self) -> None:
        assert CensysCertCollector.collector_version == "0.1.0"

    def test_tier_is_tier_1(self) -> None:
        assert CensysCertCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials(self) -> None:
        assert CensysCertCollector.requires_credentials is True

    def test_is_subclass_of_collector_abc(self) -> None:
        assert issubclass(CensysCertCollector, Collector)


# ==============================================================================
# 2. Domain seed -> certificate search
# ==============================================================================
class TestDomainSeedSearch:
    @respx.mock
    async def test_domain_seed_yields_ct_observations(self) -> None:
        """Domain seed triggers certificate search and yields CT_LOG_ENTRY."""
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_CERT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        # 2 certificates = 2 CT_LOG_ENTRY observations.
        assert len(observations) == 2

    @respx.mock
    async def test_observation_type_is_ct_log_entry(self) -> None:
        """All observations are CT_LOG_ENTRY type."""
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_CERT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.observation_type == ObservationType.CT_LOG_ENTRY

    @respx.mock
    async def test_subject_is_search_domain(self) -> None:
        """Observation subjects use the search domain."""
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_CERT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.subject.identifier_type == IdentifierType.DOMAIN
            assert obs.subject.identifier_value == "example.com"


# ==============================================================================
# 3. No credentials -> graceful degradation
# ==============================================================================
class TestNoCredentials:
    async def test_no_creds_yields_nothing(self) -> None:
        """With no API credentials, expand yields nothing."""
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config()
        observations = await _collect(seed, cfg)
        assert observations == []


# ==============================================================================
# 4. Missing API ID only
# ==============================================================================
class TestMissingApiId:
    async def test_no_api_id_yields_nothing(self) -> None:
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(api_sec="sec-only")
        observations = await _collect(seed, cfg)
        assert observations == []


# ==============================================================================
# 5. Missing API secret only
# ==============================================================================
class TestMissingApiSecret:
    async def test_no_api_secret_yields_nothing(self) -> None:
        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        cfg = _config(api_id="id-only")
        observations = await _collect(seed, cfg)
        assert observations == []


# ==============================================================================
# 6. HTTP 401 -> graceful degradation
# ==============================================================================
class TestHttp401:
    @respx.mock
    async def test_401_yields_nothing(self) -> None:
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(401, json={"error": "unauthorized"})
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 7. HTTP 429 -> graceful degradation
# ==============================================================================
class TestHttp429:
    @respx.mock
    async def test_429_yields_nothing(self) -> None:
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(429, json={"error": "rate limit"})
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 8. HTTP 500 -> graceful degradation
# ==============================================================================
class TestHttp500:
    @respx.mock
    async def test_500_yields_nothing(self) -> None:
        respx.get(_CERTS_URL).mock(return_value=httpx.Response(500))

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 9. Connection error -> graceful degradation
# ==============================================================================
class TestConnectionError:
    @respx.mock
    async def test_connect_error_yields_nothing(self) -> None:
        respx.get(_CERTS_URL).mock(
            side_effect=httpx.ConnectError("DNS failed")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 10. Non-matching seed types skipped
# ==============================================================================
class TestSeedTypeFiltering:
    async def test_ip_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.IP, value="192.0.2.1")
        observations = await _collect(seed)
        assert observations == []

    async def test_organization_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        observations = await _collect(seed)
        assert observations == []

    async def test_asn_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        observations = await _collect(seed)
        assert observations == []

    async def test_cidr_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.CIDR, value="192.0.2.0/24")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 11. Observation field correctness
# ==============================================================================
class TestObservationFields:
    @respx.mock
    async def test_collector_id_in_payload(self) -> None:
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_CERT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.structured_payload["_collector_id"] == "ct-censys"

    @respx.mock
    async def test_source_is_censys_certificates(self) -> None:
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_CERT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.structured_payload["source"] == "censys_certificates"

    @respx.mock
    async def test_collector_id_on_observation(self) -> None:
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_CERT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.collector_id == "ct-censys"

    @respx.mock
    async def test_tenant_id_propagated(self) -> None:
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_CERT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.tenant_id == TENANT_ID

    @respx.mock
    async def test_fingerprint_in_payload(self) -> None:
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_CERT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert observations[0].structured_payload["fingerprint_sha256"] == (
            "aabbccdd11223344556677889900aabbccddeeff00112233445566778899aabb"
        )

    @respx.mock
    async def test_payload_has_expected_keys(self) -> None:
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_CERT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        expected_keys = {
            "source", "_collector_id", "fingerprint_sha256",
            "issuer_dn", "subject_dn", "sans",
            "not_before", "not_after", "search_domain",
        }
        for obs in observations:
            assert set(obs.structured_payload.keys()) == expected_keys


# ==============================================================================
# 12. SAN extraction from parsed.names
# ==============================================================================
class TestSanExtraction:
    @respx.mock
    async def test_sans_extracted_from_cert(self) -> None:
        """SANs are extracted from parsed.names and lowercased."""
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_CERT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        first_sans = observations[0].structured_payload["sans"]
        assert "example.com" in first_sans
        assert "www.example.com" in first_sans
        assert "api.example.com" in first_sans
        assert len(first_sans) == 3

    @respx.mock
    async def test_wildcard_names_preserved_in_sans(self) -> None:
        """Wildcard names are preserved in SANs (CT collector keeps all names)."""
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_CERT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        second_sans = observations[1].structured_payload["sans"]
        assert "mail.example.com" in second_sans
        assert "*.internal.example.com" in second_sans

    @respx.mock
    async def test_issuer_and_subject_dn_preserved(self) -> None:
        """Issuer and subject DN are in the payload."""
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_CERT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        payload = observations[0].structured_payload
        assert payload["issuer_dn"] == "CN=R3, O=Let's Encrypt, C=US"
        assert payload["subject_dn"] == "CN=example.com"

    @respx.mock
    async def test_validity_dates_preserved(self) -> None:
        """Validity dates are preserved in the payload."""
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_CERT_SEARCH_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        payload = observations[0].structured_payload
        assert payload["not_before"] == "2025-01-01T00:00:00Z"
        assert payload["not_after"] == "2025-04-01T00:00:00Z"


# ==============================================================================
# 13. Health check: success
# ==============================================================================
class TestHealthCheckSuccess:
    @respx.mock
    async def test_health_check_success(self) -> None:
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_EMPTY_CERT_RESPONSE)
        )

        collector = CensysCertCollector(_config(api_id="test-id", api_sec="test-sec"))
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "ct-censys"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0


# ==============================================================================
# 14. Health check: failure (no credentials)
# ==============================================================================
class TestHealthCheckNoCreds:
    async def test_health_check_no_creds(self) -> None:
        collector = CensysCertCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "not configured" in result.error_message


# ==============================================================================
# 15. Health check: failure (API error)
# ==============================================================================
class TestHealthCheckApiError:
    @respx.mock
    async def test_health_check_api_error(self) -> None:
        respx.get(_CERTS_URL).mock(return_value=httpx.Response(500))

        collector = CensysCertCollector(_config(api_id="test-id", api_sec="test-sec"))
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    @respx.mock
    async def test_health_check_connection_error(self) -> None:
        respx.get(_CERTS_URL).mock(side_effect=httpx.ConnectError("timeout"))

        collector = CensysCertCollector(_config(api_id="test-id", api_sec="test-sec"))
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None


# ==============================================================================
# 16. Registration in default registry
# ==============================================================================
class TestRegistration:
    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("ct-censys")
        cls = DEFAULT_REGISTRY.get("ct-censys")
        assert cls is CensysCertCollector


# ==============================================================================
# 17. Empty search results
# ==============================================================================
class TestEmptyResults:
    @respx.mock
    async def test_empty_hits_yields_nothing(self) -> None:
        """No certificate hits -> no observations."""
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=_EMPTY_CERT_RESPONSE)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="noresults.example.com")
        observations = await _collect(seed)
        assert observations == []


# ==============================================================================
# 18. Cert with no fingerprint but has names still yields observation
# ==============================================================================
class TestEdgeCases:
    @respx.mock
    async def test_cert_with_empty_fingerprint_but_names(self) -> None:
        """A certificate with empty fingerprint but valid names yields obs."""
        response = {
            "result": {
                "hits": [
                    {
                        "fingerprint_sha256": "",
                        "parsed": {
                            "names": ["edge.example.com"],
                            "subject_dn": "CN=edge.example.com",
                            "issuer_dn": "CN=Test CA",
                            "validity": {"start": "", "end": ""},
                        },
                    },
                ],
            },
        }
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=response)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["sans"] == ["edge.example.com"]

    @respx.mock
    async def test_cert_with_empty_names_and_fingerprint_skipped(self) -> None:
        """A certificate with no fingerprint and no names yields nothing."""
        response = {
            "result": {
                "hits": [
                    {
                        "fingerprint_sha256": "",
                        "parsed": {
                            "names": [],
                            "subject_dn": "",
                            "issuer_dn": "",
                            "validity": {},
                        },
                    },
                ],
            },
        }
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=response)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert observations == []

    @respx.mock
    async def test_missing_parsed_field_graceful(self) -> None:
        """A certificate hit without a parsed field still works."""
        response = {
            "result": {
                "hits": [
                    {
                        "fingerprint_sha256": "abcdef1234",
                    },
                ],
            },
        }
        respx.get(_CERTS_URL).mock(
            return_value=httpx.Response(200, json=response)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        # Has a fingerprint so it yields, but with empty SANs.
        assert len(observations) == 1
        assert observations[0].structured_payload["sans"] == []
