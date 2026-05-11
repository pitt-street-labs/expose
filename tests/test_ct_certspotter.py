"""Tests for the ct-certspotter Certificate Transparency collector.

Uses respx to mock all HTTP interactions -- NO live network calls.
"""

from __future__ import annotations

import json
from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import (
    CollectorConfig,
    CollectorHealthCheck,
    CollectorSourceUnreachableError,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.ct_certspotter import (
    CertSpotterCollector,
    clear_certspotter_cache,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000cb01")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000cb02")

_API_URL = "https://api.certspotter.com/v1/issuances"

# -- Canned CertSpotter response data ----------------------------------------

# Two certificates with multiple SANs (mimics real korlogos.com response).
_HAPPY_PATH_RESPONSE = [
    {
        "id": "6543210001",
        "tbs_sha256": "aabbccdd00112233445566778899aabb00112233445566778899aabbccddeeff",
        "dns_names": ["korlogos.com", "kev.korlogos.com"],
        "issuer": {
            "C": "US",
            "O": "Let's Encrypt",
            "CN": "R3",
        },
        "not_before": "2025-06-01T00:00:00Z",
        "not_after": "2025-09-01T00:00:00Z",
    },
    {
        "id": "6543210002",
        "tbs_sha256": "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        "dns_names": ["goymonitor.korlogos.com", "korlogos.com"],
        "issuer": {
            "C": "US",
            "O": "Let's Encrypt",
            "CN": "E5",
        },
        "not_before": "2025-07-01T00:00:00Z",
        "not_after": "2025-10-01T00:00:00Z",
    },
]

# Response with wildcards that should be filtered out.
_WILDCARD_RESPONSE = [
    {
        "id": "7777770001",
        "tbs_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        "dns_names": ["*.example.com", "example.com", "*.staging.example.com", "api.example.com"],
        "issuer": {
            "CN": "DigiCert SHA2 Extended Validation Server CA",
        },
        "not_before": "2025-01-01T00:00:00Z",
        "not_after": "2025-12-31T00:00:00Z",
    },
]


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    """Clear CertSpotter response cache before each test to prevent leakage."""
    clear_certspotter_cache()


def _make_config(
    *,
    timeout: float = 30.0,
    rate_limit: int | None = None,
) -> CollectorConfig:
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=timeout,
        rate_limit_per_minute=rate_limit,
    )


def _make_seed(domain: str = "korlogos.com") -> Seed:
    return Seed(seed_type=SeedType.DOMAIN, value=domain)


async def _collect_all(
    collector: CertSpotterCollector, seed: Seed
) -> list[Observation]:
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# ============================================================================
# Metadata
# ============================================================================


class TestCertSpotterMetadata:
    """Verify class-level metadata attributes."""

    def test_collector_id(self) -> None:
        assert CertSpotterCollector.collector_id == "ct-certspotter"

    def test_collector_version(self) -> None:
        assert CertSpotterCollector.collector_version == "0.1.0"

    def test_tier(self) -> None:
        assert CertSpotterCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials(self) -> None:
        assert CertSpotterCollector.requires_credentials is False

    def test_rate_limit(self) -> None:
        assert CertSpotterCollector.rate_limit_per_minute == 60


# ============================================================================
# Happy path -- 2 certs, multiple SANs
# ============================================================================


class TestCertSpotterHappyPath:
    """Two certificates with overlapping SANs yield deduplicated observations."""

    @respx.mock
    async def test_yields_unique_domains(self) -> None:
        """Should yield 3 unique domains: korlogos.com, kev.korlogos.com,
        goymonitor.korlogos.com (korlogos.com deduplicated across certs)."""
        respx.get(_API_URL).mock(
            return_value=httpx.Response(
                200, text=json.dumps(_HAPPY_PATH_RESPONSE)
            ),
        )

        collector = CertSpotterCollector(_make_config())
        results = await _collect_all(collector, _make_seed("korlogos.com"))

        assert len(results) == 3
        domains = {r.subject.identifier_value for r in results}
        assert domains == {
            "korlogos.com",
            "kev.korlogos.com",
            "goymonitor.korlogos.com",
        }

    @respx.mock
    async def test_observation_type_is_ct_log_entry(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(
                200, text=json.dumps(_HAPPY_PATH_RESPONSE)
            ),
        )

        collector = CertSpotterCollector(_make_config())
        results = await _collect_all(collector, _make_seed())

        for obs in results:
            assert obs.observation_type == ObservationType.CT_LOG_ENTRY

    @respx.mock
    async def test_observation_subject_type_is_domain(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(
                200, text=json.dumps(_HAPPY_PATH_RESPONSE)
            ),
        )

        collector = CertSpotterCollector(_make_config())
        results = await _collect_all(collector, _make_seed())

        for obs in results:
            assert obs.subject.identifier_type == IdentifierType.DOMAIN

    @respx.mock
    async def test_structured_payload_keys(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(
                200, text=json.dumps(_HAPPY_PATH_RESPONSE)
            ),
        )

        collector = CertSpotterCollector(_make_config())
        results = await _collect_all(collector, _make_seed())

        expected_keys = {
            "source",
            "issuer",
            "not_before",
            "not_after",
            "tbs_sha256",
            "dns_names",
        }
        for obs in results:
            assert set(obs.structured_payload.keys()) == expected_keys

    @respx.mock
    async def test_source_is_certspotter(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(
                200, text=json.dumps(_HAPPY_PATH_RESPONSE)
            ),
        )

        collector = CertSpotterCollector(_make_config())
        results = await _collect_all(collector, _make_seed())

        for obs in results:
            assert obs.structured_payload["source"] == "certspotter"

    @respx.mock
    async def test_collector_id_and_version_on_observations(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(
                200, text=json.dumps(_HAPPY_PATH_RESPONSE)
            ),
        )

        collector = CertSpotterCollector(_make_config())
        results = await _collect_all(collector, _make_seed())

        for obs in results:
            assert obs.collector_id == "ct-certspotter"
            assert obs.collector_version == "0.1.0"
            assert obs.tenant_id == TENANT_ID

    @respx.mock
    async def test_dns_names_included_in_payload(self) -> None:
        """Each observation carries the full dns_names list from the cert."""
        respx.get(_API_URL).mock(
            return_value=httpx.Response(
                200, text=json.dumps(_HAPPY_PATH_RESPONSE)
            ),
        )

        collector = CertSpotterCollector(_make_config())
        results = await _collect_all(collector, _make_seed())

        # First cert's first domain (korlogos.com) should carry the first
        # cert's dns_names.
        first = next(
            r for r in results if r.subject.identifier_value == "korlogos.com"
        )
        assert first.structured_payload["dns_names"] == [
            "korlogos.com",
            "kev.korlogos.com",
        ]


# ============================================================================
# Wildcard filtering
# ============================================================================


class TestCertSpotterWildcardFiltering:
    """Wildcard SANs (*.example.com) are excluded from observations."""

    @respx.mock
    async def test_wildcards_excluded(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(
                200, text=json.dumps(_WILDCARD_RESPONSE)
            ),
        )

        collector = CertSpotterCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        domains = {r.subject.identifier_value for r in results}
        assert "*.example.com" not in domains
        assert "*.staging.example.com" not in domains
        # Non-wildcard names should be present.
        assert "example.com" in domains
        assert "api.example.com" in domains
        assert len(results) == 2


# ============================================================================
# Empty results
# ============================================================================


class TestCertSpotterEmptyResults:
    """Domain not in CT logs returns no observations."""

    @respx.mock
    async def test_empty_array_yields_nothing(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(200, text="[]"),
        )

        collector = CertSpotterCollector(_make_config())
        results = await _collect_all(
            collector, _make_seed("no-certs.example.com")
        )

        assert results == []

    @respx.mock
    async def test_cert_with_empty_dns_names(self) -> None:
        """A cert entry with empty dns_names list yields nothing."""
        data = [
            {
                "id": "9999",
                "tbs_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "dns_names": [],
                "issuer": {"CN": "Test CA"},
                "not_before": "2025-01-01T00:00:00Z",
                "not_after": "2025-12-31T00:00:00Z",
            }
        ]
        respx.get(_API_URL).mock(
            return_value=httpx.Response(200, text=json.dumps(data)),
        )

        collector = CertSpotterCollector(_make_config())
        results = await _collect_all(collector, _make_seed("empty-sans.com"))

        assert results == []


# ============================================================================
# Rate limiting (429)
# ============================================================================


class TestCertSpotterRateLimiting:
    """429 responses are handled gracefully."""

    @respx.mock
    async def test_429_raises_source_unreachable(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(
                429,
                text="Too Many Requests",
                headers={"Retry-After": "60"},
            ),
        )

        collector = CertSpotterCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="rate-limited"
        ):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_429_includes_retry_after(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(
                429,
                text="Too Many Requests",
                headers={"Retry-After": "120"},
            ),
        )

        collector = CertSpotterCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="Retry-After: 120"
        ):
            await _collect_all(collector, _make_seed())


# ============================================================================
# HTTP errors
# ============================================================================


class TestCertSpotterHTTPErrors:
    """Non-429 HTTP errors raise CollectorSourceUnreachableError."""

    @respx.mock
    async def test_500_raises(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(500, text="Internal Server Error"),
        )

        collector = CertSpotterCollector(_make_config())
        with pytest.raises(CollectorSourceUnreachableError, match="500"):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_connection_error_raises(self) -> None:
        respx.get(_API_URL).mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = CertSpotterCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="unreachable"
        ):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_timeout_raises(self) -> None:
        respx.get(_API_URL).mock(
            side_effect=httpx.ReadTimeout("read timed out"),
        )

        collector = CertSpotterCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="unreachable"
        ):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_malformed_json_raises(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(200, text="<html>not json</html>"),
        )

        collector = CertSpotterCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="malformed JSON"
        ):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_json_object_instead_of_array_raises(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(
                200, text=json.dumps({"error": "bad"})
            ),
        )

        collector = CertSpotterCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="instead of JSON array"
        ):
            await _collect_all(collector, _make_seed())


# ============================================================================
# Unsupported seed types
# ============================================================================


class TestCertSpotterUnsupportedSeeds:
    """Non-DOMAIN seed types are skipped."""

    async def test_ip_seed_yields_nothing(self) -> None:
        collector = CertSpotterCollector(_make_config())
        seed = Seed(seed_type=SeedType.IP, value="192.0.2.1")
        results = await _collect_all(collector, seed)
        assert results == []

    async def test_org_seed_yields_nothing(self) -> None:
        collector = CertSpotterCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        results = await _collect_all(collector, seed)
        assert results == []

    async def test_asn_seed_yields_nothing(self) -> None:
        collector = CertSpotterCollector(_make_config())
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        results = await _collect_all(collector, seed)
        assert results == []


# ============================================================================
# Health check
# ============================================================================


class TestCertSpotterHealthCheck:
    """health_check queries example.com and returns status."""

    @respx.mock
    async def test_healthy_returns_success(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(200, text="[]"),
        )

        collector = CertSpotterCollector(_make_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "ct-certspotter"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    async def test_unhealthy_returns_failure(self) -> None:
        respx.get(_API_URL).mock(
            return_value=httpx.Response(503, text="Service Unavailable"),
        )

        collector = CertSpotterCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "503" in result.error_message

    @respx.mock
    async def test_network_error_returns_failure(self) -> None:
        respx.get(_API_URL).mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = CertSpotterCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "unreachable" in result.error_message


# ============================================================================
# Registry
# ============================================================================


class TestCertSpotterRegistration:
    """Verify the collector is registered in the default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("ct-certspotter")
        cls = DEFAULT_REGISTRY.get("ct-certspotter")
        assert cls is CertSpotterCollector
