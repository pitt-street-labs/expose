"""Tests for the favicon-hash collector (Tier 2, Sprint 4).

Exercises favicon fetching and hashing logic via ``respx`` mocks — no
live network calls.  Coverage:

1.  Happy path: favicon found, SHA-256 hash computed
2.  No favicon: yields nothing (no observation)
3.  Redirect to favicon: follows redirect, hash computed
4.  IP seed: constructs URL correctly, identifier_type=IP
5.  Health check: success and failure paths
6.  Non-matching seed types skipped
7.  Fallback to apple-touch-icon.png
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import httpx
import pytest
import respx

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.favicon_hash import FaviconHashCollector
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.crypto.fips_adapter import compute_sha256_hex
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000fa01")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000fa02")

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "collectors" / "favicon_hash"


def _config(**extra: object) -> CollectorConfig:
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
        extra=dict(extra),  # type: ignore[arg-type]
    )


async def _collect(
    seed: Seed, config: CollectorConfig | None = None
) -> list[Observation]:
    cfg = config or _config()
    collector = FaviconHashCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# Deterministic test favicon data.
_FAVICON_BYTES = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00 \x00"
_FAVICON_SHA256 = compute_sha256_hex(_FAVICON_BYTES)


# ======================================================================
# 1. Happy path — favicon found, hash computed
# ======================================================================
class TestHappyPath:
    @respx.mock
    @pytest.mark.asyncio
    async def test_favicon_found_yields_observation(self) -> None:
        """Domain seed with favicon returns an observation with hash."""
        respx.get("https://example.com/favicon.ico").mock(
            return_value=httpx.Response(
                200,
                content=_FAVICON_BYTES,
                headers={"content-type": "image/x-icon"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.observation_type == ObservationType.HTTP_RESPONSE
        assert obs.collector_id == "favicon-hash"
        assert obs.collector_version == "0.1.0"
        assert obs.tenant_id == TENANT_ID
        assert obs.subject.identifier_type == IdentifierType.DOMAIN
        assert obs.subject.identifier_value == "example.com"

    @respx.mock
    @pytest.mark.asyncio
    async def test_structured_payload_keys(self) -> None:
        """Payload contains all expected keys."""
        respx.get("https://example.com/favicon.ico").mock(
            return_value=httpx.Response(
                200,
                content=_FAVICON_BYTES,
                headers={"content-type": "image/x-icon"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        payload = observations[0].structured_payload
        expected_keys = {
            "favicon_sha256",
            "favicon_mmh3",
            "favicon_size_bytes",
            "favicon_url",
            "favicon_content_type",
        }
        assert set(payload.keys()) == expected_keys

    @respx.mock
    @pytest.mark.asyncio
    async def test_sha256_hash_correct(self) -> None:
        """SHA-256 hash matches the FIPS adapter computation."""
        respx.get("https://example.com/favicon.ico").mock(
            return_value=httpx.Response(
                200,
                content=_FAVICON_BYTES,
                headers={"content-type": "image/x-icon"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        payload = observations[0].structured_payload
        assert payload["favicon_sha256"] == _FAVICON_SHA256
        assert payload["favicon_mmh3"] == 0  # stubbed
        assert payload["favicon_size_bytes"] == len(_FAVICON_BYTES)

    @respx.mock
    @pytest.mark.asyncio
    async def test_evidence_blob_contains_raw_bytes(self) -> None:
        """Evidence blob is the raw favicon bytes."""
        respx.get("https://example.com/favicon.ico").mock(
            return_value=httpx.Response(
                200,
                content=_FAVICON_BYTES,
                headers={"content-type": "image/x-icon"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = await _collect(seed)

        obs = observations[0]
        assert obs.evidence_blob == _FAVICON_BYTES
        assert obs.evidence_blob_content_type == "image/x-icon"


# ======================================================================
# 2. No favicon — yields nothing
# ======================================================================
class TestNoFavicon:
    @respx.mock
    @pytest.mark.asyncio
    async def test_no_favicon_returns_empty(self) -> None:
        """When no favicon exists, no observation is emitted."""
        respx.get("https://nofav.example.com/favicon.ico").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://nofav.example.com/apple-touch-icon.png").mock(
            return_value=httpx.Response(404)
        )
        respx.get("http://nofav.example.com/favicon.ico").mock(
            return_value=httpx.Response(404)
        )
        respx.get("http://nofav.example.com/apple-touch-icon.png").mock(
            return_value=httpx.Response(404)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="nofav.example.com")
        observations = await _collect(seed)

        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_favicon_returns_empty(self) -> None:
        """When favicon is 200 but empty body, no observation emitted."""
        respx.get("https://empty.example.com/favicon.ico").mock(
            return_value=httpx.Response(200, content=b"")
        )
        respx.get("https://empty.example.com/apple-touch-icon.png").mock(
            return_value=httpx.Response(404)
        )
        respx.get("http://empty.example.com/favicon.ico").mock(
            return_value=httpx.Response(200, content=b"")
        )
        respx.get("http://empty.example.com/apple-touch-icon.png").mock(
            return_value=httpx.Response(404)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="empty.example.com")
        observations = await _collect(seed)

        assert observations == []


# ======================================================================
# 3. Redirect to favicon — follows redirect
# ======================================================================
class TestRedirectToFavicon:
    @respx.mock
    @pytest.mark.asyncio
    async def test_redirect_followed_and_hash_computed(self) -> None:
        """Redirect from /favicon.ico is followed; hash computed from final body."""
        respx.get("https://redir.example.com/favicon.ico").mock(
            return_value=httpx.Response(
                301,
                headers={"location": "https://cdn.example.com/icon.ico"},
            )
        )
        respx.get("https://cdn.example.com/icon.ico").mock(
            return_value=httpx.Response(
                200,
                content=_FAVICON_BYTES,
                headers={"content-type": "image/x-icon"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="redir.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert payload["favicon_sha256"] == _FAVICON_SHA256
        # The final URL after redirect should be recorded.
        assert "cdn.example.com" in payload["favicon_url"]


# ======================================================================
# 4. IP seed — constructs URL correctly
# ======================================================================
class TestIpSeed:
    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_seed_constructs_url_and_uses_ip_identifier(self) -> None:
        """IP seed produces an observation with IdentifierType.IP."""
        respx.get("https://192.0.2.1/favicon.ico").mock(
            return_value=httpx.Response(
                200,
                content=_FAVICON_BYTES,
                headers={"content-type": "image/x-icon"},
            )
        )

        seed = Seed(seed_type=SeedType.IP, value="192.0.2.1")
        observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.subject.identifier_type == IdentifierType.IP
        assert obs.subject.identifier_value == "192.0.2.1"
        assert "192.0.2.1" in obs.structured_payload["favicon_url"]


# ======================================================================
# 5. Health check
# ======================================================================
class TestHealthCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Successful favicon fetch returns SUCCESS status."""
        respx.get("https://www.google.com/favicon.ico").mock(
            return_value=httpx.Response(200, content=_FAVICON_BYTES)
        )

        collector = FaviconHashCollector(_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "favicon-hash"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_error(self) -> None:
        """Connection error returns FAILURE status with error message."""
        respx.get("https://www.google.com/favicon.ico").mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )

        collector = FaviconHashCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_4xx(self) -> None:
        """A 404 response means FAILURE."""
        respx.get("https://www.google.com/favicon.ico").mock(
            return_value=httpx.Response(404)
        )

        collector = FaviconHashCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE


# ======================================================================
# 6. Non-matching seed types skipped
# ======================================================================
class TestSeedTypeFiltering:
    @pytest.mark.asyncio
    async def test_organization_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="ACME Corp")
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


# ======================================================================
# 7. Apple-touch-icon fallback
# ======================================================================
class TestAppleTouchIconFallback:
    @respx.mock
    @pytest.mark.asyncio
    async def test_apple_touch_icon_used_when_favicon_missing(self) -> None:
        """Falls back to apple-touch-icon.png when favicon.ico returns 404."""
        respx.get("https://apple.example.com/favicon.ico").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://apple.example.com/apple-touch-icon.png").mock(
            return_value=httpx.Response(
                200,
                content=_FAVICON_BYTES,
                headers={"content-type": "image/png"},
            )
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="apple.example.com")
        observations = await _collect(seed)

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert payload["favicon_sha256"] == _FAVICON_SHA256
        assert payload["favicon_content_type"] == "image/png"
        assert "apple-touch-icon" in payload["favicon_url"]


# ======================================================================
# Collector metadata
# ======================================================================
class TestCollectorMetadata:
    def test_collector_class_attributes(self) -> None:
        assert FaviconHashCollector.collector_id == "favicon-hash"
        assert FaviconHashCollector.collector_version == "0.1.0"
        assert FaviconHashCollector.tier == CollectorTier.TIER_2
        assert FaviconHashCollector.requires_credentials is False

    def test_collector_is_subclass_of_collector_abc(self) -> None:
        assert issubclass(FaviconHashCollector, Collector)


# ======================================================================
# Registry
# ======================================================================
class TestRegistration:
    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("favicon-hash")
        cls = DEFAULT_REGISTRY.get("favicon-hash")
        assert cls is FaviconHashCollector
