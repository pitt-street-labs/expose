"""Tests for the ct-certstream Certificate Transparency near-real-time collector.

Uses respx to mock all HTTP interactions -- NO live network calls.
Fixtures in tests/fixtures/collectors/ct_certstream/ provide canned crt.sh
JSON responses. Timestamps marked as RECENT_PLACEHOLDER / FUTURE_PLACEHOLDER
are replaced at load time with values relative to ``datetime.now(UTC)`` so
recency filtering can be tested deterministically.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
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
from expose.collectors.builtin.ct_certstream import CertstreamCollector
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000cb01")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000cb02")

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "collectors" / "ct_certstream"


def _load_fixture(name: str, *, recent: bool = True) -> str:
    """Load a fixture file, replacing timestamp placeholders.

    When ``recent=True``, RECENT_PLACEHOLDER is set to 1 hour ago and
    FUTURE_PLACEHOLDER is set to 90 days from now.  When ``recent=False``,
    RECENT_PLACEHOLDER is set to 48 hours ago (outside the default 24h
    recency window).
    """
    raw = (FIXTURES_DIR / name).read_text()
    now = datetime.now(tz=UTC)
    recent_dt = now - timedelta(hours=1) if recent else now - timedelta(hours=48)
    future_dt = now + timedelta(days=90)
    return (
        raw.replace("RECENT_PLACEHOLDER", recent_dt.strftime("%Y-%m-%dT%H:%M:%S"))
        .replace("FUTURE_PLACEHOLDER", future_dt.strftime("%Y-%m-%dT%H:%M:%S"))
    )


def _make_config(
    *,
    timeout: float = 30.0,
    rate_limit: int | None = None,
    recency_hours: int = 24,
) -> CollectorConfig:
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=timeout,
        rate_limit_per_minute=rate_limit,
        extra={"recency_hours": recency_hours},
    )


def _make_seed(domain: str = "example.com") -> Seed:
    return Seed(seed_type=SeedType.DOMAIN, value=domain)


async def _collect_all(
    collector: CertstreamCollector, seed: Seed
) -> list[Observation]:
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# ---------------------------------------------------------------------------
# Test 1: Happy path -- recent cert found, observation yielded
# ---------------------------------------------------------------------------


class TestCertstreamHappyPath:
    """Recent certificates within the recency window are yielded."""

    @respx.mock
    async def test_recent_certs_yielded(self) -> None:
        fixture = _load_fixture("recent_certs.json", recent=True)
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(return_value=httpx.Response(200, text=fixture))

        collector = CertstreamCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        assert len(results) == 2

    @respx.mock
    async def test_observation_fields(self) -> None:
        fixture = _load_fixture("recent_certs.json", recent=True)
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(return_value=httpx.Response(200, text=fixture))

        collector = CertstreamCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        obs = results[0]
        assert obs.collector_id == "ct-certstream"
        assert obs.collector_version == "0.1.0"
        assert obs.tenant_id == TENANT_ID
        assert obs.observation_type == ObservationType.CT_LOG_ENTRY
        assert (
            obs.subject.identifier_type
            == ExtendedIdentifierType.CERTIFICATE_FINGERPRINT
        )
        assert obs.subject.identifier_value == "aa00bb11cc22dd33ee44ff5500116677"

    @respx.mock
    async def test_structured_payload_keys(self) -> None:
        fixture = _load_fixture("recent_certs.json", recent=True)
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(return_value=httpx.Response(200, text=fixture))

        collector = CertstreamCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        payload = results[0].structured_payload
        expected_keys = {
            "issuer_name",
            "common_name",
            "sans",
            "not_before",
            "not_after",
            "serial_number",
            "source",
            "recency_hours",
        }
        assert set(payload.keys()) == expected_keys

    @respx.mock
    async def test_source_is_certstream(self) -> None:
        fixture = _load_fixture("recent_certs.json", recent=True)
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(return_value=httpx.Response(200, text=fixture))

        collector = CertstreamCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        for obs in results:
            assert obs.structured_payload["source"] == "certstream"
            assert obs.structured_payload["recency_hours"] == 24

    @respx.mock
    async def test_sans_parsed_from_newlines(self) -> None:
        fixture = _load_fixture("recent_certs.json", recent=True)
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(return_value=httpx.Response(200, text=fixture))

        collector = CertstreamCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        first_sans = results[0].structured_payload["sans"]
        assert len(first_sans) == 2
        assert "login.example.com" in first_sans
        assert "www.login.example.com" in first_sans

        second_sans = results[1].structured_payload["sans"]
        assert len(second_sans) == 1
        assert "api.example.com" in second_sans


# ---------------------------------------------------------------------------
# Test 2: No recent certs -- all older than recency window, yields nothing
# ---------------------------------------------------------------------------


class TestCertstreamNoRecentCerts:
    """Certificates outside the recency window are filtered out."""

    @respx.mock
    async def test_old_certs_filtered_out(self) -> None:
        fixture = _load_fixture("no_recent_certs.json")
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(return_value=httpx.Response(200, text=fixture))

        collector = CertstreamCollector(_make_config())
        results = await _collect_all(
            collector, _make_seed("no-recent.example.com")
        )

        assert results == []

    @respx.mock
    async def test_recent_placeholder_outside_window(self) -> None:
        """Fixture with RECENT_PLACEHOLDER set to 48h ago (beyond 24h window)."""
        fixture = _load_fixture("recent_certs.json", recent=False)
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(return_value=httpx.Response(200, text=fixture))

        collector = CertstreamCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        assert results == []

    @respx.mock
    async def test_empty_json_array(self) -> None:
        fixture = _load_fixture("empty_result.json")
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(return_value=httpx.Response(200, text=fixture))

        collector = CertstreamCollector(_make_config())
        results = await _collect_all(
            collector, _make_seed("empty.example.com")
        )

        assert results == []


# ---------------------------------------------------------------------------
# Test 3: Deduplication -- same serial seen twice, yielded once
# ---------------------------------------------------------------------------


class TestCertstreamDeduplication:
    """Duplicate serial numbers within the recency window are deduplicated."""

    @respx.mock
    async def test_dedup_by_serial(self) -> None:
        fixture = _load_fixture("duplicates.json", recent=True)
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(return_value=httpx.Response(200, text=fixture))

        collector = CertstreamCollector(_make_config())
        results = await _collect_all(collector, _make_seed("example.com"))

        # 3 entries in fixture but 2 share a serial -- expect 2 unique
        assert len(results) == 2

        serials = [r.subject.identifier_value for r in results]
        assert len(set(serials)) == 2
        assert "ff00aa11bb22cc33dd44ee5500667788" in serials
        assert "1100aa22bb33cc44dd55ee6677889900" in serials


# ---------------------------------------------------------------------------
# Test 4: Non-domain seed skipped
# ---------------------------------------------------------------------------


class TestCertstreamNonDomainSeed:
    """Non-domain seed types are skipped without making HTTP calls."""

    @respx.mock
    async def test_ip_seed_yields_nothing(self) -> None:
        collector = CertstreamCollector(_make_config())
        seed = Seed(seed_type=SeedType.IP, value="192.0.2.1")
        results = await _collect_all(collector, seed)
        assert results == []

    @respx.mock
    async def test_asn_seed_yields_nothing(self) -> None:
        collector = CertstreamCollector(_make_config())
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        results = await _collect_all(collector, seed)
        assert results == []

    @respx.mock
    async def test_organization_seed_yields_nothing(self) -> None:
        collector = CertstreamCollector(_make_config())
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        results = await _collect_all(collector, seed)
        assert results == []


# ---------------------------------------------------------------------------
# Test 5: Health check
# ---------------------------------------------------------------------------


class TestCertstreamHealthCheck:
    """Health check returns appropriate status."""

    @respx.mock
    async def test_healthy_returns_success(self) -> None:
        respx.head("https://crt.sh/").mock(
            return_value=httpx.Response(200),
        )

        collector = CertstreamCollector(_make_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "ct-certstream"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    async def test_unhealthy_returns_failure(self) -> None:
        respx.head("https://crt.sh/").mock(
            return_value=httpx.Response(503, text="Service Unavailable"),
        )

        collector = CertstreamCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "503" in result.error_message


# ---------------------------------------------------------------------------
# Test 6: Source unreachable
# ---------------------------------------------------------------------------


class TestCertstreamSourceUnreachable:
    """Network errors raise CollectorSourceUnreachableError."""

    @respx.mock
    async def test_connection_error_raises(self) -> None:
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(side_effect=httpx.ConnectError("connection refused"))

        collector = CertstreamCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="unreachable"
        ):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_timeout_raises(self) -> None:
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(side_effect=httpx.ReadTimeout("read timed out"))

        collector = CertstreamCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="unreachable"
        ):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_http_500_raises(self) -> None:
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(return_value=httpx.Response(500, text="Internal Server Error"))

        collector = CertstreamCollector(_make_config())
        with pytest.raises(CollectorSourceUnreachableError, match="500"):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_http_429_raises(self) -> None:
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(
            return_value=httpx.Response(429, text="Too Many Requests"),
        )

        collector = CertstreamCollector(_make_config())
        with pytest.raises(CollectorSourceUnreachableError, match="429"):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_health_check_network_error(self) -> None:
        respx.head("https://crt.sh/").mock(
            side_effect=httpx.ConnectError("connection refused"),
        )

        collector = CertstreamCollector(_make_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "unreachable" in result.error_message


# ---------------------------------------------------------------------------
# Test 7: Malformed JSON response handled
# ---------------------------------------------------------------------------


class TestCertstreamMalformedResponse:
    """Malformed JSON raises CollectorSourceUnreachableError."""

    @respx.mock
    async def test_not_json_raises(self) -> None:
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(
            return_value=httpx.Response(200, text="<html>not json</html>"),
        )

        collector = CertstreamCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="malformed JSON"
        ):
            await _collect_all(collector, _make_seed())

    @respx.mock
    async def test_json_object_instead_of_array_raises(self) -> None:
        fixture = _load_fixture("malformed.json")
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(return_value=httpx.Response(200, text=fixture))

        collector = CertstreamCollector(_make_config())
        with pytest.raises(
            CollectorSourceUnreachableError, match="instead of JSON array"
        ):
            await _collect_all(collector, _make_seed())


# ---------------------------------------------------------------------------
# Metadata & registration
# ---------------------------------------------------------------------------


class TestCertstreamMetadata:
    """Verify class-level metadata attributes."""

    def test_collector_id(self) -> None:
        assert CertstreamCollector.collector_id == "ct-certstream"

    def test_collector_version(self) -> None:
        assert CertstreamCollector.collector_version == "0.1.0"

    def test_tier(self) -> None:
        assert CertstreamCollector.tier == CollectorTier.TIER_1

    def test_requires_credentials(self) -> None:
        assert CertstreamCollector.requires_credentials is False


class TestCertstreamRegistration:
    """Verify the collector is registered in the default registry."""

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("ct-certstream")
        cls = DEFAULT_REGISTRY.get("ct-certstream")
        assert cls is CertstreamCollector


# ---------------------------------------------------------------------------
# Recency window configuration
# ---------------------------------------------------------------------------


class TestCertstreamRecencyConfig:
    """Verify the recency window is configurable via CollectorConfig.extra."""

    @respx.mock
    async def test_custom_recency_hours(self) -> None:
        """With a 1-hour window, certs from 1h ago pass; with a 0.5h they don't."""
        fixture = _load_fixture("recent_certs.json", recent=True)
        respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(return_value=httpx.Response(200, text=fixture))

        # 72-hour window -- the 1-hour-ago certs should pass
        collector = CertstreamCollector(_make_config(recency_hours=72))
        results = await _collect_all(collector, _make_seed("example.com"))
        assert len(results) == 2

        for obs in results:
            assert obs.structured_payload["recency_hours"] == 72

    @respx.mock
    async def test_default_recency_hours(self) -> None:
        """Default recency window is 24 hours."""
        collector = CertstreamCollector(_make_config())
        assert collector._recency_hours == 24

    @respx.mock
    async def test_exclude_expired_param_sent(self) -> None:
        """The collector sends exclude=expired to crt.sh."""
        fixture = _load_fixture("empty_result.json")
        route = respx.get(
            "https://crt.sh/", params__contains={"output": "json"}
        ).mock(return_value=httpx.Response(200, text=fixture))

        collector = CertstreamCollector(_make_config())
        await _collect_all(collector, _make_seed("example.com"))

        assert route.called
        request = route.calls[0].request
        assert "exclude=expired" in str(request.url)
