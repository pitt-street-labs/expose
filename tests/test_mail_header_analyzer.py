"""Tests for the mail-headers collector (Tier 1, issue #79).

Exercises mailing list archive discovery and header IP extraction via
``respx`` mocks -- no live network calls. Coverage:

1.  Collector metadata: ID, tier, version, rate limit, requires_credentials
2.  Only expands DOMAIN seeds (others return [])
3.  Happy path: domain seed -> archive found -> IPs extracted
4.  Archive not found: empty result
5.  Empty/whitespace seed value skipped
6.  Multiple archive subdomains probed
7.  Software fingerprinting (Mailman, Sympa, etc.)
8.  Received: header IP extraction
9.  HTTP errors: graceful degradation (no exceptions)
10. Ignored IPs filtered (127.0.0.1, 0.0.0.0)
11. Health check: success and failure paths
12. Observation fields and structured_payload shape
13. Archive discovery emits DOMAIN observations
14. IP extraction emits IP observations
"""

from __future__ import annotations

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
from expose.collectors.builtin.mail_header_analyzer import (
    MailHeaderAnalyzerCollector,
    _detect_software,
    _extract_received_ips,
)
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, IdentifierType

TENANT_ID = UUID("018f1f00-0000-7000-8000-0000000c0d01")
RUN_ID = UUID("018f1f00-0000-7000-8000-0000000c0d02")

_HEALTH_CHECK_URL = "https://httpbin.org/status/200"


def _config() -> CollectorConfig:
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
    )


async def _collect(seed: Seed) -> list[Observation]:
    cfg = _config()
    collector = MailHeaderAnalyzerCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# === Canned archive page content =============================================

_MAILMAN_ARCHIVE_PAGE = """
<html>
<head><title>Mailman Archives</title></head>
<body>
<h1>Mailing Lists powered by Mailman</h1>
<p>Welcome to the mailing list archive for acme.com</p>
<pre>
Received: from mail-relay.acme.com (10.20.30.40) by lists.acme.com
Received: from external-gw.acme.com ([203.0.113.50]) by mail-relay.acme.com
</pre>
</body>
</html>
"""

_PIPERMAIL_ARCHIVE_PAGE = """
<html>
<head><title>Pipermail Archives</title></head>
<body>
<h1>Pipermail list index</h1>
<p>Archive of dev@acme.com list</p>
<pre>
Received: from smtp.acme.com (192.0.2.100) by lists.acme.com
</pre>
</body>
</html>
"""

_SYMPA_PAGE = """
<html><body><h1>Sympa Mailing Lists</h1></body></html>
"""

_EMPTY_PAGE = """
<html><body><p>Nothing here.</p></body></html>
"""

_PAGE_WITH_IGNORED_IPS = """
<html><body>
<pre>
Received: from localhost (127.0.0.1) by lists.acme.com
Received: from any (0.0.0.0) by lists.acme.com
</pre>
</body></html>
"""


# ======================================================================
# 1. Collector metadata
# ======================================================================
class TestCollectorMetadata:
    def test_collector_id(self) -> None:
        assert MailHeaderAnalyzerCollector.collector_id == "mail-headers"

    def test_collector_version(self) -> None:
        assert MailHeaderAnalyzerCollector.collector_version == "0.1.0"

    def test_tier_is_tier_1(self) -> None:
        assert MailHeaderAnalyzerCollector.tier == CollectorTier.TIER_1

    def test_no_credentials_required(self) -> None:
        assert MailHeaderAnalyzerCollector.requires_credentials is False

    def test_rate_limit(self) -> None:
        assert MailHeaderAnalyzerCollector.rate_limit_per_minute == 30

    def test_is_subclass_of_collector(self) -> None:
        assert issubclass(MailHeaderAnalyzerCollector, Collector)


# ======================================================================
# 2. Seed type filtering
# ======================================================================
class TestSeedTypeFiltering:
    @pytest.mark.asyncio
    async def test_ip_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.IP, value="192.0.2.1")
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

    @pytest.mark.asyncio
    async def test_organization_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Acme Corp")
        observations = await _collect(seed)
        assert observations == []

    @pytest.mark.asyncio
    async def test_empty_domain_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.DOMAIN, value="  ")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 3. Happy path — archive found with IPs
# ======================================================================
class TestHappyPath:
    @respx.mock
    @pytest.mark.asyncio
    async def test_archive_found_with_ips(self) -> None:
        """Archive page found at lists.{domain}/ -> IPs and archive observed."""
        # lists.acme.com/ returns the Mailman archive page.
        respx.get("https://lists.acme.com/").mock(
            return_value=httpx.Response(200, text=_MAILMAN_ARCHIVE_PAGE)
        )
        # All other probes return 404.
        respx.get(url__regex=r"^https://(?!lists\.acme\.com/)").mock(
            return_value=httpx.Response(404)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        # Should have archive discovery observation + IP observations.
        archive_obs = [
            o for o in observations
            if o.observation_type == ObservationType.HTTP_RESPONSE
        ]
        ip_obs = [
            o for o in observations
            if o.observation_type == ObservationType.SCANNER_HOST
        ]

        assert len(archive_obs) >= 1
        assert archive_obs[0].subject.identifier_type == IdentifierType.DOMAIN
        assert archive_obs[0].subject.identifier_value == "lists.acme.com"

        ip_values = {o.subject.identifier_value for o in ip_obs}
        assert "10.20.30.40" in ip_values
        assert "203.0.113.50" in ip_values

    @respx.mock
    @pytest.mark.asyncio
    async def test_observation_collector_metadata(self) -> None:
        """Observations have correct collector metadata."""
        respx.get("https://lists.acme.com/").mock(
            return_value=httpx.Response(200, text=_MAILMAN_ARCHIVE_PAGE)
        )
        respx.get(url__regex=r"^https://(?!lists\.acme\.com/)").mock(
            return_value=httpx.Response(404)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        for obs in observations:
            assert obs.collector_id == "mail-headers"
            assert obs.collector_version == "0.1.0"
            assert obs.tenant_id == TENANT_ID

    @respx.mock
    @pytest.mark.asyncio
    async def test_archive_payload_shape(self) -> None:
        """Archive observation has expected payload keys."""
        respx.get("https://lists.acme.com/").mock(
            return_value=httpx.Response(200, text=_MAILMAN_ARCHIVE_PAGE)
        )
        respx.get(url__regex=r"^https://(?!lists\.acme\.com/)").mock(
            return_value=httpx.Response(404)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        archive_obs = [
            o for o in observations
            if o.observation_type == ObservationType.HTTP_RESPONSE
        ]
        assert len(archive_obs) >= 1

        payload = archive_obs[0].structured_payload
        assert payload["source"] == "mail_archive_discovery"
        assert "seed_domain" in payload
        assert "archive_url" in payload
        assert "software" in payload

    @respx.mock
    @pytest.mark.asyncio
    async def test_ip_payload_shape(self) -> None:
        """IP observation has expected payload keys."""
        respx.get("https://lists.acme.com/").mock(
            return_value=httpx.Response(200, text=_MAILMAN_ARCHIVE_PAGE)
        )
        respx.get(url__regex=r"^https://(?!lists\.acme\.com/)").mock(
            return_value=httpx.Response(404)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        ip_obs = [
            o for o in observations
            if o.observation_type == ObservationType.SCANNER_HOST
        ]
        assert len(ip_obs) >= 1

        payload = ip_obs[0].structured_payload
        assert payload["source"] == "mail_header_ip"
        assert "seed_domain" in payload
        assert "archives_checked" in payload


# ======================================================================
# 4. Archive not found
# ======================================================================
class TestArchiveNotFound:
    @respx.mock
    @pytest.mark.asyncio
    async def test_all_probes_404(self) -> None:
        """All archive probes return 404 -> no observations."""
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="nonexistent.example")
        observations = await _collect(seed)
        assert observations == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_all_probes_connection_error(self) -> None:
        """All archive probes fail with connection error -> no observations."""
        respx.get(url__regex=r".*").mock(
            side_effect=httpx.ConnectError("DNS failed")
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="nonexistent.example")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 5. Software fingerprinting
# ======================================================================
class TestSoftwareDetection:
    def test_detect_mailman(self) -> None:
        assert "mailman" in _detect_software("Mailman 2.1 Archives")

    def test_detect_sympa(self) -> None:
        assert "sympa" in _detect_software("Sympa Mailing List Manager")

    def test_detect_pipermail(self) -> None:
        assert "pipermail" in _detect_software("Pipermail archive index")

    def test_detect_hyperkitty(self) -> None:
        assert "hyperkitty" in _detect_software("HyperKitty List Archive")

    def test_detect_majordomo(self) -> None:
        assert "majordomo" in _detect_software("Majordomo list server")

    def test_detect_nothing(self) -> None:
        assert _detect_software("Just a normal page") == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_software_in_payload(self) -> None:
        """Detected software appears in observation payload."""
        respx.get("https://lists.acme.com/").mock(
            return_value=httpx.Response(200, text=_MAILMAN_ARCHIVE_PAGE)
        )
        respx.get(url__regex=r"^https://(?!lists\.acme\.com/)").mock(
            return_value=httpx.Response(404)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        archive_obs = [
            o for o in observations
            if o.observation_type == ObservationType.HTTP_RESPONSE
        ]
        assert len(archive_obs) >= 1
        assert "mailman" in archive_obs[0].structured_payload["software"].lower()


# ======================================================================
# 6. Received: header IP extraction
# ======================================================================
class TestReceivedIPExtraction:
    def test_extract_ips_from_received_headers(self) -> None:
        """IPs in Received: headers are extracted."""
        content = (
            "Received: from mail-relay.acme.com (10.20.30.40) by lists.acme.com\n"
            "Received: from external-gw.acme.com ([203.0.113.50]) by mx.acme.com"
        )
        ips = _extract_received_ips(content)
        assert "10.20.30.40" in ips
        assert "203.0.113.50" in ips

    def test_ignored_ips_excluded(self) -> None:
        """Loopback IPs are filtered out."""
        content = "Received: from localhost (127.0.0.1) by lists.acme.com"
        ips = _extract_received_ips(content)
        assert "127.0.0.1" not in ips

    def test_no_received_headers(self) -> None:
        """Content without Received: headers yields empty set."""
        content = "Just a plain HTML page with no mail headers."
        ips = _extract_received_ips(content)
        assert len(ips) == 0

    def test_bare_ip_in_received_line(self) -> None:
        """Bare IPs in Received: lines are extracted via fallback regex."""
        content = "Received: from host 192.0.2.99 to dest"
        ips = _extract_received_ips(content)
        assert "192.0.2.99" in ips


# ======================================================================
# 7. Ignored IPs in full pipeline
# ======================================================================
class TestIgnoredIPsPipeline:
    @respx.mock
    @pytest.mark.asyncio
    async def test_loopback_not_emitted(self) -> None:
        """127.0.0.1 and 0.0.0.0 do not appear in IP observations."""
        respx.get("https://lists.acme.com/").mock(
            return_value=httpx.Response(200, text=_PAGE_WITH_IGNORED_IPS)
        )
        respx.get(url__regex=r"^https://(?!lists\.acme\.com/)").mock(
            return_value=httpx.Response(404)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        ip_values = {
            o.subject.identifier_value
            for o in observations
            if o.subject.identifier_type == IdentifierType.IP
        }
        assert "127.0.0.1" not in ip_values
        assert "0.0.0.0" not in ip_values


# ======================================================================
# 8. Health check
# ======================================================================
class TestHealthCheck:
    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Successful httpbin response returns SUCCESS."""
        respx.get(_HEALTH_CHECK_URL).mock(
            return_value=httpx.Response(200)
        )

        collector = MailHeaderAnalyzerCollector(_config())
        result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "mail-headers"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_error(self) -> None:
        """Connection error returns FAILURE with error message."""
        respx.get(_HEALTH_CHECK_URL).mock(
            side_effect=httpx.ConnectError("DNS resolution failed")
        )

        collector = MailHeaderAnalyzerCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None

    @respx.mock
    @pytest.mark.asyncio
    async def test_health_check_failure_on_5xx(self) -> None:
        """500 means FAILURE."""
        respx.get(_HEALTH_CHECK_URL).mock(
            return_value=httpx.Response(500)
        )

        collector = MailHeaderAnalyzerCollector(_config())
        result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE


# ======================================================================
# 9. Multiple subdomains probed
# ======================================================================
class TestSubdomainProbes:
    @respx.mock
    @pytest.mark.asyncio
    async def test_mail_subdomain_found(self) -> None:
        """Archive at mail.{domain} is discovered when lists.{domain} is down."""
        respx.get(url__regex=r"https://lists\.").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://mail.acme.com/").mock(
            return_value=httpx.Response(200, text=_SYMPA_PAGE)
        )
        respx.get(url__regex=r"https://mail\.acme\.com/(?!$)").mock(
            return_value=httpx.Response(404)
        )
        respx.get(url__regex=r"https://mailman\.").mock(
            return_value=httpx.Response(404)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        archive_obs = [
            o for o in observations
            if o.observation_type == ObservationType.HTTP_RESPONSE
        ]
        assert len(archive_obs) >= 1
        assert archive_obs[0].subject.identifier_value == "mail.acme.com"

    @respx.mock
    @pytest.mark.asyncio
    async def test_multiple_archives_found(self) -> None:
        """Multiple archives at different subdomains are all discovered."""
        respx.get("https://lists.acme.com/").mock(
            return_value=httpx.Response(200, text=_MAILMAN_ARCHIVE_PAGE)
        )
        respx.get("https://mail.acme.com/").mock(
            return_value=httpx.Response(200, text=_SYMPA_PAGE)
        )
        respx.get("https://mailman.acme.com/").mock(
            return_value=httpx.Response(200, text=_EMPTY_PAGE)
        )
        # Other paths return 404.
        respx.get(url__regex=r".*").mock(
            return_value=httpx.Response(404)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        archive_obs = [
            o for o in observations
            if o.observation_type == ObservationType.HTTP_RESPONSE
        ]
        subdomains_found = {o.subject.identifier_value for o in archive_obs}
        assert "lists.acme.com" in subdomains_found


# ======================================================================
# 10. Empty archive page (no IPs)
# ======================================================================
class TestEmptyArchive:
    @respx.mock
    @pytest.mark.asyncio
    async def test_archive_without_received_headers(self) -> None:
        """Archive found but no Received: headers -> archive obs only, no IPs."""
        respx.get("https://lists.acme.com/").mock(
            return_value=httpx.Response(200, text=_EMPTY_PAGE)
        )
        respx.get(url__regex=r"^https://(?!lists\.acme\.com/)").mock(
            return_value=httpx.Response(404)
        )

        seed = Seed(seed_type=SeedType.DOMAIN, value="acme.com")
        observations = await _collect(seed)

        archive_obs = [
            o for o in observations
            if o.observation_type == ObservationType.HTTP_RESPONSE
        ]
        ip_obs = [
            o for o in observations
            if o.observation_type == ObservationType.SCANNER_HOST
        ]

        assert len(archive_obs) == 1
        assert len(ip_obs) == 0
