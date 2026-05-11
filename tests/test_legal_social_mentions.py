"""Tests for the legal-social-mentions collector.

Coverage:
    1.  UDRP search with mocked HTTP responses
    2.  CVE/NVD search with mocked HTTP responses
    3.  Social mention (urlscan.io) detection
    4.  Observation format validation (structured_payload fields)
    5.  Health check success path
    6.  Health check failure paths (HTTP error, connection error)
    7.  Seed type filtering (domain only, skip IP/ORG/ASN)
    8.  Empty domain seed is skipped
    9.  Collector metadata (tier, credentials, technique_ids)
   10.  Collector is registered in DEFAULT_REGISTRY
   11.  Malformed JSON responses handled gracefully
   12.  HTTP error responses handled gracefully
   13.  Observation _collector_id tag present
   14.  FIPS gate: no banned imports in collector source
   15.  Empty API results produce no observations

All HTTP is mocked -- no real network calls are made.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import httpx
import pytest

from expose.collectors.base import (
    CollectorConfig,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.legal_social_mentions import (
    LegalSocialMentionsCollector,
    _extract_cve_observations,
    _extract_social_observations,
    _extract_udrp_observations,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus

# Synthetic IDs reused across tests (matches project conventions).
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000E001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000E002")


def _config() -> CollectorConfig:
    """Build a minimal CollectorConfig for test use."""
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        credentials={},
    )


# ---------------------------------------------------------------------------
# Mock API response factories
# ---------------------------------------------------------------------------


def _udrp_response(
    cases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a mock WIPO UDRP search response."""
    if cases is None:
        cases = [
            {
                "caseNumber": "D2024-0001",
                "status": "Decided",
                "decisionDate": "2024-03-15",
                "outcome": "Transfer",
                "complainant": "Example Corp",
                "respondent": "John Doe",
            },
        ]
    return {"cases": cases}


def _udrp_empty_response() -> dict[str, Any]:
    """Build a WIPO UDRP response with no cases."""
    return {"cases": []}


def _cve_response(
    vulnerabilities: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a mock NVD CVE API v2.0 response."""
    if vulnerabilities is None:
        vulnerabilities = [
            {
                "cve": {
                    "id": "CVE-2024-12345",
                    "published": "2024-01-10T12:00:00.000",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": (
                                "A vulnerability in example.com allows "
                                "remote code execution."
                            ),
                        },
                    ],
                    "references": [
                        {
                            "url": "https://example.com/advisory/2024-001",
                            "source": "vendor",
                        },
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseSeverity": "HIGH",
                                    "baseScore": 8.1,
                                },
                            },
                        ],
                    },
                },
            },
        ]
    return {"vulnerabilities": vulnerabilities}


def _cve_empty_response() -> dict[str, Any]:
    """Build a NVD CVE response with no vulnerabilities."""
    return {"vulnerabilities": []}


def _social_response(
    results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a mock urlscan.io search response."""
    if results is None:
        results = [
            {
                "task": {
                    "url": "https://example.com/login",
                    "time": "2024-06-01T10:00:00.000Z",
                    "visibility": "public",
                },
                "page": {
                    "title": "Example Login Page",
                    "domain": "example.com",
                    "ip": "93.184.216.34",
                },
                "result": "https://urlscan.io/result/abc123/",
            },
        ]
    return {"results": results}


def _social_empty_response() -> dict[str, Any]:
    """Build a urlscan.io response with no results."""
    return {"results": []}


def _mock_http_response(
    status_code: int = 200,
    json_data: Any = None,
) -> MagicMock:
    """Create a mock httpx response object."""
    resp = MagicMock()
    resp.status_code = status_code
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("No JSON")
    return resp


def _mock_client(responses: list[MagicMock]) -> AsyncMock:
    """Create a mock httpx.AsyncClient returning responses in order."""
    client = AsyncMock()
    client.get = AsyncMock(side_effect=responses)
    client.head = AsyncMock(return_value=responses[0] if responses else MagicMock())
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


# ---------------------------------------------------------------------------
# Extraction function unit tests
# ---------------------------------------------------------------------------


class TestUdrpExtraction:
    """Test WIPO UDRP response parsing."""

    def test_extract_udrp_single_case(self) -> None:
        """Single UDRP case is extracted correctly."""
        data = _udrp_response()
        mentions = _extract_udrp_observations(data, "example.com")

        assert len(mentions) == 1
        m = mentions[0]
        assert m["mention_type"] == "udrp"
        assert m["source"] == "wipo_udrp"
        assert m["case_number"] == "D2024-0001"
        assert m["status"] == "Decided"
        assert m["outcome"] == "Transfer"
        assert m["severity"] == "medium"
        assert m["_collector_id"] == "legal-social-mentions"
        assert "D2024-0001" in m["title"]
        assert "D2024-0001" in m["url"]

    def test_extract_udrp_multiple_cases(self) -> None:
        """Multiple UDRP cases are all extracted."""
        cases = [
            {
                "caseNumber": f"D2024-{i:04d}",
                "status": "Decided",
                "decisionDate": f"2024-0{i}-01",
                "outcome": "Transfer",
                "complainant": "Corp",
                "respondent": "Doe",
            }
            for i in range(1, 4)
        ]
        data = _udrp_response(cases=cases)
        mentions = _extract_udrp_observations(data, "example.com")

        assert len(mentions) == 3

    def test_extract_udrp_empty_cases(self) -> None:
        """Empty cases list produces no mentions."""
        data = _udrp_empty_response()
        mentions = _extract_udrp_observations(data, "example.com")

        assert mentions == []

    def test_extract_udrp_missing_case_number_skipped(self) -> None:
        """Cases without a case number are skipped."""
        data = _udrp_response(cases=[{"status": "Decided"}])
        mentions = _extract_udrp_observations(data, "example.com")

        assert mentions == []

    def test_extract_udrp_non_list_cases(self) -> None:
        """Non-list 'cases' value produces no mentions."""
        data = {"cases": "not a list"}
        mentions = _extract_udrp_observations(data, "example.com")

        assert mentions == []

    def test_extract_udrp_non_dict_case_entries(self) -> None:
        """Non-dict entries in cases list are skipped."""
        data = {"cases": ["string", 42, None]}
        mentions = _extract_udrp_observations(data, "example.com")

        assert mentions == []


class TestCveExtraction:
    """Test NVD CVE response parsing."""

    def test_extract_cve_single_vulnerability(self) -> None:
        """Single CVE is extracted with correct fields."""
        data = _cve_response()
        mentions = _extract_cve_observations(data, "example.com")

        assert len(mentions) == 1
        m = mentions[0]
        assert m["mention_type"] == "cve"
        assert m["source"] == "nvd"
        assert m["cve_id"] == "CVE-2024-12345"
        assert m["severity"] == "high"
        assert m["_collector_id"] == "legal-social-mentions"
        assert "CVE-2024-12345" in m["title"]
        assert "nvd.nist.gov" in m["url"]
        assert "remote code execution" in m["snippet"]

    def test_extract_cve_critical_severity(self) -> None:
        """CRITICAL severity maps correctly."""
        vuln = {
            "cve": {
                "id": "CVE-2024-99999",
                "published": "2024-12-01",
                "descriptions": [{"lang": "en", "value": "Critical vuln"}],
                "references": [],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseSeverity": "CRITICAL", "baseScore": 9.8}},
                    ],
                },
            },
        }
        data = _cve_response(vulnerabilities=[vuln])
        mentions = _extract_cve_observations(data, "example.com")

        assert len(mentions) == 1
        assert mentions[0]["severity"] == "critical"

    def test_extract_cve_low_severity(self) -> None:
        """LOW severity maps correctly."""
        vuln = {
            "cve": {
                "id": "CVE-2024-00001",
                "published": "2024-01-01",
                "descriptions": [{"lang": "en", "value": "Low vuln"}],
                "references": [],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseSeverity": "LOW", "baseScore": 2.0}},
                    ],
                },
            },
        }
        data = _cve_response(vulnerabilities=[vuln])
        mentions = _extract_cve_observations(data, "example.com")

        assert len(mentions) == 1
        assert mentions[0]["severity"] == "low"

    def test_extract_cve_no_metrics_defaults_to_info(self) -> None:
        """Missing CVSS metrics default severity to 'info'."""
        vuln = {
            "cve": {
                "id": "CVE-2024-00002",
                "published": "2024-01-01",
                "descriptions": [{"lang": "en", "value": "No metrics"}],
                "references": [],
                "metrics": {},
            },
        }
        data = _cve_response(vulnerabilities=[vuln])
        mentions = _extract_cve_observations(data, "example.com")

        assert len(mentions) == 1
        assert mentions[0]["severity"] == "info"

    def test_extract_cve_empty_vulnerabilities(self) -> None:
        """Empty vulnerabilities list produces no mentions."""
        data = _cve_empty_response()
        mentions = _extract_cve_observations(data, "example.com")

        assert mentions == []

    def test_extract_cve_missing_id_skipped(self) -> None:
        """Vulnerabilities without a CVE ID are skipped."""
        data = _cve_response(vulnerabilities=[{"cve": {"descriptions": []}}])
        mentions = _extract_cve_observations(data, "example.com")

        assert mentions == []

    def test_extract_cve_non_list_vulnerabilities(self) -> None:
        """Non-list 'vulnerabilities' value produces no mentions."""
        data = {"vulnerabilities": "not a list"}
        mentions = _extract_cve_observations(data, "example.com")

        assert mentions == []

    def test_extract_cve_v30_metrics_fallback(self) -> None:
        """Falls back to CVSS v3.0 when v3.1 is absent."""
        vuln = {
            "cve": {
                "id": "CVE-2024-00003",
                "published": "2024-02-01",
                "descriptions": [{"lang": "en", "value": "V30 vuln"}],
                "references": [],
                "metrics": {
                    "cvssMetricV30": [
                        {"cvssData": {"baseSeverity": "MEDIUM", "baseScore": 5.0}},
                    ],
                },
            },
        }
        data = _cve_response(vulnerabilities=[vuln])
        mentions = _extract_cve_observations(data, "example.com")

        assert len(mentions) == 1
        assert mentions[0]["severity"] == "medium"


class TestSocialExtraction:
    """Test urlscan.io response parsing."""

    def test_extract_social_single_result(self) -> None:
        """Single scan result is extracted correctly."""
        data = _social_response()
        mentions = _extract_social_observations(data, "example.com")

        assert len(mentions) == 1
        m = mentions[0]
        assert m["mention_type"] == "social"
        assert m["source"] == "urlscan"
        assert m["title"] == "Example Login Page"
        assert m["severity"] == "info"
        assert m["_collector_id"] == "legal-social-mentions"
        assert "urlscan.io" in m["url"]
        assert "example.com/login" in m["snippet"]

    def test_extract_social_no_title_uses_domain(self) -> None:
        """Missing page title falls back to domain-based title."""
        data = _social_response(results=[{
            "task": {
                "url": "https://example.com",
                "time": "2024-06-01",
                "visibility": "public",
            },
            "page": {
                "title": "",
                "domain": "example.com",
                "ip": "1.2.3.4",
            },
            "result": "https://urlscan.io/result/def456/",
        }])
        mentions = _extract_social_observations(data, "example.com")

        assert len(mentions) == 1
        assert "example.com" in mentions[0]["title"]

    def test_extract_social_empty_results(self) -> None:
        """Empty results list produces no mentions."""
        data = _social_empty_response()
        mentions = _extract_social_observations(data, "example.com")

        assert mentions == []

    def test_extract_social_non_list_results(self) -> None:
        """Non-list 'results' value produces no mentions."""
        data = {"results": "not a list"}
        mentions = _extract_social_observations(data, "example.com")

        assert mentions == []

    def test_extract_social_non_dict_entries(self) -> None:
        """Non-dict entries in results list are skipped."""
        data = {"results": [42, "string", None]}
        mentions = _extract_social_observations(data, "example.com")

        assert mentions == []


# ---------------------------------------------------------------------------
# Collector integration tests
# ---------------------------------------------------------------------------


class TestLegalSocialMentionsCollector:
    """Test the collector end-to-end with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_expand_produces_all_source_observations(self) -> None:
        """Collector yields observations from all three sources."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        udrp_resp = _mock_http_response(200, _udrp_response())
        cve_resp = _mock_http_response(200, _cve_response())
        social_resp = _mock_http_response(200, _social_response())
        client = _mock_client([udrp_resp, cve_resp, social_resp])

        with patch("httpx.AsyncClient", return_value=client):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        # 1 UDRP + 1 CVE + 1 social = 3.
        assert len(observations) == 3

        # Verify all are Observation instances.
        for obs in observations:
            assert isinstance(obs, Observation)
            assert obs.observation_type == ObservationType.DARK_WEB_MENTION
            assert obs.collector_id == "legal-social-mentions"
            assert obs.tenant_id == TENANT_ID
            assert obs.subject.identifier_value == "example.com"

        # Verify mention types.
        mention_types = [
            obs.structured_payload["mention_type"] for obs in observations
        ]
        assert "udrp" in mention_types
        assert "cve" in mention_types
        assert "social" in mention_types

    @pytest.mark.asyncio
    async def test_expand_udrp_only(self) -> None:
        """Collector yields UDRP observations when other sources are empty."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        udrp_resp = _mock_http_response(200, _udrp_response())
        cve_resp = _mock_http_response(200, _cve_empty_response())
        social_resp = _mock_http_response(200, _social_empty_response())
        client = _mock_client([udrp_resp, cve_resp, social_resp])

        with patch("httpx.AsyncClient", return_value=client):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].structured_payload["mention_type"] == "udrp"

    @pytest.mark.asyncio
    async def test_expand_cve_severity_in_payload(self) -> None:
        """CVE observations carry severity from CVSS metrics."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        udrp_resp = _mock_http_response(200, _udrp_empty_response())
        cve_resp = _mock_http_response(200, _cve_response())
        social_resp = _mock_http_response(200, _social_empty_response())
        client = _mock_client([udrp_resp, cve_resp, social_resp])

        with patch("httpx.AsyncClient", return_value=client):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert payload["severity"] == "high"
        assert payload["cve_id"] == "CVE-2024-12345"

    @pytest.mark.asyncio
    async def test_expand_handles_api_errors_gracefully(self) -> None:
        """Collector continues when one source returns an error."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        udrp_resp = _mock_http_response(500)
        udrp_resp.json.return_value = {}
        cve_resp = _mock_http_response(200, _cve_response())
        social_resp = _mock_http_response(200, _social_response())
        client = _mock_client([udrp_resp, cve_resp, social_resp])

        with patch("httpx.AsyncClient", return_value=client):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        # UDRP failed, but CVE and social should still produce results.
        assert len(observations) == 2
        mention_types = [
            obs.structured_payload["mention_type"] for obs in observations
        ]
        assert "udrp" not in mention_types
        assert "cve" in mention_types
        assert "social" in mention_types

    @pytest.mark.asyncio
    async def test_expand_handles_malformed_json(self) -> None:
        """Collector handles malformed JSON responses gracefully."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        udrp_resp = _mock_http_response(200)
        udrp_resp.json.side_effect = ValueError("bad json")
        cve_resp = _mock_http_response(200, _cve_empty_response())
        social_resp = _mock_http_response(200, _social_empty_response())
        client = _mock_client([udrp_resp, cve_resp, social_resp])

        with patch("httpx.AsyncClient", return_value=client):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        assert observations == []

    @pytest.mark.asyncio
    async def test_expand_handles_connection_error(self) -> None:
        """Collector handles httpx connection errors gracefully."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=client):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        # All three sources failed, but no exception propagated.
        assert observations == []

    @pytest.mark.asyncio
    async def test_expand_404_produces_no_observations(self) -> None:
        """HTTP 404 responses produce no observations."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        udrp_resp = _mock_http_response(404)
        cve_resp = _mock_http_response(404)
        social_resp = _mock_http_response(404)
        client = _mock_client([udrp_resp, cve_resp, social_resp])

        with patch("httpx.AsyncClient", return_value=client):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        assert observations == []

    @pytest.mark.asyncio
    async def test_expand_all_sources_empty(self) -> None:
        """All sources returning empty results produces no observations."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        udrp_resp = _mock_http_response(200, _udrp_empty_response())
        cve_resp = _mock_http_response(200, _cve_empty_response())
        social_resp = _mock_http_response(200, _social_empty_response())
        client = _mock_client([udrp_resp, cve_resp, social_resp])

        with patch("httpx.AsyncClient", return_value=client):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        assert observations == []


# ---------------------------------------------------------------------------
# Seed type filtering
# ---------------------------------------------------------------------------


class TestSeedTypeFiltering:
    """Verify the collector only processes DOMAIN seeds."""

    @pytest.mark.asyncio
    async def test_skips_ip_seeds(self) -> None:
        """Collector produces no observations for IP seeds."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        seed = Seed(seed_type=SeedType.IP, value="93.184.216.34")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []

    @pytest.mark.asyncio
    async def test_skips_organization_seeds(self) -> None:
        """Collector produces no observations for ORGANIZATION seeds."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        seed = Seed(seed_type=SeedType.ORGANIZATION, value="Example Corp")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []

    @pytest.mark.asyncio
    async def test_skips_asn_seeds(self) -> None:
        """Collector produces no observations for ASN seeds."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []

    @pytest.mark.asyncio
    async def test_skips_cidr_seeds(self) -> None:
        """Collector produces no observations for CIDR seeds."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        seed = Seed(seed_type=SeedType.CIDR, value="10.0.0.0/8")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []

    @pytest.mark.asyncio
    async def test_skips_empty_domain(self) -> None:
        """Collector skips empty or whitespace-only domain seeds."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        seed = Seed(seed_type=SeedType.DOMAIN, value="   ")
        observations = [obs async for obs in collector.expand(seed)]

        assert observations == []

    @pytest.mark.asyncio
    async def test_domain_is_lowercased(self) -> None:
        """Domain seed value is lowercased before queries."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        udrp_resp = _mock_http_response(200, _udrp_response())
        cve_resp = _mock_http_response(200, _cve_empty_response())
        social_resp = _mock_http_response(200, _social_empty_response())
        client = _mock_client([udrp_resp, cve_resp, social_resp])

        with patch("httpx.AsyncClient", return_value=client):
            seed = Seed(seed_type=SeedType.DOMAIN, value="  EXAMPLE.COM  ")
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].subject.identifier_value == "example.com"


# ---------------------------------------------------------------------------
# Observation format validation
# ---------------------------------------------------------------------------


class TestObservationFormat:
    """Verify observation structured_payload conforms to spec."""

    @pytest.mark.asyncio
    async def test_udrp_observation_payload_fields(self) -> None:
        """UDRP observation has all required payload fields."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        udrp_resp = _mock_http_response(200, _udrp_response())
        cve_resp = _mock_http_response(200, _cve_empty_response())
        social_resp = _mock_http_response(200, _social_empty_response())
        client = _mock_client([udrp_resp, cve_resp, social_resp])

        with patch("httpx.AsyncClient", return_value=client):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload

        required_fields = [
            "mention_type", "source", "title", "url", "date",
            "snippet", "severity", "_collector_id",
        ]
        for field in required_fields:
            assert field in payload, f"Missing required field: {field}"

        assert payload["mention_type"] == "udrp"
        assert payload["_collector_id"] == "legal-social-mentions"

    @pytest.mark.asyncio
    async def test_cve_observation_payload_fields(self) -> None:
        """CVE observation has all required payload fields."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        udrp_resp = _mock_http_response(200, _udrp_empty_response())
        cve_resp = _mock_http_response(200, _cve_response())
        social_resp = _mock_http_response(200, _social_empty_response())
        client = _mock_client([udrp_resp, cve_resp, social_resp])

        with patch("httpx.AsyncClient", return_value=client):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload

        required_fields = [
            "mention_type", "source", "title", "url", "date",
            "snippet", "severity", "cve_id", "_collector_id",
        ]
        for field in required_fields:
            assert field in payload, f"Missing required field: {field}"

        assert payload["mention_type"] == "cve"

    @pytest.mark.asyncio
    async def test_social_observation_payload_fields(self) -> None:
        """Social observation has all required payload fields."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        udrp_resp = _mock_http_response(200, _udrp_empty_response())
        cve_resp = _mock_http_response(200, _cve_empty_response())
        social_resp = _mock_http_response(200, _social_response())
        client = _mock_client([udrp_resp, cve_resp, social_resp])

        with patch("httpx.AsyncClient", return_value=client):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        payload = observations[0].structured_payload

        required_fields = [
            "mention_type", "source", "title", "url", "date",
            "snippet", "severity", "_collector_id",
        ]
        for field in required_fields:
            assert field in payload, f"Missing required field: {field}"

        assert payload["mention_type"] == "social"


# ---------------------------------------------------------------------------
# Collector metadata
# ---------------------------------------------------------------------------


class TestCollectorMetadata:
    """Verify collector class-level metadata."""

    def test_collector_id(self) -> None:
        """Collector ID is 'legal-social-mentions'."""
        assert LegalSocialMentionsCollector.collector_id == "legal-social-mentions"

    def test_collector_version(self) -> None:
        """Collector version is set."""
        assert LegalSocialMentionsCollector.collector_version == "0.1.0"

    def test_collector_is_tier_1(self) -> None:
        """Collector is classified as Tier 1."""
        assert LegalSocialMentionsCollector.tier == CollectorTier.TIER_1

    def test_collector_requires_no_credentials(self) -> None:
        """Collector does not require credentials."""
        assert LegalSocialMentionsCollector.requires_credentials is False

    def test_collector_technique_ids(self) -> None:
        """Collector declares T1593.001 (Search Open Websites/Domains)."""
        assert LegalSocialMentionsCollector.technique_ids == ["T1593.001"]

    def test_collector_rate_limit(self) -> None:
        """Collector declares a rate limit."""
        assert LegalSocialMentionsCollector.rate_limit_per_minute == 20

    def test_collector_display_name(self) -> None:
        """Collector has a display name."""
        assert LegalSocialMentionsCollector.display_name == "Legal & Social Media Mentions"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestRegistry:
    """Verify the collector is properly registered."""

    def test_collector_registered_in_default_registry(self) -> None:
        """legal-social-mentions is registered in DEFAULT_REGISTRY."""
        assert DEFAULT_REGISTRY.is_registered("legal-social-mentions")

    def test_registry_returns_correct_class(self) -> None:
        """Registry returns LegalSocialMentionsCollector."""
        cls = DEFAULT_REGISTRY.get("legal-social-mentions")
        assert cls is LegalSocialMentionsCollector


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


class TestHealthCheck:
    """Test the health check endpoint."""

    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Health check returns SUCCESS on HTTP 200."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.head.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "legal-social-mentions"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @pytest.mark.asyncio
    async def test_health_check_failure_http_error(self) -> None:
        """Health check returns FAILURE on HTTP error status."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.head.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE

    @pytest.mark.asyncio
    async def test_health_check_failure_connection_error(self) -> None:
        """Health check returns FAILURE on connection exception."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.head.side_effect = httpx.ConnectError("Connection refused")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert "WIPO UDRP unreachable" in (result.error_message or "")

    @pytest.mark.asyncio
    async def test_health_check_latency_recorded(self) -> None:
        """Health check records latency in milliseconds."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.head.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await collector.health_check()

        assert result.latency_ms is not None
        assert isinstance(result.latency_ms, float)


# ---------------------------------------------------------------------------
# FIPS gate compliance
# ---------------------------------------------------------------------------


class TestFipsCompliance:
    """Verify the collector source does not import banned crypto modules."""

    BANNED_PATTERNS = [
        re.compile(r"^\s*import\s+hashlib\b", re.MULTILINE),
        re.compile(r"^\s*from\s+hashlib\b", re.MULTILINE),
        re.compile(r"^\s*import\s+secrets\b", re.MULTILINE),
        re.compile(r"^\s*from\s+secrets\b", re.MULTILINE),
        re.compile(r"^\s*from\s+Crypto\b", re.MULTILINE),
        re.compile(r"^\s*import\s+Crypto\b", re.MULTILINE),
    ]

    REPO_ROOT = Path(__file__).resolve().parent.parent

    NEW_FILES = [
        REPO_ROOT
        / "src"
        / "expose"
        / "collectors"
        / "builtin"
        / "legal_social_mentions.py",
    ]

    @pytest.mark.parametrize(
        "path",
        NEW_FILES,
        ids=lambda p: str(p.name),
    )
    def test_no_banned_crypto_imports(self, path: Path) -> None:
        """Collector source must not import banned crypto modules."""
        text = path.read_text(encoding="utf-8")
        violations = []
        for pattern in self.BANNED_PATTERNS:
            for match in pattern.finditer(text):
                line_no = text[: match.start()].count("\n") + 1
                violations.append(
                    f"  {path.name}:{line_no}: {match.group(0).strip()}"
                )
        assert not violations, (
            "Non-FIPS crypto import found (violates ADR-010):\n"
            + "\n".join(violations)
        )


# ---------------------------------------------------------------------------
# NVD rate limit handling
# ---------------------------------------------------------------------------


class TestNvdRateLimit:
    """Test NVD API rate limit (403) handling."""

    @pytest.mark.asyncio
    async def test_nvd_403_produces_warning_not_crash(self) -> None:
        """NVD 403 rate limit adds warning but doesn't crash."""
        config = _config()
        collector = LegalSocialMentionsCollector(config)

        udrp_resp = _mock_http_response(200, _udrp_empty_response())
        cve_resp = _mock_http_response(403)
        cve_resp.json.return_value = {}
        social_resp = _mock_http_response(200, _social_empty_response())
        client = _mock_client([udrp_resp, cve_resp, social_resp])

        with patch("httpx.AsyncClient", return_value=client):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        # No crash, no CVE observations.
        assert observations == []
