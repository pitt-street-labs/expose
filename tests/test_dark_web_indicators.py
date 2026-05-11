"""Tests for the dark-web-indicators collector and DarkWebEnricher.

Coverage:
    1. DarkWebEnricher produces IoC indicators for credential breaches (HIBP)
    2. DarkWebEnricher produces IoI indicators for non-credential breaches
    3. DarkWebEnricher produces indicators from IntelX
    4. DarkWebEnricher produces indicators from DeHashed
    5. DarkWebEnricher skips sources with missing credentials
    6. Collector integrates with enricher (end-to-end with mocked APIs)
    7. Collector skips non-DOMAIN seeds
    8. Tier-3 gating applies (collector is TIER_3)
    9. License check function exists and returns True
   10. Health check success and failure paths
   11. Collector is registered in DEFAULT_REGISTRY
   12. Credential spec exists in CREDENTIAL_SPECS
   13. FIPS gate: no banned imports in new source files
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from expose.collectors.base import (
    CollectorConfig,
    CollectorCredential,
    CollectorHealthCheck,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.dark_web_indicators import (
    DarkWebIndicatorsCollector,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.modules.threat_context import check_license
from expose.modules.threat_context.dark_web import (
    DarkWebEnricher,
    IndicatorType,
    ThreatIndicator,
)
from expose.pipeline.credential_resolver import CREDENTIAL_SPECS
from expose.types.canonical import CollectorStatus

# Synthetic IDs reused across tests (matches project conventions).
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000D001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000D002")


def _config(
    credentials: dict[str, CollectorCredential] | None = None,
) -> CollectorConfig:
    """Build a minimal CollectorConfig for test use."""
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        credentials=credentials or {},
    )


def _config_with_hibp() -> CollectorConfig:
    """Build a CollectorConfig with HIBP API key credential."""
    return _config(
        credentials={
            "hibp_api_key": CollectorCredential(
                name="hibp_api_key", secret_value="test-hibp-key-123"
            ),
        }
    )


def _config_with_all_credentials() -> CollectorConfig:
    """Build a CollectorConfig with all dark web credentials."""
    return _config(
        credentials={
            "hibp_api_key": CollectorCredential(
                name="hibp_api_key", secret_value="test-hibp-key-123"
            ),
            "intelx_api_key": CollectorCredential(
                name="intelx_api_key", secret_value="test-intelx-key-456"
            ),
            "dehashed_email": CollectorCredential(
                name="dehashed_email", secret_value="test@example.com"
            ),
            "dehashed_api_key": CollectorCredential(
                name="dehashed_api_key", secret_value="test-dehashed-key-789"
            ),
        }
    )


# === Mock API response factories =============================================


def _hibp_breach_response(
    name: str = "TestBreach",
    domain: str = "example.com",
    pwn_count: int = 10000,
    data_classes: list[str] | None = None,
    is_verified: bool = True,
    breach_date: str = "2024-01-15",
) -> dict[str, Any]:
    """Build a mock HIBP breach response object."""
    if data_classes is None:
        data_classes = ["Email addresses", "Passwords"]
    return {
        "Name": name,
        "Title": name,
        "Domain": domain,
        "BreachDate": breach_date,
        "PwnCount": pwn_count,
        "DataClasses": data_classes,
        "IsVerified": is_verified,
        "IsFabricated": False,
        "IsSensitive": False,
        "IsRetired": False,
        "IsSpamList": False,
    }


def _intelx_search_response(search_id: str = "test-search-id") -> dict[str, Any]:
    """Build a mock IntelX search initiation response."""
    return {"id": search_id, "status": 0}


def _intelx_results_response(
    selectors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a mock IntelX search results response."""
    if selectors is None:
        selectors = [
            {"selectorvalue": "leaked@example.com", "selectortype": 1},
            {"selectorvalue": "example.com", "selectortype": 2},
        ]
    return {"selectors": selectors, "status": 0}


def _dehashed_response(
    entries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a mock DeHashed search response."""
    if entries is None:
        entries = [
            {
                "email": "user@example.com",
                "database_name": "LeakedDB",
                "password": "plaintext123",
                "hashed_password": "",
            },
            {
                "email": "other@example.com",
                "database_name": "AnotherLeak",
                "password": "",
                "hashed_password": "",
            },
        ]
    return {"entries": entries, "total": len(entries)}


# === DarkWebEnricher tests ====================================================


class TestDarkWebEnricher:
    """Test the DarkWebEnricher produces correct indicator types."""

    @pytest.mark.asyncio
    async def test_hibp_credential_breach_produces_ioc(self) -> None:
        """HIBP breach with passwords produces IoC indicator."""
        breach = _hibp_breach_response(
            data_classes=["Email addresses", "Passwords"],
            is_verified=True,
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [breach]

        enricher = DarkWebEnricher(hibp_api_key="test-key")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            indicators = await enricher.enrich_domain("example.com")

        assert len(indicators) == 1
        assert indicators[0].indicator_type == IndicatorType.IOC
        assert indicators[0].source == "hibp"
        assert indicators[0].confidence == 0.9
        assert "Passwords" in indicators[0].description

    @pytest.mark.asyncio
    async def test_hibp_non_credential_breach_produces_ioi(self) -> None:
        """HIBP breach without passwords produces IoI indicator."""
        breach = _hibp_breach_response(
            data_classes=["Email addresses", "IP addresses"],
            is_verified=True,
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [breach]

        enricher = DarkWebEnricher(hibp_api_key="test-key")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            indicators = await enricher.enrich_domain("example.com")

        assert len(indicators) == 1
        assert indicators[0].indicator_type == IndicatorType.IOI
        assert indicators[0].source == "hibp"

    @pytest.mark.asyncio
    async def test_hibp_unverified_breach_lower_confidence(self) -> None:
        """Unverified HIBP breach has lower confidence (0.5 vs 0.9)."""
        breach = _hibp_breach_response(is_verified=False)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [breach]

        enricher = DarkWebEnricher(hibp_api_key="test-key")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            indicators = await enricher.enrich_domain("example.com")

        assert len(indicators) == 1
        assert indicators[0].confidence == 0.5

    @pytest.mark.asyncio
    async def test_intelx_produces_ioi_indicators(self) -> None:
        """IntelX results produce IoI indicators."""
        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.json.return_value = _intelx_search_response()

        results_resp = MagicMock()
        results_resp.status_code = 200
        results_resp.json.return_value = _intelx_results_response()

        enricher = DarkWebEnricher(intelx_api_key="test-key")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = search_resp
            mock_client.get.return_value = results_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            indicators = await enricher.enrich_domain("example.com")

        assert len(indicators) == 2
        assert all(i.indicator_type == IndicatorType.IOI for i in indicators)
        assert all(i.source == "intelx" for i in indicators)

    @pytest.mark.asyncio
    async def test_dehashed_with_password_produces_ioc(self) -> None:
        """DeHashed entry with password produces IoC indicator."""
        entries = [
            {
                "email": "user@example.com",
                "database_name": "LeakedDB",
                "password": "plaintext123",
                "hashed_password": "",
            },
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _dehashed_response(entries=entries)

        enricher = DarkWebEnricher(
            dehashed_email="test@example.com",
            dehashed_api_key="test-key",
        )

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            indicators = await enricher.enrich_domain("example.com")

        assert len(indicators) == 1
        assert indicators[0].indicator_type == IndicatorType.IOC
        assert indicators[0].source == "dehashed"
        assert indicators[0].confidence == 0.8

    @pytest.mark.asyncio
    async def test_dehashed_without_password_produces_ioi(self) -> None:
        """DeHashed entry without password produces IoI indicator."""
        entries = [
            {
                "email": "user@example.com",
                "database_name": "LeakedDB",
                "password": "",
                "hashed_password": "",
            },
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _dehashed_response(entries=entries)

        enricher = DarkWebEnricher(
            dehashed_email="test@example.com",
            dehashed_api_key="test-key",
        )

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            indicators = await enricher.enrich_domain("example.com")

        assert len(indicators) == 1
        assert indicators[0].indicator_type == IndicatorType.IOI
        assert indicators[0].confidence == 0.5

    @pytest.mark.asyncio
    async def test_enricher_skips_unconfigured_sources(self) -> None:
        """Enricher with no credentials configured returns empty list."""
        enricher = DarkWebEnricher()
        indicators = await enricher.enrich_domain("example.com")
        assert indicators == []

    @pytest.mark.asyncio
    async def test_enricher_email_skips_unconfigured_sources(self) -> None:
        """Enricher email method with no credentials returns empty list."""
        enricher = DarkWebEnricher()
        indicators = await enricher.enrich_email("user@example.com")
        assert indicators == []

    @pytest.mark.asyncio
    async def test_hibp_404_no_indicators(self) -> None:
        """HIBP returning 404 (no breaches) produces no indicators."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        enricher = DarkWebEnricher(hibp_api_key="test-key")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            indicators = await enricher.enrich_domain("clean-domain.com")

        assert indicators == []


# === Collector integration tests ==============================================


class TestDarkWebIndicatorsCollector:
    """Test the collector integrates with DarkWebEnricher."""

    @pytest.mark.asyncio
    async def test_collector_produces_observations(self) -> None:
        """Collector yields observations from enricher results."""
        config = _config_with_hibp()
        collector = DarkWebIndicatorsCollector(config)

        mock_indicators = [
            ThreatIndicator(
                indicator_type=IndicatorType.IOC,
                source="hibp",
                first_seen=None,
                last_seen=None,
                confidence=0.9,
                description="Test breach for example.com",
            ),
            ThreatIndicator(
                indicator_type=IndicatorType.IOI,
                source="intelx",
                first_seen=None,
                last_seen=None,
                confidence=0.6,
                description="IntelX mention of example.com",
            ),
        ]

        with patch.object(
            collector._enricher,
            "enrich_domain",
            new_callable=AsyncMock,
            return_value=mock_indicators,
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 2

        # First observation: IoC from HIBP.
        obs_ioc = observations[0]
        assert isinstance(obs_ioc, Observation)
        assert obs_ioc.observation_type == ObservationType.DARK_WEB_MENTION
        assert obs_ioc.collector_id == "dark-web-indicators"
        assert obs_ioc.tenant_id == TENANT_ID
        assert obs_ioc.structured_payload["indicator_type"] == "ioc"
        assert obs_ioc.structured_payload["source"] == "hibp"
        assert obs_ioc.structured_payload["confidence"] == 0.9

        # Second observation: IoI from IntelX.
        obs_ioi = observations[1]
        assert obs_ioi.structured_payload["indicator_type"] == "ioi"
        assert obs_ioi.structured_payload["source"] == "intelx"

    @pytest.mark.asyncio
    async def test_collector_skips_non_domain_seeds(self) -> None:
        """Collector skips seeds that are not DOMAIN type."""
        config = _config_with_hibp()
        collector = DarkWebIndicatorsCollector(config)

        for seed_type in (SeedType.IP, SeedType.ORGANIZATION, SeedType.ASN):
            seed = Seed(seed_type=seed_type, value="test-value")
            observations = [obs async for obs in collector.expand(seed)]
            assert observations == [], f"Expected no observations for {seed_type}"

    @pytest.mark.asyncio
    async def test_collector_skips_empty_domain(self) -> None:
        """Collector skips empty or whitespace-only domain seeds."""
        config = _config_with_hibp()
        collector = DarkWebIndicatorsCollector(config)

        seed = Seed(seed_type=SeedType.DOMAIN, value="   ")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []

    @pytest.mark.asyncio
    async def test_collector_observation_subject(self) -> None:
        """Observations have correct subject (domain identifier)."""
        config = _config_with_hibp()
        collector = DarkWebIndicatorsCollector(config)

        mock_indicators = [
            ThreatIndicator(
                indicator_type=IndicatorType.IOC,
                source="hibp",
                first_seen=None,
                last_seen=None,
                confidence=0.9,
                description="Test breach",
            ),
        ]

        with patch.object(
            collector._enricher,
            "enrich_domain",
            new_callable=AsyncMock,
            return_value=mock_indicators,
        ):
            seed = Seed(seed_type=SeedType.DOMAIN, value="  EXAMPLE.COM  ")
            observations = [obs async for obs in collector.expand(seed)]

        assert len(observations) == 1
        assert observations[0].subject.identifier_value == "example.com"

    @pytest.mark.asyncio
    async def test_collector_no_credentials(self) -> None:
        """Collector with no credentials produces no observations."""
        config = _config()
        collector = DarkWebIndicatorsCollector(config)

        seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
        observations = [obs async for obs in collector.expand(seed)]
        assert observations == []


# === Tier-3 gating tests =====================================================


class TestTier3Gating:
    """Verify the collector is properly tagged as Tier 3."""

    def test_collector_is_tier_3(self) -> None:
        """DarkWebIndicatorsCollector is classified as Tier 3."""
        assert DarkWebIndicatorsCollector.tier == CollectorTier.TIER_3

    def test_collector_requires_credentials(self) -> None:
        """Collector declares that it requires credentials."""
        assert DarkWebIndicatorsCollector.requires_credentials is True

    def test_collector_technique_ids(self) -> None:
        """Collector declares T1597 (Search Closed Sources)."""
        assert DarkWebIndicatorsCollector.technique_ids == ["T1597"]


# === License check tests =====================================================


class TestLicenseCheck:
    """Verify the Threat Context module license gate."""

    def test_check_license_exists(self) -> None:
        """check_license function exists and is callable."""
        assert callable(check_license)

    def test_check_license_returns_true(self) -> None:
        """check_license returns True (placeholder per ADR-009)."""
        assert check_license() is True


# === Registry and credential spec tests ======================================


class TestRegistryAndCredentials:
    """Verify the collector is properly registered and has credential specs."""

    def test_collector_registered(self) -> None:
        """dark-web-indicators is registered in DEFAULT_REGISTRY."""
        assert DEFAULT_REGISTRY.is_registered("dark-web-indicators")

    def test_collector_class_from_registry(self) -> None:
        """Registry returns the correct class."""
        cls = DEFAULT_REGISTRY.get("dark-web-indicators")
        assert cls is DarkWebIndicatorsCollector

    def test_credential_spec_exists(self) -> None:
        """CREDENTIAL_SPECS has an entry for dark-web-indicators."""
        assert "dark-web-indicators" in CREDENTIAL_SPECS

    def test_credential_spec_required_keys(self) -> None:
        """Required key is hibp_api_key."""
        spec = CREDENTIAL_SPECS["dark-web-indicators"]
        assert spec.required_keys == ["hibp_api_key"]

    def test_credential_spec_optional_keys(self) -> None:
        """Optional keys include intelx, dehashed email, and dehashed key."""
        spec = CREDENTIAL_SPECS["dark-web-indicators"]
        assert "intelx_api_key" in spec.optional_keys
        assert "dehashed_email" in spec.optional_keys
        assert "dehashed_api_key" in spec.optional_keys


# === Health check tests =======================================================


class TestHealthCheck:
    """Test the health check endpoint."""

    @pytest.mark.asyncio
    async def test_health_check_success(self) -> None:
        """Health check returns SUCCESS on HTTP 200."""
        config = _config_with_hibp()
        collector = DarkWebIndicatorsCollector(config)

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "dark-web-indicators"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0

    @pytest.mark.asyncio
    async def test_health_check_failure_http(self) -> None:
        """Health check returns FAILURE on HTTP error status."""
        config = _config_with_hibp()
        collector = DarkWebIndicatorsCollector(config)

        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE

    @pytest.mark.asyncio
    async def test_health_check_failure_exception(self) -> None:
        """Health check returns FAILURE on connection exception."""
        config = _config_with_hibp()
        collector = DarkWebIndicatorsCollector(config)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.side_effect = Exception("Connection refused")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message == "Connection refused"


# === FIPS gate compliance =====================================================


class TestFipsCompliance:
    """Verify new source files do not import banned crypto modules."""

    # Banned patterns per ADR-010 / test_fips_crypto_gate.py.
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
        REPO_ROOT / "src" / "expose" / "modules" / "__init__.py",
        REPO_ROOT / "src" / "expose" / "modules" / "threat_context" / "__init__.py",
        REPO_ROOT / "src" / "expose" / "modules" / "threat_context" / "dark_web.py",
        REPO_ROOT / "src" / "expose" / "collectors" / "builtin" / "dark_web_indicators.py",
    ]

    @pytest.mark.parametrize(
        "path",
        NEW_FILES,
        ids=lambda p: str(p.name),
    )
    def test_no_banned_crypto_imports(self, path: Path) -> None:
        """New dark web module files must not import banned crypto modules."""
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
