"""Tests for DarkWebEnricher domain/email input validation (#160).

Coverage:
    1. Valid domain passes validation
    2. Valid email passes validation
    3. Path traversal characters rejected (domain and email)
    4. Overlong input rejected (domain and email)
    5. Malformed domain rejected
    6. Malformed email rejected
    7. enrich_domain returns empty for invalid input (integration)
    8. enrich_email returns empty for invalid input (integration)
    9. Valid inputs still reach API (not over-blocked)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from expose.modules.threat_context.dark_web import (
    DarkWebEnricher,
    _validate_domain,
    _validate_email,
)


# === _validate_domain unit tests =============================================


class TestValidateDomain:
    """Unit tests for the _validate_domain helper."""

    @pytest.mark.parametrize(
        "domain",
        [
            "example.com",
            "sub.example.com",
            "deep.sub.example.com",
            "example.co.uk",
            "a.b.c.d.e.f.g",
            "x",                          # single-char label
            "123.456",                     # numeric labels
            "my-domain.org",              # hyphens in labels
            "a-b-c.d-e-f.com",           # multiple hyphens
            "A" * 63 + ".com",           # max label length (63)
        ],
        ids=[
            "simple", "subdomain", "deep-sub", "cctld", "many-labels",
            "single-char", "numeric", "hyphen", "multi-hyphen", "max-label",
        ],
    )
    def test_valid_domain_accepted(self, domain: str) -> None:
        """Well-formed domains pass validation."""
        assert _validate_domain(domain) is True

    @pytest.mark.parametrize(
        "domain",
        [
            "",                           # empty
            "   ",                        # whitespace only
            ".example.com",               # leading dot
            "example.com.",               # trailing dot
            "-example.com",               # leading hyphen
            "example-.com",               # trailing hyphen in label
            "exam ple.com",               # space in label
            "exam\tple.com",              # tab in label
            "example..com",               # double dot
            "A" * 64 + ".com",           # label too long (64 chars)
            "ex@mple.com",                # @ in domain
        ],
        ids=[
            "empty", "whitespace", "leading-dot", "trailing-dot",
            "leading-hyphen", "trailing-hyphen", "space", "tab",
            "double-dot", "label-too-long", "at-sign",
        ],
    )
    def test_malformed_domain_rejected(self, domain: str) -> None:
        """Malformed domains are rejected."""
        assert _validate_domain(domain) is False

    @pytest.mark.parametrize(
        "domain",
        [
            "../etc/passwd",
            "example.com/../../secret",
            "example.com\\..\\secret",
            "..example.com",
            "example..com",
        ],
        ids=[
            "unix-traversal", "slash-traversal", "backslash-traversal",
            "dot-dot-prefix", "dot-dot-in-domain",
        ],
    )
    def test_path_traversal_rejected(self, domain: str) -> None:
        """Path traversal attempts are rejected."""
        assert _validate_domain(domain) is False

    def test_overlong_domain_rejected(self) -> None:
        """Domains exceeding 253 characters are rejected."""
        # Build a valid-looking but overlong domain.
        long_domain = ("a" * 50 + ".") * 6 + "com"  # 50*6 + 5*6 + 3 = 333
        assert len(long_domain) > 253
        assert _validate_domain(long_domain) is False

    def test_exactly_253_chars_accepted(self) -> None:
        """A domain of exactly 253 characters is accepted if format-valid."""
        # 4 labels of 62 chars each + dots + "com" = 62*4 + 3(dots) + 1(dot) + 3 = 255 -- too long.
        # 3 labels of 63 + 3 dots + final 61-char label = 63*3 + 3 + 61 = 253.
        label63 = "a" * 63
        final = "b" * 61
        domain = f"{label63}.{label63}.{label63}.{final}"
        assert len(domain) == 253
        assert _validate_domain(domain) is True


# === _validate_email unit tests ==============================================


class TestValidateEmail:
    """Unit tests for the _validate_email helper."""

    @pytest.mark.parametrize(
        "email",
        [
            "user@example.com",
            "admin@sub.example.com",
            "user+tag@example.com",
            "first.last@example.co.uk",
            "user123@domain456.org",
            "x@y.z",                      # minimal valid
        ],
        ids=[
            "simple", "subdomain-host", "plus-tag", "dotted-local",
            "numeric-parts", "minimal",
        ],
    )
    def test_valid_email_accepted(self, email: str) -> None:
        """Well-formed emails pass validation."""
        assert _validate_email(email) is True

    @pytest.mark.parametrize(
        "email",
        [
            "",                           # empty
            "   ",                        # whitespace only
            "user",                       # no @ or domain
            "user@",                      # no domain
            "@example.com",               # no local part
            "user@host",                  # no TLD dot
            "user @example.com",          # space in local
            "user@ example.com",          # space in domain
            "user@example .com",          # space in domain label
        ],
        ids=[
            "empty", "whitespace", "no-at", "no-domain", "no-local",
            "no-tld", "space-local", "space-domain", "space-label",
        ],
    )
    def test_malformed_email_rejected(self, email: str) -> None:
        """Malformed emails are rejected."""
        assert _validate_email(email) is False

    @pytest.mark.parametrize(
        "email",
        [
            "user@../etc/passwd",
            "user@example.com/../../secret",
            "user@example.com\\..\\secret",
            "../traversal@host.com",
        ],
        ids=[
            "domain-traversal", "slash-traversal",
            "backslash-traversal", "local-traversal",
        ],
    )
    def test_path_traversal_rejected(self, email: str) -> None:
        """Path traversal attempts in email are rejected."""
        assert _validate_email(email) is False

    def test_overlong_email_rejected(self) -> None:
        """Emails exceeding 253 characters are rejected."""
        long_email = "a" * 242 + "@example.com"  # 254 chars total
        assert len(long_email) > 253
        assert _validate_email(long_email) is False


# === DarkWebEnricher integration (validation gate) ===========================


class TestEnricherValidationGate:
    """Verify that DarkWebEnricher methods reject invalid inputs."""

    @pytest.mark.asyncio
    async def test_enrich_domain_rejects_invalid(self) -> None:
        """enrich_domain returns empty list for malformed domain."""
        enricher = DarkWebEnricher(hibp_api_key="test-key")
        result = await enricher.enrich_domain("../etc/passwd")
        assert result == []

    @pytest.mark.asyncio
    async def test_enrich_email_rejects_invalid(self) -> None:
        """enrich_email returns empty list for malformed email."""
        enricher = DarkWebEnricher(hibp_api_key="test-key")
        result = await enricher.enrich_email("not-an-email")
        assert result == []

    @pytest.mark.asyncio
    async def test_enrich_domain_rejects_overlong(self) -> None:
        """enrich_domain returns empty list for overlong domain."""
        enricher = DarkWebEnricher(hibp_api_key="test-key")
        result = await enricher.enrich_domain("a" * 254 + ".com")
        assert result == []

    @pytest.mark.asyncio
    async def test_enrich_email_rejects_overlong(self) -> None:
        """enrich_email returns empty list for overlong email."""
        enricher = DarkWebEnricher(hibp_api_key="test-key")
        result = await enricher.enrich_email("a" * 250 + "@x.com")
        assert result == []

    @pytest.mark.asyncio
    async def test_valid_domain_reaches_api(self) -> None:
        """Valid domain passes validation and reaches the API layer."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404  # No breaches (but API was called)

        enricher = DarkWebEnricher(hibp_api_key="test-key")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await enricher.enrich_domain("example.com")

        # If validation rejected it, get() would never be called.
        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_valid_email_reaches_api(self) -> None:
        """Valid email passes validation and reaches the API layer."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        enricher = DarkWebEnricher(hibp_api_key="test-key")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await enricher.enrich_email("user@example.com")

        mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_enrich_domain_rejects_empty(self) -> None:
        """enrich_domain returns empty list for empty string."""
        enricher = DarkWebEnricher(hibp_api_key="test-key")
        result = await enricher.enrich_domain("")
        assert result == []

    @pytest.mark.asyncio
    async def test_enrich_email_rejects_empty(self) -> None:
        """enrich_email returns empty list for empty string."""
        enricher = DarkWebEnricher(hibp_api_key="test-key")
        result = await enricher.enrich_email("")
        assert result == []
