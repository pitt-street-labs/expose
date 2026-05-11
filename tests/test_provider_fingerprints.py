"""Tests for provider fingerprint database (Issue #90).

Coverage:
- match_provider function: exact match, glob wildcards, case insensitivity,
  no-match, empty patterns
- Database integrity: 50 providers present, all have valid structure
- Category coverage: every expected category has at least one provider
- Pattern validity: every provider has at least one matchable pattern
- Risk notes: every provider has non-empty risk notes
"""

from __future__ import annotations

import pytest

from expose.pipeline.provider_fingerprints import (
    PROVIDER_DATABASE,
    ProviderFingerprint,
    match_provider,
)

# ---------------------------------------------------------------------------
# Expected categories — must each have at least one provider
# ---------------------------------------------------------------------------
EXPECTED_CATEGORIES = frozenset(
    {
        "cdn_waf",
        "email",
        "email_delivery",
        "support",
        "status_page",
        "hosting",
        "auth_sso",
        "ci_cd",
        "monitoring",
        "analytics",
        "crm",
        "security",
    }
)


# ---------------------------------------------------------------------------
# match_provider tests
# ---------------------------------------------------------------------------


class TestMatchProvider:
    """Unit tests for the glob-style pattern matcher."""

    def test_exact_match(self) -> None:
        assert match_provider("cname.vercel-dns.com", ("cname.vercel-dns.com",))

    def test_glob_prefix(self) -> None:
        assert match_provider("d1234.cloudfront.net", ("*.cloudfront.net",))

    def test_glob_nested_subdomain(self) -> None:
        assert match_provider(
            "abc.def.cloudfront.net", ("*.cloudfront.net",)
        )

    def test_case_insensitive_value(self) -> None:
        assert match_provider("FOO.CloudFront.NET", ("*.cloudfront.net",))

    def test_case_insensitive_pattern(self) -> None:
        assert match_provider("foo.cloudfront.net", ("*.CLOUDFRONT.NET",))

    def test_no_match(self) -> None:
        assert not match_provider("example.com", ("*.cloudfront.net",))

    def test_empty_patterns(self) -> None:
        assert not match_provider("anything.example.com", ())

    def test_multiple_patterns_first_matches(self) -> None:
        patterns = ("*.fastly.net", "*.fastlylb.net")
        assert match_provider("cdn.fastly.net", patterns)

    def test_multiple_patterns_second_matches(self) -> None:
        patterns = ("*.fastly.net", "*.fastlylb.net")
        assert match_provider("lb.fastlylb.net", patterns)

    def test_multiple_patterns_none_match(self) -> None:
        patterns = ("*.fastly.net", "*.fastlylb.net")
        assert not match_provider("unrelated.example.com", patterns)

    def test_substring_txt_pattern(self) -> None:
        """TXT patterns use substring matching in practice, but
        match_provider is glob-based.  Verify the glob still works
        for substring patterns containing wildcards."""
        assert match_provider(
            "_github-challenge-myorg", ("*_github-challenge-*",)
        )

    def test_partial_domain_does_not_match(self) -> None:
        """'notcloudfront.net' should not match '*.cloudfront.net'."""
        assert not match_provider("notcloudfront.net", ("*.cloudfront.net",))

    def test_wildcard_awsdns(self) -> None:
        """AWS NS pattern uses interior wildcard."""
        assert match_provider(
            "ns-123.awsdns-45.com", ("*.awsdns-*.com",)
        )


# ---------------------------------------------------------------------------
# Database integrity tests
# ---------------------------------------------------------------------------


class TestDatabaseIntegrity:
    """Verify the provider database is complete and well-formed."""

    def test_provider_count(self) -> None:
        """Database must contain exactly 50 providers."""
        assert len(PROVIDER_DATABASE) == 50

    def test_unique_ids(self) -> None:
        """All provider IDs must be unique (enforced by dict, but
        verify the source list has no duplicates)."""
        from expose.pipeline.provider_fingerprints import _PROVIDERS

        ids = [p.id for p in _PROVIDERS]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"

    def test_all_ids_are_strings(self) -> None:
        for pid, prov in PROVIDER_DATABASE.items():
            assert isinstance(pid, str) and pid
            assert pid == prov.id

    def test_all_names_non_empty(self) -> None:
        for prov in PROVIDER_DATABASE.values():
            assert prov.name, f"Provider {prov.id} has empty name"

    def test_all_categories_valid(self) -> None:
        valid = EXPECTED_CATEGORIES | {"dns"}  # allow extra categories
        for prov in PROVIDER_DATABASE.values():
            assert prov.category in valid, (
                f"Provider {prov.id} has unexpected category '{prov.category}'"
            )

    def test_every_expected_category_covered(self) -> None:
        found = {prov.category for prov in PROVIDER_DATABASE.values()}
        missing = EXPECTED_CATEGORIES - found
        assert not missing, f"Missing categories: {missing}"

    def test_every_provider_has_at_least_one_pattern(self) -> None:
        """Each provider must have at least one DNS matching pattern
        (cname, mx, spf, ns, or txt)."""
        for prov in PROVIDER_DATABASE.values():
            has_pattern = (
                prov.cname_patterns
                or prov.mx_patterns
                or prov.spf_includes
                or prov.ns_patterns
                or prov.txt_patterns
            )
            assert has_pattern, f"Provider {prov.id} has no patterns"

    def test_every_provider_has_risk_notes(self) -> None:
        for prov in PROVIDER_DATABASE.values():
            assert prov.risk_notes, f"Provider {prov.id} has empty risk_notes"

    def test_patterns_are_tuples(self) -> None:
        """All pattern fields must be tuples (frozen dataclass)."""
        for prov in PROVIDER_DATABASE.values():
            assert isinstance(prov.cname_patterns, tuple), prov.id
            assert isinstance(prov.mx_patterns, tuple), prov.id
            assert isinstance(prov.spf_includes, tuple), prov.id
            assert isinstance(prov.ns_patterns, tuple), prov.id
            assert isinstance(prov.txt_patterns, tuple), prov.id

    def test_frozen_dataclass(self) -> None:
        """ProviderFingerprint instances should be immutable."""
        prov = PROVIDER_DATABASE["cloudflare"]
        with pytest.raises(AttributeError):
            prov.name = "modified"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Category-specific provider verification
# ---------------------------------------------------------------------------


class TestCategoryPopulation:
    """Verify expected providers appear in each category."""

    def _providers_in_category(self, cat: str) -> list[str]:
        return [p.id for p in PROVIDER_DATABASE.values() if p.category == cat]

    def test_cdn_waf_count(self) -> None:
        providers = self._providers_in_category("cdn_waf")
        assert len(providers) == 7
        assert "cloudflare" in providers
        assert "akamai" in providers

    def test_email_count(self) -> None:
        providers = self._providers_in_category("email")
        assert len(providers) == 3
        assert "google_workspace" in providers
        assert "microsoft_365" in providers

    def test_email_delivery_count(self) -> None:
        providers = self._providers_in_category("email_delivery")
        assert len(providers) == 5
        assert "sendgrid" in providers
        assert "aws_ses" in providers

    def test_support_count(self) -> None:
        providers = self._providers_in_category("support")
        assert len(providers) == 4
        assert "zendesk" in providers

    def test_status_page_count(self) -> None:
        providers = self._providers_in_category("status_page")
        assert len(providers) == 3
        assert "statuspage" in providers

    def test_hosting_count(self) -> None:
        providers = self._providers_in_category("hosting")
        assert len(providers) == 8
        assert "aws" in providers
        assert "heroku" in providers

    def test_auth_sso_count(self) -> None:
        providers = self._providers_in_category("auth_sso")
        assert len(providers) == 4
        assert "okta" in providers
        assert "auth0" in providers

    def test_ci_cd_count(self) -> None:
        providers = self._providers_in_category("ci_cd")
        assert len(providers) == 3
        assert "github_actions" in providers

    def test_monitoring_count(self) -> None:
        providers = self._providers_in_category("monitoring")
        assert len(providers) == 5
        assert "datadog" in providers

    def test_analytics_count(self) -> None:
        providers = self._providers_in_category("analytics")
        assert len(providers) == 3
        assert "segment" in providers

    def test_crm_count(self) -> None:
        providers = self._providers_in_category("crm")
        assert len(providers) == 2
        assert "salesforce" in providers

    def test_security_count(self) -> None:
        providers = self._providers_in_category("security")
        assert len(providers) == 3
        assert "proofpoint" in providers
        assert "mimecast" in providers


# ---------------------------------------------------------------------------
# Pattern matching integration tests
# ---------------------------------------------------------------------------


class TestPatternMatchIntegration:
    """Test match_provider against real patterns from the database."""

    @pytest.mark.parametrize(
        "provider_id, value, field",
        [
            ("cloudflare", "cdn.cloudflare.com", "cname_patterns"),
            ("cloudflare", "anna.ns.cloudflare.com", "ns_patterns"),
            ("aws_cloudfront", "d111111abcdef8.cloudfront.net", "cname_patterns"),
            ("akamai", "e1234.dscx.akamaiedge.net", "cname_patterns"),
            ("fastly", "prod.fastly.net", "cname_patterns"),
            ("imperva", "site.incapdns.net", "cname_patterns"),
            ("google_workspace", "aspmx.l.google.com", "mx_patterns"),
            ("microsoft_365", "mail.protection.outlook.com", "mx_patterns"),
            ("sendgrid", "em1234.sendgrid.net", "cname_patterns"),
            ("zendesk", "support.zendesk.com", "cname_patterns"),
            ("statuspage", "status.statuspage.io", "cname_patterns"),
            ("aws", "web.elasticbeanstalk.com", "cname_patterns"),
            ("aws", "ns-123.awsdns-45.com", "ns_patterns"),
            ("heroku", "myapp.herokuapp.com", "cname_patterns"),
            ("vercel", "cname.vercel-dns.com", "cname_patterns"),
            ("github_pages", "myorg.github.io", "cname_patterns"),
            ("okta", "corp.okta.com", "cname_patterns"),
            ("auth0", "tenant.auth0.com", "cname_patterns"),
            ("datadog", "rum.datadoghq.com", "cname_patterns"),
            ("salesforce", "portal.force.com", "cname_patterns"),
            ("proofpoint", "mx1.pphosted.com", "mx_patterns"),
            ("mimecast", "inbound.mimecast.com", "mx_patterns"),
            ("barracuda", "gw.barracudanetworks.com", "mx_patterns"),
        ],
    )
    def test_known_provider_matches(
        self, provider_id: str, value: str, field: str
    ) -> None:
        prov = PROVIDER_DATABASE[provider_id]
        patterns = getattr(prov, field)
        assert match_provider(value, patterns), (
            f"{provider_id}.{field}: {value!r} did not match {patterns}"
        )

    @pytest.mark.parametrize(
        "provider_id, value, field",
        [
            ("cloudflare", "evil.notcloudflare.com", "cname_patterns"),
            ("aws_cloudfront", "cloudfront.example.com", "cname_patterns"),
            ("heroku", "heroku.com", "cname_patterns"),
        ],
    )
    def test_known_provider_rejects(
        self, provider_id: str, value: str, field: str
    ) -> None:
        prov = PROVIDER_DATABASE[provider_id]
        patterns = getattr(prov, field)
        assert not match_provider(value, patterns), (
            f"{provider_id}.{field}: {value!r} should NOT match {patterns}"
        )

    def test_spf_exact_match(self) -> None:
        """SPF includes are exact domains — match_provider should work
        when the value equals the pattern exactly."""
        prov = PROVIDER_DATABASE["google_workspace"]
        # SPF includes are exact, not glob, but match_provider still works
        assert match_provider("_spf.google.com", prov.spf_includes)

    def test_txt_substring_approach(self) -> None:
        """For TXT records, the real pipeline does substring matching.
        Verify that the txt_patterns at least contain reasonable
        substrings."""
        prov = PROVIDER_DATABASE["microsoft_365"]
        # The pattern "MS=ms" should be a substring of a real TXT record
        assert any("MS=ms" in p for p in prov.txt_patterns)
