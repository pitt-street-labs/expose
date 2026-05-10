"""Tests for the rich authorization scope models and matching engine.

Covers SPEC §10.1 authorization scope: apex domains, exact domains,
IP addresses, CIDR ranges, ASN, cloud accounts, registrant org patterns,
and exclusion semantics.

Refs #30 (authorization scope schema evolution).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from expose.scope.matcher import ScopeMatcher, ScopeMatchResult
from expose.scope.models import AuthorizationScope, ScopeRule, ScopeRuleType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")
_NOW = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)


def _make_scope(rules: list[ScopeRule]) -> AuthorizationScope:
    """Build a minimal AuthorizationScope for testing."""
    return AuthorizationScope(
        tenant_id=_TENANT_ID,
        rules=rules,
        enforcement_mode="medium",
        last_modified=_NOW,
        modified_by="test-harness",
    )


# ---------------------------------------------------------------------------
# 1. Apex domain matches subdomains
# ---------------------------------------------------------------------------
class TestApexDomainSubdomainMatch:
    def test_subdomain_matches(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="example.com"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("domain", "sub.example.com")
        assert result.in_scope is True
        assert result.matched_rule is not None
        assert result.matched_rule.value == "example.com"

    def test_deep_subdomain_matches(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="example.com"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("domain", "a.b.c.example.com")
        assert result.in_scope is True


# ---------------------------------------------------------------------------
# 2. Apex domain matches the apex itself
# ---------------------------------------------------------------------------
class TestApexDomainSelfMatch:
    def test_apex_matches_itself(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="example.com"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("domain", "example.com")
        assert result.in_scope is True
        assert result.matched_rule is not None
        assert result.matched_rule.rule_type == ScopeRuleType.APEX_DOMAIN


# ---------------------------------------------------------------------------
# 3. Exact domain doesn't match subdomains
# ---------------------------------------------------------------------------
class TestExactDomainNoSubdomains:
    def test_exact_does_not_match_subdomain(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.EXACT_DOMAIN, value="www.example.com"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("domain", "sub.www.example.com")
        assert result.in_scope is False
        assert result.matched_rule is None

    def test_exact_matches_itself(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.EXACT_DOMAIN, value="www.example.com"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("domain", "www.example.com")
        assert result.in_scope is True


# ---------------------------------------------------------------------------
# 4. IP address exact match
# ---------------------------------------------------------------------------
class TestIPAddressMatch:
    def test_exact_ip_match(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.IP_ADDRESS, value="192.0.2.1"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("ip", "192.0.2.1")
        assert result.in_scope is True
        assert result.matched_rule is not None
        assert result.matched_rule.value == "192.0.2.1"

    def test_ip_no_match(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.IP_ADDRESS, value="192.0.2.1"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("ip", "192.0.2.2")
        assert result.in_scope is False

    def test_ip_wrong_entity_type(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.IP_ADDRESS, value="192.0.2.1"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("domain", "192.0.2.1")
        assert result.in_scope is False


# ---------------------------------------------------------------------------
# 5. CIDR containment match
# ---------------------------------------------------------------------------
class TestCIDRContainment:
    def test_ip_in_cidr(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.CIDR, value="192.0.2.0/24"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("ip", "192.0.2.42")
        assert result.in_scope is True
        assert result.matched_rule is not None
        assert result.matched_rule.value == "192.0.2.0/24"


# ---------------------------------------------------------------------------
# 6. CIDR non-match
# ---------------------------------------------------------------------------
class TestCIDRNonMatch:
    def test_ip_outside_cidr(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.CIDR, value="192.0.2.0/24"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("ip", "10.0.0.1")
        assert result.in_scope is False
        assert result.matched_rule is None


# ---------------------------------------------------------------------------
# 7. ASN match
# ---------------------------------------------------------------------------
class TestASNMatch:
    def test_asn_match(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.ASN, value="AS13335"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("asn", "AS13335")
        assert result.in_scope is True

    def test_asn_case_insensitive(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.ASN, value="AS13335"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("asn", "as13335")
        assert result.in_scope is True


# ---------------------------------------------------------------------------
# 8. Cloud account match
# ---------------------------------------------------------------------------
class TestCloudAccountMatch:
    def test_cloud_account_match(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.CLOUD_ACCOUNT, value="123456789012"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("cloud_account", "123456789012")
        assert result.in_scope is True
        assert result.matched_rule is not None

    def test_cloud_account_no_match(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.CLOUD_ACCOUNT, value="123456789012"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("cloud_account", "999999999999")
        assert result.in_scope is False


# ---------------------------------------------------------------------------
# 9. Registrant org substring match (case-insensitive)
# ---------------------------------------------------------------------------
class TestRegistrantOrgMatch:
    def test_registrant_substring_match(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.REGISTRANT_ORG, value="Acme Corp"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("registrant_org", "ACME CORP INTERNATIONAL LTD")
        assert result.in_scope is True

    def test_registrant_case_insensitive(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.REGISTRANT_ORG, value="KORLOGOS"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("registrant_org", "Korlogos Holdings Pty Ltd")
        assert result.in_scope is True

    def test_registrant_no_match(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.REGISTRANT_ORG, value="Acme Corp"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("registrant_org", "Globex Industries")
        assert result.in_scope is False


# ---------------------------------------------------------------------------
# 10. Exclusion overrides inclusion
# ---------------------------------------------------------------------------
class TestExclusionOverride:
    def test_exclusion_overrides_inclusion(self) -> None:
        """An apex domain includes *.example.com, but an exclusion
        carves out cdn.example.com specifically."""
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="example.com"),
                ScopeRule(
                    rule_type=ScopeRuleType.EXACT_DOMAIN,
                    value="cdn.example.com",
                    include=False,
                ),
            ]
        )
        matcher = ScopeMatcher(scope)

        # cdn.example.com should be excluded
        result_cdn = matcher.matches("domain", "cdn.example.com")
        assert result_cdn.in_scope is False
        assert result_cdn.excluded_by is not None
        assert result_cdn.excluded_by.value == "cdn.example.com"

        # www.example.com should still be included
        result_www = matcher.matches("domain", "www.example.com")
        assert result_www.in_scope is True

    def test_exclusion_domain_type(self) -> None:
        """EXCLUSION_DOMAIN rule type acts as an exclude."""
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="example.com"),
                ScopeRule(
                    rule_type=ScopeRuleType.EXCLUSION_DOMAIN,
                    value="shared.example.com",
                ),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("domain", "shared.example.com")
        assert result.in_scope is False
        assert result.excluded_by is not None


# ---------------------------------------------------------------------------
# 11. No matching rule -> not in scope
# ---------------------------------------------------------------------------
class TestNoMatchNotInScope:
    def test_unmatched_domain(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="example.com"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("domain", "evil.org")
        assert result.in_scope is False
        assert result.matched_rule is None
        assert result.excluded_by is None

    def test_unmatched_entity_type(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="example.com"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("ip", "192.0.2.1")
        assert result.in_scope is False


# ---------------------------------------------------------------------------
# 12. Multiple rules - first inclusion match wins (after exclusion check)
# ---------------------------------------------------------------------------
class TestMultipleRulesFirstMatchWins:
    def test_first_inclusion_wins(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.CIDR, value="10.0.0.0/8"),
                ScopeRule(rule_type=ScopeRuleType.CIDR, value="10.0.0.0/24"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("ip", "10.0.0.5")
        assert result.in_scope is True
        # The broader /8 rule is listed first, so it matches first
        assert result.matched_rule is not None
        assert result.matched_rule.value == "10.0.0.0/8"

    def test_mixed_rule_types_first_match(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="example.com"),
                ScopeRule(rule_type=ScopeRuleType.EXACT_DOMAIN, value="www.example.com"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("domain", "www.example.com")
        assert result.in_scope is True
        # APEX_DOMAIN is listed first and matches subdomains
        assert result.matched_rule is not None
        assert result.matched_rule.rule_type == ScopeRuleType.APEX_DOMAIN


# ---------------------------------------------------------------------------
# 13. Empty scope -> nothing matches
# ---------------------------------------------------------------------------
class TestEmptyScope:
    def test_empty_rules_list(self) -> None:
        scope = _make_scope([])
        matcher = ScopeMatcher(scope)
        result = matcher.matches("domain", "anything.example.com")
        assert result.in_scope is False
        assert result.matched_rule is None
        assert result.excluded_by is None
        assert result.reason == "No matching scope rule found"


# ---------------------------------------------------------------------------
# 14. ScopeMatchResult has correct reason text
# ---------------------------------------------------------------------------
class TestScopeMatchResultReason:
    def test_inclusion_reason_text(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="example.com"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("domain", "www.example.com")
        assert "apex_domain" in result.reason
        assert "example.com" in result.reason

    def test_exclusion_reason_text(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(
                    rule_type=ScopeRuleType.EXACT_DOMAIN,
                    value="excluded.example.com",
                    include=False,
                ),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("domain", "excluded.example.com")
        assert "exact_domain" in result.reason
        assert "excluded.example.com" in result.reason
        assert result.in_scope is False

    def test_no_match_reason_text(self) -> None:
        scope = _make_scope([])
        matcher = ScopeMatcher(scope)
        result = matcher.matches("domain", "nope.example.com")
        assert result.reason == "No matching scope rule found"


# ---------------------------------------------------------------------------
# 15. Model immutability (frozen=True)
# ---------------------------------------------------------------------------
class TestModelImmutability:
    def test_scope_rule_frozen(self) -> None:
        rule = ScopeRule(rule_type=ScopeRuleType.APEX_DOMAIN, value="example.com")
        with pytest.raises(Exception):  # noqa: B017
            rule.value = "evil.com"  # type: ignore[misc]

    def test_authorization_scope_frozen(self) -> None:
        scope = _make_scope([])
        with pytest.raises(Exception):  # noqa: B017
            scope.enforcement_mode = "hard"  # type: ignore[misc]

    def test_scope_match_result_frozen(self) -> None:
        result = ScopeMatchResult(in_scope=True, reason="test")
        with pytest.raises(Exception):  # noqa: B017
            result.in_scope = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 16. Extra fields are forbidden
# ---------------------------------------------------------------------------
class TestExtraFieldsForbidden:
    def test_scope_rule_extra_forbidden(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            ScopeRule(
                rule_type=ScopeRuleType.APEX_DOMAIN,
                value="example.com",
                bogus="should fail",  # type: ignore[call-arg]
            )

    def test_authorization_scope_extra_forbidden(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            AuthorizationScope(
                tenant_id=_TENANT_ID,
                rules=[],
                enforcement_mode="medium",
                last_modified=_NOW,
                modified_by="test",
                bogus="should fail",  # type: ignore[call-arg]
            )


# ---------------------------------------------------------------------------
# 17. IPv6 handling
# ---------------------------------------------------------------------------
class TestIPv6:
    def test_ipv6_exact_match(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.IP_ADDRESS, value="2001:db8::1"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("ip", "2001:db8::1")
        assert result.in_scope is True

    def test_ipv6_cidr_containment(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.CIDR, value="2001:db8::/32"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("ip", "2001:db8::42")
        assert result.in_scope is True

    def test_ipv6_cidr_no_match(self) -> None:
        scope = _make_scope(
            [
                ScopeRule(rule_type=ScopeRuleType.CIDR, value="2001:db8::/32"),
            ]
        )
        matcher = ScopeMatcher(scope)
        result = matcher.matches("ip", "fe80::1")
        assert result.in_scope is False
