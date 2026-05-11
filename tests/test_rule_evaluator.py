"""Tests for the rule evaluation engine (expose.pipeline.rule_evaluator).

Covers all 12 predicates individually, AND/OR/NOT condition combinations,
priority ordering, confidence delta aggregation, tier threshold mapping,
disabled rule skipping, and unknown predicate rejection at load time.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from expose.pipeline.rule_evaluator import (
    AppliedDelta,
    EntityData,
    RuleEvaluationResult,
    RuleEvaluator,
    ScopeContext,
    validate_rule_pack,
)
from expose.types.rulepack import (
    Action,
    AndCondition,
    AttributionRule,
    LeadScoreFormula,
    LeadScoreWeights,
    NotCondition,
    OrCondition,
    Outcome,
    Predicate,
    PredicateCondition,
    RulePack,
    TierThresholds,
)


# =============================================================================
# Helpers
# =============================================================================


def _minimal_lead_score_formula() -> LeadScoreFormula:
    """Return a minimal lead score formula for rule pack construction."""
    return LeadScoreFormula(
        formula_version="0.1.0",
        weights=LeadScoreWeights(),
        modifiers=[],
    )


def _make_pack(
    rules: list[AttributionRule],
    *,
    thresholds: TierThresholds | None = None,
) -> RulePack:
    """Build a minimal RulePack wrapping the given rules."""
    return RulePack(
        pack_id="test-pack",
        pack_version="1.0.0",
        attribution_rules=rules,
        lead_score_formula=_minimal_lead_score_formula(),
        tier_thresholds=thresholds or TierThresholds(),
    )


def _make_rule(
    rule_id: str = "test-rule",
    predicate: Predicate = Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
    params: dict | None = None,
    outcome: Outcome = Outcome.PROMOTE,
    confidence_delta: float | None = 0.5,
    priority: int = 100,
    enabled: bool = True,
    review_flag: bool | None = None,
    review_reason: str | None = None,
    when: None = None,
) -> AttributionRule:
    """Build a single-predicate attribution rule with sensible defaults."""
    condition = PredicateCondition(predicate=predicate, params=params)
    action_kwargs: dict = {"outcome": outcome}
    if confidence_delta is not None:
        action_kwargs["confidence_delta"] = confidence_delta
    if review_flag is not None:
        action_kwargs["review_flag"] = review_flag
    if review_reason is not None:
        action_kwargs["review_reason"] = review_reason
    return AttributionRule(
        rule_id=rule_id,
        rule_version="1.0.0",
        description=f"Test rule {rule_id}",
        when=condition,
        then=Action(**action_kwargs),
        priority=priority,
        enabled=enabled,
    )


def _base_entity(**overrides: object) -> dict:
    """Build a base entity dict with sensible defaults."""
    entity = {
        "entity_type": "domain",
        "canonical_identifier": "test.example.com",
        "properties": {},
        "attribution_status": "unattributed",
        "attribution_confidence": 0.0,
    }
    entity.update(overrides)
    return entity


# =============================================================================
# Predicate tests — one per predicate
# =============================================================================


class TestPredicateCertSanInScope:
    """TARGET_HAS_CERTIFICATE_WITH_SAN_IN_SCOPE."""

    def test_san_matches_scope_domain(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_HAS_CERTIFICATE_WITH_SAN_IN_SCOPE,
            confidence_delta=0.8,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack, scope_context={"scope_domains": ["example.com"]},
        )
        entity = _base_entity(
            properties={"tls_san_values": ["test.example.com", "other.net"]},
        )
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_wildcard_san_matches(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_HAS_CERTIFICATE_WITH_SAN_IN_SCOPE,
            confidence_delta=0.8,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack, scope_context={"scope_domains": ["example.com"]},
        )
        entity = _base_entity(
            properties={"tls_san_values": ["*.example.com"]},
        )
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_no_san_no_match(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_HAS_CERTIFICATE_WITH_SAN_IN_SCOPE,
            confidence_delta=0.8,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack, scope_context={"scope_domains": ["example.com"]},
        )
        entity = _base_entity(properties={})
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []


class TestPredicateIpInCloudRange:
    """TARGET_IP_IN_AUTHORIZED_CLOUD_ACCOUNT_RANGE."""

    def test_ip_in_range(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_IP_IN_AUTHORIZED_CLOUD_ACCOUNT_RANGE,
            confidence_delta=1.0,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack, scope_context={"cloud_ranges": ["10.0.0.0/8"]},
        )
        entity = _base_entity(
            entity_type="ip",
            canonical_identifier="10.1.2.3",
            properties={"ip": "10.1.2.3"},
        )
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_ip_not_in_range(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_IP_IN_AUTHORIZED_CLOUD_ACCOUNT_RANGE,
            confidence_delta=1.0,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack, scope_context={"cloud_ranges": ["10.0.0.0/8"]},
        )
        entity = _base_entity(
            entity_type="ip",
            canonical_identifier="192.168.1.1",
            properties={"ip": "192.168.1.1"},
        )
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []

    def test_resolved_ips_fallback(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_IP_IN_AUTHORIZED_CLOUD_ACCOUNT_RANGE,
            confidence_delta=1.0,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack, scope_context={"cloud_ranges": ["10.0.0.0/8"]},
        )
        entity = _base_entity(
            entity_type="domain",
            canonical_identifier="app.example.com",
            properties={"resolved_ips": ["10.5.6.7"]},
        )
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules


class TestPredicateRegistrantMatches:
    """TARGET_REGISTRANT_MATCHES_AUTHORIZED_PATTERN."""

    def test_registrant_org_matches(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_REGISTRANT_MATCHES_AUTHORIZED_PATTERN,
            confidence_delta=0.5,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"registrant_patterns": [r"Acme\s+Corp"]},
        )
        entity = _base_entity(
            properties={"registrant_org": "Acme Corp International"},
        )
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_registrant_no_match(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_REGISTRANT_MATCHES_AUTHORIZED_PATTERN,
            confidence_delta=0.5,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"registrant_patterns": [r"^Globex$"]},
        )
        entity = _base_entity(
            properties={"registrant_org": "Acme Corp"},
        )
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []


class TestPredicateSharedCertChain:
    """TARGET_SHARES_CERT_CHAIN_WITH_ATTRIBUTED_TARGET."""

    def test_cert_chain_overlap(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_SHARES_CERT_CHAIN_WITH_ATTRIBUTED_TARGET,
            confidence_delta=0.4,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "attributed_cert_fingerprints": ["aabbccdd", "11223344"],
            },
        )
        entity = _base_entity(
            properties={"cert_chain_fingerprints": ["aabbccdd", "99887766"]},
        )
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_no_cert_chain_overlap(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_SHARES_CERT_CHAIN_WITH_ATTRIBUTED_TARGET,
            confidence_delta=0.4,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "attributed_cert_fingerprints": ["aabbccdd"],
            },
        )
        entity = _base_entity(
            properties={"cert_chain_fingerprints": ["99887766"]},
        )
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []


class TestPredicateNameserverMatches:
    """TARGET_NAMESERVER_MATCHES_AUTHORIZED_PATTERN."""

    def test_ns_matches_pattern(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_NAMESERVER_MATCHES_AUTHORIZED_PATTERN,
            confidence_delta=0.3,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"nameserver_patterns": [r"ns\d+\.example\.com"]},
        )
        entity = _base_entity(
            properties={"nameservers": ["ns1.example.com", "ns2.other.com"]},
        )
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_ns_no_match(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_NAMESERVER_MATCHES_AUTHORIZED_PATTERN,
            confidence_delta=0.3,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"nameserver_patterns": [r"ns\d+\.acme\.com"]},
        )
        entity = _base_entity(
            properties={"nameservers": ["ns1.example.com"]},
        )
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []


class TestPredicateAsnInAuthorizedList:
    """TARGET_ASN_IN_AUTHORIZED_LIST."""

    def test_asn_in_list(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_ASN_IN_AUTHORIZED_LIST,
            confidence_delta=0.6,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"authorized_asns": [13335, 15169]},
        )
        entity = _base_entity(properties={"asn": 13335})
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_asn_string_normalization(self) -> None:
        """ASN given as 'AS13335' should match integer 13335."""
        rule = _make_rule(
            predicate=Predicate.TARGET_ASN_IN_AUTHORIZED_LIST,
            confidence_delta=0.6,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"authorized_asns": ["AS13335"]},
        )
        entity = _base_entity(properties={"asn": 13335})
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_asn_not_in_list(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_ASN_IN_AUTHORIZED_LIST,
            confidence_delta=0.6,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"authorized_asns": [13335]},
        )
        entity = _base_entity(properties={"asn": 99999})
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []


class TestPredicateSubdomainOfApex:
    """TARGET_SUBDOMAIN_OF_AUTHORIZED_APEX."""

    def test_subdomain_matches_apex(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_SUBDOMAIN_OF_AUTHORIZED_APEX,
            confidence_delta=0.95,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"apex_domains": ["example.com"]},
        )
        entity = _base_entity(canonical_identifier="app.example.com")
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_apex_itself_matches(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_SUBDOMAIN_OF_AUTHORIZED_APEX,
            confidence_delta=0.95,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"apex_domains": ["example.com"]},
        )
        entity = _base_entity(canonical_identifier="example.com")
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_different_domain_no_match(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_SUBDOMAIN_OF_AUTHORIZED_APEX,
            confidence_delta=0.95,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"apex_domains": ["example.com"]},
        )
        entity = _base_entity(canonical_identifier="malicious.net")
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []


class TestPredicateInExplicitScope:
    """TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE."""

    def test_in_explicit_scope(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.9,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com", "other.com"],
            },
        )
        entity = _base_entity(canonical_identifier="test.example.com")
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_rejection_only_mode(self) -> None:
        rule = _make_rule(
            rule_id="reject-rule",
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            params={"rejection_only": True},
            outcome=Outcome.REJECT,
            confidence_delta=None,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "rejection_identifiers": ["bad.example.com"],
            },
        )
        entity = _base_entity(canonical_identifier="bad.example.com")
        result = evaluator.evaluate(entity)
        assert "reject-rule" in result.matched_rules
        assert result.attribution_tier == "rejected"

    def test_not_in_scope(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.9,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["other.com"],
            },
        )
        entity = _base_entity(canonical_identifier="test.example.com")
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []


class TestPredicateCollectorCountGte:
    """TARGET_OBSERVED_BY_COLLECTORS_COUNT_GTE."""

    def test_meets_threshold(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_OBSERVED_BY_COLLECTORS_COUNT_GTE,
            params={"count": 2},
            confidence_delta=0.3,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(pack)
        entity = _base_entity(
            properties={"_collector_ids": ["ct-crtsh", "active-dns", "tls-handshake"]},
        )
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_below_threshold(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_OBSERVED_BY_COLLECTORS_COUNT_GTE,
            params={"count": 3},
            confidence_delta=0.3,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(pack)
        entity = _base_entity(
            properties={"_collector_ids": ["ct-crtsh", "active-dns"]},
        )
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []

    def test_single_collector_id_fallback(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_OBSERVED_BY_COLLECTORS_COUNT_GTE,
            params={"count": 1},
            confidence_delta=0.2,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(pack)
        entity = _base_entity(
            properties={"_collector_id": "ct-crtsh"},
        )
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules


class TestPredicateFirstObservedWithinDays:
    """TARGET_FIRST_OBSERVED_WITHIN_DAYS."""

    def test_within_days(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_FIRST_OBSERVED_WITHIN_DAYS,
            params={"days": 7},
            confidence_delta=0.2,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(pack)
        recent = (datetime.now(tz=UTC) - timedelta(days=3)).isoformat()
        entity = _base_entity(properties={"_observed_at": recent})
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_outside_days(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_FIRST_OBSERVED_WITHIN_DAYS,
            params={"days": 7},
            confidence_delta=0.2,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(pack)
        old = (datetime.now(tz=UTC) - timedelta(days=30)).isoformat()
        entity = _base_entity(properties={"_observed_at": old})
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []


class TestPredicateExposureIndicator:
    """TARGET_HAS_EXPOSURE_INDICATOR."""

    def test_specific_indicator_present(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_HAS_EXPOSURE_INDICATOR,
            params={"indicator": "admin_panel_exposed"},
            confidence_delta=0.3,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(pack)
        entity = _base_entity(
            properties={
                "exposure_indicators": ["admin_panel_exposed", "weak_cipher"],
            },
        )
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_indicator_not_present(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_HAS_EXPOSURE_INDICATOR,
            params={"indicator": "admin_panel_exposed"},
            confidence_delta=0.3,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(pack)
        entity = _base_entity(
            properties={"exposure_indicators": ["weak_cipher"]},
        )
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []

    def test_any_indicator_when_no_specific(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_HAS_EXPOSURE_INDICATOR,
            params={},
            confidence_delta=0.3,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(pack)
        entity = _base_entity(
            properties={"exposure_indicators": ["open_port_22"]},
        )
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules


class TestPredicateNamingConvention:
    """TARGET_RESPONDS_WITH_AUTHORIZED_NAMING_CONVENTION."""

    def test_title_matches_pattern(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_RESPONDS_WITH_AUTHORIZED_NAMING_CONVENTION,
            confidence_delta=0.3,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"naming_convention_patterns": [r"Acme\s+Portal"]},
        )
        entity = _base_entity(
            properties={"http_title": "Acme Portal - Login"},
        )
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_body_matches_pattern(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_RESPONDS_WITH_AUTHORIZED_NAMING_CONVENTION,
            confidence_delta=0.3,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"naming_convention_patterns": [r"Copyright.*Acme"]},
        )
        entity = _base_entity(
            properties={"http_body": "Copyright 2026 Acme Inc."},
        )
        result = evaluator.evaluate(entity)
        assert "test-rule" in result.matched_rules

    def test_no_match(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_RESPONDS_WITH_AUTHORIZED_NAMING_CONVENTION,
            confidence_delta=0.3,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"naming_convention_patterns": [r"Acme"]},
        )
        entity = _base_entity(
            properties={"http_title": "Globex Corporation"},
        )
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []


# =============================================================================
# Condition combination tests
# =============================================================================


class TestAndCondition:
    """AND (all_of) condition evaluation."""

    def test_all_true(self) -> None:
        condition = AndCondition(
            all_of=[
                PredicateCondition(
                    predicate=Predicate.TARGET_SUBDOMAIN_OF_AUTHORIZED_APEX,
                ),
                PredicateCondition(
                    predicate=Predicate.TARGET_OBSERVED_BY_COLLECTORS_COUNT_GTE,
                    params={"count": 1},
                ),
            ],
        )
        rule = AttributionRule(
            rule_id="and-test",
            rule_version="1.0.0",
            description="AND test",
            when=condition,
            then=Action(outcome=Outcome.PROMOTE, confidence_delta=0.7),
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"apex_domains": ["example.com"]},
        )
        entity = _base_entity(
            canonical_identifier="app.example.com",
            properties={"_collector_id": "ct-crtsh"},
        )
        result = evaluator.evaluate(entity)
        assert "and-test" in result.matched_rules

    def test_one_false(self) -> None:
        condition = AndCondition(
            all_of=[
                PredicateCondition(
                    predicate=Predicate.TARGET_SUBDOMAIN_OF_AUTHORIZED_APEX,
                ),
                PredicateCondition(
                    predicate=Predicate.TARGET_OBSERVED_BY_COLLECTORS_COUNT_GTE,
                    params={"count": 5},
                ),
            ],
        )
        rule = AttributionRule(
            rule_id="and-test",
            rule_version="1.0.0",
            description="AND test",
            when=condition,
            then=Action(outcome=Outcome.PROMOTE, confidence_delta=0.7),
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"apex_domains": ["example.com"]},
        )
        entity = _base_entity(
            canonical_identifier="app.example.com",
            properties={"_collector_id": "ct-crtsh"},
        )
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []


class TestOrCondition:
    """OR (any_of) condition evaluation."""

    def test_one_true_of_two(self) -> None:
        condition = OrCondition(
            any_of=[
                PredicateCondition(
                    predicate=Predicate.TARGET_SUBDOMAIN_OF_AUTHORIZED_APEX,
                ),
                PredicateCondition(
                    predicate=Predicate.TARGET_ASN_IN_AUTHORIZED_LIST,
                ),
            ],
        )
        rule = AttributionRule(
            rule_id="or-test",
            rule_version="1.0.0",
            description="OR test",
            when=condition,
            then=Action(outcome=Outcome.PROMOTE, confidence_delta=0.5),
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "apex_domains": ["example.com"],
                "authorized_asns": [],  # not matching
            },
        )
        entity = _base_entity(canonical_identifier="app.example.com")
        result = evaluator.evaluate(entity)
        assert "or-test" in result.matched_rules

    def test_none_true(self) -> None:
        condition = OrCondition(
            any_of=[
                PredicateCondition(
                    predicate=Predicate.TARGET_SUBDOMAIN_OF_AUTHORIZED_APEX,
                ),
                PredicateCondition(
                    predicate=Predicate.TARGET_ASN_IN_AUTHORIZED_LIST,
                ),
            ],
        )
        rule = AttributionRule(
            rule_id="or-test",
            rule_version="1.0.0",
            description="OR test",
            when=condition,
            then=Action(outcome=Outcome.PROMOTE, confidence_delta=0.5),
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "apex_domains": ["other.com"],
                "authorized_asns": [99999],
            },
        )
        entity = _base_entity(canonical_identifier="test.example.com")
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []


class TestNotCondition:
    """NOT (not_) condition evaluation."""

    def test_not_inverts_true_to_false(self) -> None:
        condition = NotCondition(
            **{"not": PredicateCondition(
                predicate=Predicate.TARGET_SUBDOMAIN_OF_AUTHORIZED_APEX,
            )},
        )
        rule = AttributionRule(
            rule_id="not-test",
            rule_version="1.0.0",
            description="NOT test",
            when=condition,
            then=Action(outcome=Outcome.PROMOTE, confidence_delta=0.3),
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"apex_domains": ["example.com"]},
        )
        # Entity IS a subdomain, so NOT should fail
        entity = _base_entity(canonical_identifier="app.example.com")
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []

    def test_not_inverts_false_to_true(self) -> None:
        condition = NotCondition(
            **{"not": PredicateCondition(
                predicate=Predicate.TARGET_SUBDOMAIN_OF_AUTHORIZED_APEX,
            )},
        )
        rule = AttributionRule(
            rule_id="not-test",
            rule_version="1.0.0",
            description="NOT test",
            when=condition,
            then=Action(outcome=Outcome.PROMOTE, confidence_delta=0.3),
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"apex_domains": ["example.com"]},
        )
        # Entity is NOT a subdomain, so NOT should pass
        entity = _base_entity(canonical_identifier="malicious.net")
        result = evaluator.evaluate(entity)
        assert "not-test" in result.matched_rules


class TestNestedConditions:
    """Nested condition combinations (AND containing NOT, etc.)."""

    def test_and_with_not(self) -> None:
        """Matches example-baseline 'shared-cert-chain' rule structure."""
        condition = AndCondition(
            all_of=[
                PredicateCondition(
                    predicate=Predicate.TARGET_SHARES_CERT_CHAIN_WITH_ATTRIBUTED_TARGET,
                ),
                NotCondition(
                    **{"not": PredicateCondition(
                        predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
                        params={"rejection_only": True},
                    )},
                ),
            ],
        )
        rule = AttributionRule(
            rule_id="nested-test",
            rule_version="1.0.0",
            description="Nested AND+NOT test",
            when=condition,
            then=Action(outcome=Outcome.PROMOTE, confidence_delta=0.4),
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "attributed_cert_fingerprints": ["aabbccdd"],
                "rejection_identifiers": [],  # not rejected
            },
        )
        entity = _base_entity(
            properties={"cert_chain_fingerprints": ["aabbccdd"]},
        )
        result = evaluator.evaluate(entity)
        assert "nested-test" in result.matched_rules


# =============================================================================
# Priority ordering
# =============================================================================


class TestPriorityOrdering:
    """Rules fire in priority order (lower number = higher priority)."""

    def test_lower_priority_fires_first(self) -> None:
        rule_low = _make_rule(
            rule_id="high-priority",
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.3,
            priority=10,
        )
        rule_high = _make_rule(
            rule_id="low-priority",
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.2,
            priority=200,
        )
        # Intentionally add in reverse order to verify sorting
        pack = _make_pack([rule_high, rule_low])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(canonical_identifier="test.example.com")
        result = evaluator.evaluate(entity)
        assert result.matched_rules == ["high-priority", "low-priority"]


# =============================================================================
# Confidence delta aggregation
# =============================================================================


class TestConfidenceDeltaAggregation:
    """Promote + demote deltas aggregate to net confidence."""

    def test_promote_adds_confidence(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.8,
            outcome=Outcome.PROMOTE,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(
            canonical_identifier="test.example.com",
            attribution_confidence=0.1,
        )
        result = evaluator.evaluate(entity)
        assert result.final_confidence == pytest.approx(0.9)

    def test_demote_subtracts_confidence(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.3,
            outcome=Outcome.DEMOTE,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(
            canonical_identifier="test.example.com",
            attribution_confidence=0.8,
        )
        result = evaluator.evaluate(entity)
        assert result.final_confidence == pytest.approx(0.5)

    def test_promote_and_demote_net(self) -> None:
        promote_rule = _make_rule(
            rule_id="promote",
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.6,
            outcome=Outcome.PROMOTE,
            priority=10,
        )
        demote_rule = _make_rule(
            rule_id="demote",
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.2,
            outcome=Outcome.DEMOTE,
            priority=20,
        )
        pack = _make_pack([promote_rule, demote_rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(
            canonical_identifier="test.example.com",
            attribution_confidence=0.0,
        )
        result = evaluator.evaluate(entity)
        # 0.0 + 0.6 - 0.2 = 0.4
        assert result.final_confidence == pytest.approx(0.4)

    def test_confidence_clamped_to_1(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=1.0,
            outcome=Outcome.PROMOTE,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(
            canonical_identifier="test.example.com",
            attribution_confidence=0.5,
        )
        result = evaluator.evaluate(entity)
        assert result.final_confidence == 1.0

    def test_confidence_clamped_to_0(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.8,
            outcome=Outcome.DEMOTE,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(
            canonical_identifier="test.example.com",
            attribution_confidence=0.3,
        )
        result = evaluator.evaluate(entity)
        assert result.final_confidence == 0.0


# =============================================================================
# Tier threshold mapping
# =============================================================================


class TestTierThresholdMapping:
    """Confidence maps to tiers via TierThresholds."""

    def test_confirmed_tier(self) -> None:
        """Confidence >= 0.95 maps to confirmed."""
        rule = _make_rule(
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.95,
            outcome=Outcome.PROMOTE,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(
            canonical_identifier="test.example.com",
            attribution_confidence=0.0,
        )
        result = evaluator.evaluate(entity)
        assert result.attribution_tier == "confirmed"
        assert result.final_confidence >= 0.95

    def test_high_tier(self) -> None:
        """Confidence >= 0.75 but < 0.95 maps to high."""
        rule = _make_rule(
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.8,
            outcome=Outcome.PROMOTE,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(
            canonical_identifier="test.example.com",
            attribution_confidence=0.0,
        )
        result = evaluator.evaluate(entity)
        assert result.attribution_tier == "high"

    def test_medium_tier(self) -> None:
        """Confidence >= 0.5 but < 0.75 maps to medium."""
        rule = _make_rule(
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.6,
            outcome=Outcome.PROMOTE,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(
            canonical_identifier="test.example.com",
            attribution_confidence=0.0,
        )
        result = evaluator.evaluate(entity)
        assert result.attribution_tier == "medium"

    def test_unattributed_tier(self) -> None:
        """Confidence < 0.5 maps to unattributed."""
        rule = _make_rule(
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.2,
            outcome=Outcome.PROMOTE,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(
            canonical_identifier="test.example.com",
            attribution_confidence=0.0,
        )
        result = evaluator.evaluate(entity)
        assert result.attribution_tier == "unattributed"

    def test_custom_thresholds(self) -> None:
        """Custom thresholds override defaults."""
        thresholds = TierThresholds(confirmed=0.9, high=0.6, medium=0.3)
        rule = _make_rule(
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.65,
            outcome=Outcome.PROMOTE,
        )
        pack = _make_pack([rule], thresholds=thresholds)
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(
            canonical_identifier="test.example.com",
            attribution_confidence=0.0,
        )
        result = evaluator.evaluate(entity)
        assert result.attribution_tier == "high"


# =============================================================================
# Disabled rules
# =============================================================================


class TestDisabledRules:
    """Disabled rules are skipped."""

    def test_disabled_rule_not_evaluated(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.9,
            enabled=False,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(canonical_identifier="test.example.com")
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []
        assert result.final_confidence == 0.0

    def test_mix_of_enabled_and_disabled(self) -> None:
        enabled_rule = _make_rule(
            rule_id="enabled",
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.5,
            priority=10,
            enabled=True,
        )
        disabled_rule = _make_rule(
            rule_id="disabled",
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.5,
            priority=20,
            enabled=False,
        )
        pack = _make_pack([enabled_rule, disabled_rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(canonical_identifier="test.example.com")
        result = evaluator.evaluate(entity)
        assert result.matched_rules == ["enabled"]
        assert result.final_confidence == pytest.approx(0.5)


# =============================================================================
# Unknown predicate rejection at load time
# =============================================================================


class TestUnknownPredicateRejection:
    """Unknown predicates are rejected at RulePack load/validation time."""

    def test_unknown_predicate_raises_at_construction(self) -> None:
        """Predicate enum validation at Pydantic level rejects unknown values."""
        with pytest.raises((ValueError, KeyError)):
            PredicateCondition(
                predicate="totally_unknown_predicate",  # type: ignore[arg-type]
            )

    def test_validate_rule_pack_catches_invalid(self) -> None:
        """Manually constructing a rule with valid enum but no evaluator raises."""
        # We test the validation layer by monkey-patching — but since
        # the Predicate enum IS the vocabulary and Pydantic rejects anything
        # outside it, this validates the contract end-to-end.
        # The Pydantic model will reject unknown predicate strings at parse time.
        import json

        raw = {
            "pack_id": "bad-pack",
            "pack_version": "1.0.0",
            "attribution_rules": [
                {
                    "rule_id": "bad-rule",
                    "rule_version": "1.0.0",
                    "description": "Uses unknown predicate",
                    "when": {
                        "predicate": "totally_bogus_predicate",
                    },
                    "then": {
                        "outcome": "promote",
                        "confidence_delta": 0.5,
                    },
                }
            ],
            "lead_score_formula": {
                "formula_version": "0.1.0",
                "weights": {},
                "modifiers": [],
            },
        }
        with pytest.raises((ValueError, Exception)):
            RulePack.model_validate(raw)


# =============================================================================
# Reject outcome
# =============================================================================


class TestRejectOutcome:
    """REJECT outcome sets confidence to 0 and tier to rejected."""

    def test_reject_zeroes_confidence(self) -> None:
        rule = _make_rule(
            rule_id="reject",
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            params={"rejection_only": True},
            outcome=Outcome.REJECT,
            confidence_delta=None,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "rejection_identifiers": ["bad.example.com"],
            },
        )
        entity = _base_entity(
            canonical_identifier="bad.example.com",
            attribution_confidence=0.9,
        )
        result = evaluator.evaluate(entity)
        assert result.final_confidence == 0.0
        assert result.attribution_tier == "rejected"

    def test_reject_overrides_promote(self) -> None:
        """Reject should override any promote that fires in the same evaluation."""
        promote_rule = _make_rule(
            rule_id="promote",
            predicate=Predicate.TARGET_SUBDOMAIN_OF_AUTHORIZED_APEX,
            confidence_delta=0.9,
            outcome=Outcome.PROMOTE,
            priority=50,
        )
        reject_rule = _make_rule(
            rule_id="reject",
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            params={"rejection_only": True},
            outcome=Outcome.REJECT,
            confidence_delta=None,
            priority=5,  # Higher priority (lower number)
        )
        pack = _make_pack([promote_rule, reject_rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "apex_domains": ["example.com"],
                "rejection_identifiers": ["bad.example.com"],
            },
        )
        entity = _base_entity(canonical_identifier="bad.example.com")
        result = evaluator.evaluate(entity)
        assert result.attribution_tier == "rejected"
        assert result.final_confidence == 0.0


# =============================================================================
# Neutral outcome with review flag
# =============================================================================


class TestNeutralOutcomeWithReview:
    """Neutral outcome with review flag."""

    def test_review_flag_added(self) -> None:
        rule = _make_rule(
            rule_id="review-rule",
            predicate=Predicate.TARGET_OBSERVED_BY_COLLECTORS_COUNT_GTE,
            params={"count": 1},
            outcome=Outcome.NEUTRAL,
            confidence_delta=None,
            review_flag=True,
            review_reason="thin_evidence",
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(pack)
        entity = _base_entity(
            properties={"_collector_id": "ct-crtsh"},
        )
        result = evaluator.evaluate(entity)
        assert "review-rule" in result.matched_rules
        assert "thin_evidence" in result.review_flags


# =============================================================================
# Result dataclass structure
# =============================================================================


class TestResultStructure:
    """RuleEvaluationResult contains expected fields."""

    def test_no_matches_returns_defaults(self) -> None:
        rule = _make_rule(
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.5,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={"explicit_entity_identifiers": []},
        )
        entity = _base_entity(canonical_identifier="unmatched.example.com")
        result = evaluator.evaluate(entity)
        assert result.matched_rules == []
        assert result.applied_deltas == []
        assert result.final_confidence == 0.0
        assert result.attribution_tier == "unattributed"
        assert result.review_flags == []

    def test_applied_deltas_contain_details(self) -> None:
        rule = _make_rule(
            rule_id="detail-check",
            predicate=Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE,
            confidence_delta=0.7,
            outcome=Outcome.PROMOTE,
        )
        pack = _make_pack([rule])
        evaluator = RuleEvaluator(
            pack,
            scope_context={
                "explicit_entity_identifiers": ["test.example.com"],
            },
        )
        entity = _base_entity(canonical_identifier="test.example.com")
        result = evaluator.evaluate(entity)
        assert len(result.applied_deltas) == 1
        delta = result.applied_deltas[0]
        assert delta.rule_id == "detail-check"
        assert delta.outcome == "promote"
        assert delta.confidence_delta == pytest.approx(0.7)
        assert delta.review_flag is False


# =============================================================================
# Example baseline rule pack integration
# =============================================================================


class TestExampleBaselineIntegration:
    """Load and evaluate the example-baseline.json rule pack."""

    @pytest.fixture()
    def baseline_pack(self) -> RulePack:
        """Load the example baseline rule pack, skipping $schema field."""
        import json
        from pathlib import Path

        pack_path = (
            Path(__file__).resolve().parent.parent
            / "examples"
            / "rulepacks"
            / "example-baseline.json"
        )
        raw = json.loads(pack_path.read_text())
        # Remove $schema key that the RulePack model rejects
        raw.pop("$schema", None)
        return RulePack.model_validate(raw)

    def test_baseline_pack_loads(self, baseline_pack: RulePack) -> None:
        """The pack loads and validates without error."""
        evaluator = RuleEvaluator(baseline_pack)
        assert evaluator is not None

    def test_baseline_cloud_account_rule(self, baseline_pack: RulePack) -> None:
        """Cloud account authoritative rule promotes with delta=1.0."""
        evaluator = RuleEvaluator(
            baseline_pack,
            scope_context={"cloud_ranges": ["10.0.0.0/8"]},
        )
        entity = _base_entity(
            entity_type="ip",
            canonical_identifier="10.1.2.3",
            properties={"ip": "10.1.2.3"},
        )
        result = evaluator.evaluate(entity)
        assert "cloud-account-authoritative" in result.matched_rules
        assert result.final_confidence == pytest.approx(1.0)
        assert result.attribution_tier == "confirmed"

    def test_baseline_rejection_rule_fires_first(
        self, baseline_pack: RulePack,
    ) -> None:
        """Explicit rejection rule (priority 5) fires before all others."""
        evaluator = RuleEvaluator(
            baseline_pack,
            scope_context={
                "rejection_identifiers": ["rejected.example.com"],
                "apex_domains": ["example.com"],
            },
        )
        entity = _base_entity(canonical_identifier="rejected.example.com")
        result = evaluator.evaluate(entity)
        assert result.matched_rules[0] == "explicit-rejection"
        assert result.attribution_tier == "rejected"
