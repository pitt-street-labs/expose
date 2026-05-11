"""Rule evaluation engine — applies RulePack attribution rules to entities.

Evaluates declarative rule packs (per SPEC section 8.2 / ADR-006) against entity
data to produce attribution confidence adjustments and review flags.  Rule packs
are data, not code: the 12-predicate vocabulary is closed and defined in
``expose.types.rulepack.Predicate``.  Unknown predicates are rejected at load
time, not silently ignored.

This module is pure — no DB access, no LLM calls, no external I/O.  All
evaluation is deterministic given the same inputs.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable

from expose.types.pipeline import EntityData, ScopeContext
from expose.types.rulepack import (
    Action,
    AndCondition,
    AttributionRule,
    Condition,
    NotCondition,
    OrCondition,
    Outcome,
    Predicate,
    PredicateCondition,
    RulePack,
    TierThresholds,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Result types
# =============================================================================


@dataclass(frozen=True)
class AppliedDelta:
    """Record of a single rule's confidence adjustment."""

    rule_id: str
    outcome: str
    confidence_delta: float
    review_flag: bool
    review_reason: str | None


@dataclass
class RuleEvaluationResult:
    """Aggregate outcome of evaluating all rules against an entity."""

    matched_rules: list[str] = field(default_factory=list)
    applied_deltas: list[AppliedDelta] = field(default_factory=list)
    final_confidence: float = 0.0
    attribution_tier: str = "unattributed"
    review_flags: list[str] = field(default_factory=list)


# =============================================================================
# Attribution tier mapping
# =============================================================================


def _confidence_to_tier(confidence: float, thresholds: TierThresholds) -> str:
    """Map a confidence value to an attribution tier using the pack's thresholds."""
    if confidence >= thresholds.confirmed:
        return "confirmed"
    if confidence >= thresholds.high:
        return "high"
    if confidence >= thresholds.medium:
        return "medium"
    return "unattributed"


# =============================================================================
# Predicate evaluators
# =============================================================================

# Each predicate evaluator receives ``(entity_data, params, scope_context)``
# and returns a bool.  ``scope_context`` carries tenant authorization data
# (cloud ranges, apex domains, explicit identifiers, authorized patterns, etc.)
# needed by scope-aware predicates.  Callers populate it when constructing the
# ``RuleEvaluator``; predicates that don't need it simply ignore it.


def _get_scope_field(scope: ScopeContext | dict[str, Any], key: str, default: Any = None) -> Any:
    """Retrieve a field from a ScopeContext model or a raw dict.

    ScopeContext uses ``extra="allow"`` so arbitrary scope keys (cloud_ranges,
    apex_domains, etc.) are accessible as extra fields or via dict fallback.
    """
    if isinstance(scope, dict):
        return scope.get(key, default if default is not None else [])
    # For ScopeContext: check named fields first, then extra fields
    if hasattr(scope, key):
        return getattr(scope, key)
    # Extra fields stored in model_extra
    extras = scope.model_extra or {}
    return extras.get(key, default if default is not None else [])


def _eval_target_has_certificate_with_san_in_scope(
    entity: EntityData,
    params: dict[str, Any] | None,
    scope: ScopeContext,
) -> bool:
    """Check if entity has a TLS SAN matching any scope domain."""
    props = entity.properties
    san_values: list[str] = props.get("tls_san_values", [])
    if isinstance(san_values, str):
        san_values = [san_values]
    scope_domains: list[str] = _get_scope_field(scope, "scope_domains", [])
    for san in san_values:
        san_lower = san.lower().lstrip("*.")
        for domain in scope_domains:
            if san_lower == domain.lower() or san_lower.endswith("." + domain.lower()):
                return True
    return False


def _eval_target_ip_in_authorized_cloud_account_range(
    entity: EntityData,
    params: dict[str, Any] | None,
    scope: ScopeContext,
) -> bool:
    """Check if entity IP falls within configured cloud CIDR ranges."""
    props = entity.properties
    # Collect all candidate IPs to check
    candidate_ips: list[str] = []
    # Explicit ip property takes priority
    if props.get("ip"):
        candidate_ips.append(str(props["ip"]))
    # For IP-type entities, the identifier itself is the IP
    if entity.entity_type == "ip":
        candidate_ips.append(entity.canonical_identifier)
    # Resolved IPs from DNS lookups
    resolved = props.get("resolved_ips", [])
    if isinstance(resolved, list):
        candidate_ips.extend(str(ip) for ip in resolved)
    cloud_ranges: list[str] = _get_scope_field(scope, "cloud_ranges", [])
    if not candidate_ips or not cloud_ranges:
        return False
    for ip_str in candidate_ips:
        try:
            addr = ipaddress.ip_address(ip_str)
        except (ValueError, TypeError):
            continue
        for cidr_str in cloud_ranges:
            try:
                network = ipaddress.ip_network(cidr_str, strict=False)
                if addr in network:
                    return True
            except (ValueError, TypeError):
                continue
    return False


def _eval_target_registrant_matches_authorized_pattern(
    entity: EntityData,
    params: dict[str, Any] | None,
    scope: ScopeContext,
) -> bool:
    """Regex match on WHOIS registrant fields."""
    props = entity.properties
    registrant_fields = [
        props.get("registrant_org", ""),
        props.get("registrant_name", ""),
        props.get("registrant_email", ""),
        props.get("whois_registrant", ""),
    ]
    patterns: list[str] = _get_scope_field(scope, "registrant_patterns", [])
    for field_val in registrant_fields:
        if not field_val:
            continue
        for pattern in patterns:
            try:
                if re.search(pattern, str(field_val), re.IGNORECASE):
                    return True
            except re.error:
                logger.warning("Invalid registrant pattern: %s", pattern)
    return False


def _eval_target_shares_cert_chain_with_attributed_target(
    entity: EntityData,
    params: dict[str, Any] | None,
    scope: ScopeContext,
) -> bool:
    """Check cert chain overlap with confirmed entities."""
    props = entity.properties
    cert_chain = props.get("cert_chain_fingerprints", [])
    if isinstance(cert_chain, str):
        cert_chain = [cert_chain]
    attributed_chains: list[str] = _get_scope_field(scope, "attributed_cert_fingerprints", [])
    if not cert_chain or not attributed_chains:
        return False
    return bool(set(cert_chain) & set(attributed_chains))


def _eval_target_nameserver_matches_authorized_pattern(
    entity: EntityData,
    params: dict[str, Any] | None,
    scope: ScopeContext,
) -> bool:
    """Regex match on NS records."""
    props = entity.properties
    nameservers = props.get("nameservers", [])
    if isinstance(nameservers, str):
        nameservers = [nameservers]
    patterns: list[str] = _get_scope_field(scope, "nameserver_patterns", [])
    for ns in nameservers:
        for pattern in patterns:
            try:
                if re.search(pattern, str(ns), re.IGNORECASE):
                    return True
            except re.error:
                logger.warning("Invalid nameserver pattern: %s", pattern)
    return False


def _eval_target_asn_in_authorized_list(
    entity: EntityData,
    params: dict[str, Any] | None,
    scope: ScopeContext,
) -> bool:
    """Check if entity ASN is in authorized list."""
    props = entity.properties
    entity_asn = props.get("asn")
    if entity_asn is None:
        return False
    authorized_asns: list[int | str] = _get_scope_field(scope, "authorized_asns", [])
    # Normalize to strings for comparison (ASNs can be int or "AS12345")
    entity_asn_str = str(entity_asn).upper().lstrip("AS")
    for auth_asn in authorized_asns:
        if str(auth_asn).upper().lstrip("AS") == entity_asn_str:
            return True
    return False


def _eval_target_subdomain_of_authorized_apex(
    entity: EntityData,
    params: dict[str, Any] | None,
    scope: ScopeContext,
) -> bool:
    """Check if entity is a subdomain of a confirmed apex domain."""
    identifier = entity.canonical_identifier
    apex_domains: list[str] = _get_scope_field(scope, "apex_domains", [])
    identifier_lower = identifier.lower()
    for apex in apex_domains:
        apex_lower = apex.lower()
        if identifier_lower == apex_lower:
            return True
        if identifier_lower.endswith("." + apex_lower):
            return True
    return False


def _eval_target_in_explicit_authorization_scope(
    entity: EntityData,
    params: dict[str, Any] | None,
    scope: ScopeContext,
) -> bool:
    """Check if entity is in tenant's explicit_entity_identifiers."""
    identifier = entity.canonical_identifier
    explicit_ids: list[str] = _get_scope_field(scope, "explicit_entity_identifiers", [])
    rejection_only = (params or {}).get("rejection_only", False)
    if rejection_only:
        rejection_ids: list[str] = _get_scope_field(scope, "rejection_identifiers", [])
        return identifier.lower() in [r.lower() for r in rejection_ids]
    return identifier.lower() in [e.lower() for e in explicit_ids]


def _eval_target_observed_by_collectors_count_gte(
    entity: EntityData,
    params: dict[str, Any] | None,
    scope: ScopeContext,
) -> bool:
    """Count distinct _collector_id values and compare to threshold."""
    threshold = (params or {}).get("count", 1)
    props = entity.properties
    # Support multiple collector IDs stored as a list or single value
    collector_ids = props.get("_collector_ids", [])
    if not collector_ids:
        # Fall back to single collector_id
        single = props.get("_collector_id")
        if single:
            collector_ids = [single]
    if isinstance(collector_ids, str):
        collector_ids = [collector_ids]
    return len(set(collector_ids)) >= threshold


def _eval_target_first_observed_within_days(
    entity: EntityData,
    params: dict[str, Any] | None,
    scope: ScopeContext,
) -> bool:
    """Check if entity was first observed within N days of now."""
    days = (params or {}).get("days", 30)
    props = entity.properties
    observed_at_str = props.get("_observed_at")
    if not observed_at_str:
        return False
    try:
        if isinstance(observed_at_str, datetime):
            observed_at = observed_at_str
        else:
            observed_at = datetime.fromisoformat(str(observed_at_str).replace("Z", "+00:00"))
        if observed_at.tzinfo is None:
            observed_at = observed_at.replace(tzinfo=UTC)
        age = (datetime.now(tz=UTC) - observed_at).days
        return age <= days
    except (ValueError, TypeError):
        return False


def _eval_target_has_exposure_indicator(
    entity: EntityData,
    params: dict[str, Any] | None,
    scope: ScopeContext,
) -> bool:
    """Check for exposure properties (open ports, weak ciphers, etc.)."""
    indicator = (params or {}).get("indicator")
    props = entity.properties
    exposure_indicators = props.get("exposure_indicators", [])
    if isinstance(exposure_indicators, str):
        exposure_indicators = [exposure_indicators]
    if indicator:
        return indicator in exposure_indicators
    # If no specific indicator requested, check if any exist
    return bool(exposure_indicators)


def _eval_target_responds_with_authorized_naming_convention(
    entity: EntityData,
    params: dict[str, Any] | None,
    scope: ScopeContext,
) -> bool:
    """Regex match on HTTP response body/title."""
    props = entity.properties
    response_title = props.get("http_title", "")
    response_body = props.get("http_body", "")
    patterns: list[str] = _get_scope_field(scope, "naming_convention_patterns", [])
    targets = [str(response_title), str(response_body)]
    for target in targets:
        if not target:
            continue
        for pattern in patterns:
            try:
                if re.search(pattern, target, re.IGNORECASE):
                    return True
            except re.error:
                logger.warning("Invalid naming convention pattern: %s", pattern)
    return False


# Lookup table: predicate enum -> evaluator function
_PREDICATE_EVALUATORS: dict[Predicate, Any] = {
    Predicate.TARGET_HAS_CERTIFICATE_WITH_SAN_IN_SCOPE: _eval_target_has_certificate_with_san_in_scope,
    Predicate.TARGET_IP_IN_AUTHORIZED_CLOUD_ACCOUNT_RANGE: _eval_target_ip_in_authorized_cloud_account_range,
    Predicate.TARGET_REGISTRANT_MATCHES_AUTHORIZED_PATTERN: _eval_target_registrant_matches_authorized_pattern,
    Predicate.TARGET_SHARES_CERT_CHAIN_WITH_ATTRIBUTED_TARGET: _eval_target_shares_cert_chain_with_attributed_target,
    Predicate.TARGET_NAMESERVER_MATCHES_AUTHORIZED_PATTERN: _eval_target_nameserver_matches_authorized_pattern,
    Predicate.TARGET_ASN_IN_AUTHORIZED_LIST: _eval_target_asn_in_authorized_list,
    Predicate.TARGET_SUBDOMAIN_OF_AUTHORIZED_APEX: _eval_target_subdomain_of_authorized_apex,
    Predicate.TARGET_IN_EXPLICIT_AUTHORIZATION_SCOPE: _eval_target_in_explicit_authorization_scope,
    Predicate.TARGET_OBSERVED_BY_COLLECTORS_COUNT_GTE: _eval_target_observed_by_collectors_count_gte,
    Predicate.TARGET_FIRST_OBSERVED_WITHIN_DAYS: _eval_target_first_observed_within_days,
    Predicate.TARGET_HAS_EXPOSURE_INDICATOR: _eval_target_has_exposure_indicator,
    Predicate.TARGET_RESPONDS_WITH_AUTHORIZED_NAMING_CONVENTION: _eval_target_responds_with_authorized_naming_convention,
}


# =============================================================================
# Condition evaluator (recursive)
# =============================================================================


def _eval_predicate_condition(
    condition: PredicateCondition,
    entity: EntityData,
    scope: ScopeContext,
) -> bool:
    """Evaluate a leaf predicate condition against entity data."""
    evaluator = _PREDICATE_EVALUATORS.get(condition.predicate)
    if evaluator is None:
        # This should not happen if validation passed at load time
        raise ValueError(f"Unknown predicate: {condition.predicate}")
    return evaluator(entity, condition.params, scope)


def _eval_and_condition(
    condition: AndCondition,
    entity: EntityData,
    scope: ScopeContext,
) -> bool:
    """Evaluate an AND condition — all sub-conditions must be true."""
    return all(_evaluate_condition(c, entity, scope) for c in condition.all_of)


def _eval_or_condition(
    condition: OrCondition,
    entity: EntityData,
    scope: ScopeContext,
) -> bool:
    """Evaluate an OR condition — at least one sub-condition must be true."""
    return any(_evaluate_condition(c, entity, scope) for c in condition.any_of)


def _eval_not_condition(
    condition: NotCondition,
    entity: EntityData,
    scope: ScopeContext,
) -> bool:
    """Evaluate a NOT condition — negate the sub-condition."""
    return not _evaluate_condition(condition.not_, entity, scope)


_CONDITION_DISPATCH: dict[type, Callable] = {
    PredicateCondition: _eval_predicate_condition,
    AndCondition: _eval_and_condition,
    OrCondition: _eval_or_condition,
    NotCondition: _eval_not_condition,
}


def _evaluate_condition(
    condition: Condition,
    entity: EntityData,
    scope: ScopeContext,
) -> bool:
    """Recursively evaluate a condition tree against entity data."""
    handler = _CONDITION_DISPATCH.get(type(condition))
    if handler is None:
        raise TypeError(f"Unknown condition type: {type(condition)}")
    return handler(condition, entity, scope)


# =============================================================================
# Validation
# =============================================================================


def _validate_predicates_in_condition(condition: Condition) -> None:
    """Recursively check that all predicates in a condition tree are known.

    Raises ``ValueError`` if any predicate is not in the closed vocabulary.
    This is the load-time rejection gate per SPEC section 8.2.
    """
    if isinstance(condition, PredicateCondition):
        if condition.predicate not in _PREDICATE_EVALUATORS:
            raise ValueError(
                f"Unknown predicate '{condition.predicate}' is not in the "
                f"closed vocabulary. Engine update required to support it."
            )
    elif isinstance(condition, AndCondition):
        for c in condition.all_of:
            _validate_predicates_in_condition(c)
    elif isinstance(condition, OrCondition):
        for c in condition.any_of:
            _validate_predicates_in_condition(c)
    elif isinstance(condition, NotCondition):
        _validate_predicates_in_condition(condition.not_)


def validate_rule_pack(pack: RulePack) -> None:
    """Validate all predicates in a rule pack at load time.

    Raises ``ValueError`` if any rule references an unknown predicate.
    """
    for rule in pack.attribution_rules:
        try:
            _validate_predicates_in_condition(rule.when)
        except ValueError as exc:
            raise ValueError(
                f"Rule '{rule.rule_id}' uses an invalid predicate: {exc}"
            ) from exc


# =============================================================================
# Main evaluator
# =============================================================================


class RuleEvaluator:
    """Evaluates a RulePack's attribution rules against entity data.

    Construction validates all predicates in the rule pack.  Evaluation
    iterates rules in priority order (lower number = higher priority),
    skips disabled rules, evaluates the ``when`` condition tree, and
    aggregates ``then`` actions into a ``RuleEvaluationResult``.

    Parameters
    ----------
    rule_pack : RulePack
        The rule pack to evaluate. Must contain valid predicates.
    scope_context : ScopeContext | dict | None
        Tenant authorization context providing data needed by scope-aware
        predicates (cloud ranges, apex domains, explicit identifiers, etc.).
        Accepts a ``ScopeContext`` model or a raw dict (coerced automatically).
    """

    def __init__(
        self,
        rule_pack: RulePack,
        scope_context: ScopeContext | dict[str, Any] | None = None,
    ) -> None:
        validate_rule_pack(rule_pack)
        self._rules = sorted(
            rule_pack.attribution_rules,
            key=lambda r: r.priority,
        )
        self._thresholds = rule_pack.tier_thresholds or TierThresholds()
        # Coerce dict to ScopeContext for type safety; None becomes empty.
        if scope_context is None:
            self._scope = ScopeContext()
        elif isinstance(scope_context, dict):
            self._scope = ScopeContext.model_validate(scope_context)
        else:
            self._scope = scope_context

    def evaluate(self, entity: EntityData | dict[str, Any]) -> RuleEvaluationResult:
        """Evaluate all enabled rules against a single entity.

        Parameters
        ----------
        entity : EntityData | dict
            Entity data as an ``EntityData`` model or a raw dict with keys:
            ``entity_type``, ``canonical_identifier``, ``properties`` (dict),
            ``attribution_status``, ``attribution_confidence``.  Raw dicts
            are coerced to ``EntityData`` automatically.

        Returns
        -------
        RuleEvaluationResult
            Aggregate result with matched rules, final confidence,
            attribution tier, review flags, and applied deltas.
        """
        # Coerce dict to EntityData for type safety.
        if isinstance(entity, dict):
            entity = EntityData.model_validate(entity)

        result = RuleEvaluationResult()
        base_confidence = float(entity.attribution_confidence)
        cumulative_delta = 0.0
        rejected = False

        for rule in self._rules:
            if not rule.enabled:
                continue

            try:
                matched = _evaluate_condition(rule.when, entity, self._scope)
            except Exception:
                logger.exception(
                    "Error evaluating rule %s against %s",
                    rule.rule_id,
                    entity.canonical_identifier,
                )
                continue

            if not matched:
                continue

            result.matched_rules.append(rule.rule_id)
            action = rule.then

            delta = action.confidence_delta or 0.0
            review_flag = action.review_flag or False
            review_reason = action.review_reason

            if action.outcome == Outcome.REJECT:
                rejected = True
                delta = 0.0  # Reject overrides delta

            if action.outcome == Outcome.DEMOTE:
                # Demote rules apply negative delta
                delta = -abs(delta) if delta > 0 else delta

            cumulative_delta += delta

            result.applied_deltas.append(
                AppliedDelta(
                    rule_id=rule.rule_id,
                    outcome=action.outcome.value,
                    confidence_delta=delta,
                    review_flag=review_flag,
                    review_reason=review_reason,
                )
            )

            if review_flag and review_reason:
                result.review_flags.append(review_reason)

        if rejected:
            result.final_confidence = 0.0
            result.attribution_tier = "rejected"
        else:
            result.final_confidence = max(0.0, min(1.0, base_confidence + cumulative_delta))
            result.attribution_tier = _confidence_to_tier(
                result.final_confidence, self._thresholds,
            )

        return result


__all__ = [
    "AppliedDelta",
    "EntityData",
    "RuleEvaluationResult",
    "RuleEvaluator",
    "ScopeContext",
    "validate_rule_pack",
]
