"""Scope matching engine (per SPEC §10.1).

Evaluates whether an entity falls within a tenant's
:class:`~expose.scope.models.AuthorizationScope` by checking each
:class:`~expose.scope.models.ScopeRule` against the entity's type and
value.

Matching semantics:

1. **Exclusion rules are checked first.**  If *any* exclusion rule matches,
   the entity is out of scope regardless of inclusion rules.  This ensures
   security teams can carve out shared-hosting domains, CDN ranges, or
   partner infrastructure.

2. **Inclusion rules are checked in order.**  The first matching inclusion
   rule determines the match result.

3. **No match → not in scope.**  An entity that doesn't match any rule is
   outside the authorized perimeter.

Domain matching uses :func:`expose.sanitization.canonicalize.canonicalize_domain`
for normalization.  IP/CIDR matching uses :mod:`ipaddress` from the stdlib.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from expose.sanitization.canonicalize import CanonicalizationError, canonicalize_domain
from expose.scope.models import ScopeRule, ScopeRuleType

if TYPE_CHECKING:
    from expose.scope.models import AuthorizationScope

# Type alias for the per-rule-type match functions used in the dispatch table.
_MatchFn = Callable[[str, str, str], bool]


class ScopeMatchResult(BaseModel):
    """Result of evaluating an entity against an authorization scope.

    Attributes:
        in_scope: Whether the entity is within the authorized perimeter.
        matched_rule: The inclusion rule that matched (if any).
        excluded_by: The exclusion rule that caused rejection (if any).
        reason: Human-readable explanation of the match decision.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    in_scope: bool
    matched_rule: ScopeRule | None = None
    excluded_by: ScopeRule | None = None
    reason: str


def _is_subdomain_of(candidate: str, apex: str) -> bool:
    """Return True if ``candidate`` is the apex itself or a subdomain of it.

    Both arguments must already be canonicalized (lowercase, IDN-encoded,
    no trailing dot).
    """
    if candidate == apex:
        return True
    return candidate.endswith("." + apex)


def _ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    """Return True if ``ip_str`` is contained in ``cidr_str``.

    Returns False on any parse error rather than raising — the caller
    should have validated inputs, but we fail safe here.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return False
    return addr in network


class ScopeMatcher:
    """Evaluates whether an entity is within the authorization scope.

    Instantiate with an :class:`~expose.scope.models.AuthorizationScope` and
    call :meth:`matches` for each entity to check.

    The matcher pre-partitions rules into exclusion and inclusion lists at
    construction time, so repeated calls to :meth:`matches` avoid re-scanning
    the full rule list.
    """

    def __init__(self, scope: AuthorizationScope) -> None:
        self._scope = scope
        self._exclusions: list[ScopeRule] = []
        self._inclusions: list[ScopeRule] = []
        for rule in scope.rules:
            if not rule.include or rule.rule_type == ScopeRuleType.EXCLUSION_DOMAIN:
                self._exclusions.append(rule)
            else:
                self._inclusions.append(rule)

    def matches(self, entity_type: str, entity_value: str) -> ScopeMatchResult:
        """Evaluate whether an entity is within the authorization scope.

        Args:
            entity_type: The kind of entity (``"domain"``, ``"ip"``,
                ``"cidr"``, ``"asn"``, ``"cloud_account"``,
                ``"registrant_org"``).
            entity_value: The entity's identifier value.

        Returns:
            A :class:`ScopeMatchResult` with the match decision, the
            matched rule (if any), and a human-readable reason.
        """
        # Phase 1: check exclusions — any match means out of scope.
        for rule in self._exclusions:
            if self._rule_matches(rule, entity_type, entity_value):
                return ScopeMatchResult(
                    in_scope=False,
                    excluded_by=rule,
                    reason=(f"Excluded by {rule.rule_type.value} rule: {rule.value!r}"),
                )

        # Phase 2: check inclusions — first match wins.
        for rule in self._inclusions:
            if self._rule_matches(rule, entity_type, entity_value):
                return ScopeMatchResult(
                    in_scope=True,
                    matched_rule=rule,
                    reason=(f"Matched {rule.rule_type.value} rule: {rule.value!r}"),
                )

        # Phase 3: no match — not in scope.
        return ScopeMatchResult(
            in_scope=False,
            reason="No matching scope rule found",
        )

    def _rule_matches(self, rule: ScopeRule, entity_type: str, entity_value: str) -> bool:
        """Return True if ``rule`` matches the given entity."""
        # Dispatch table avoids PLR0911 (too many return statements) and
        # ensures new ScopeRuleType variants produce a clear KeyError rather
        # than a silent fallthrough.
        dispatch: dict[
            ScopeRuleType,
            _MatchFn,
        ] = {
            ScopeRuleType.APEX_DOMAIN: self._match_apex_domain,
            ScopeRuleType.EXACT_DOMAIN: self._match_exact_domain,
            ScopeRuleType.IP_ADDRESS: self._match_ip,
            ScopeRuleType.CIDR: self._match_cidr,
            ScopeRuleType.ASN: self._match_asn,
            ScopeRuleType.CLOUD_ACCOUNT: self._match_cloud_account,
            ScopeRuleType.REGISTRANT_ORG: self._match_registrant_org,
            ScopeRuleType.EXCLUSION_DOMAIN: self._match_exact_domain,
        }
        handler = dispatch[rule.rule_type]
        return handler(rule.value, entity_type, entity_value)

    @staticmethod
    def _match_apex_domain(apex_value: str, entity_type: str, entity_value: str) -> bool:
        """Apex domain: entity must be the apex or a subdomain of it."""
        if entity_type not in {"domain", "subdomain"}:
            return False
        try:
            canonical_entity = canonicalize_domain(entity_value)
            canonical_apex = canonicalize_domain(apex_value)
        except CanonicalizationError:
            return False
        return _is_subdomain_of(canonical_entity, canonical_apex)

    @staticmethod
    def _match_exact_domain(domain_value: str, entity_type: str, entity_value: str) -> bool:
        """Exact domain: string match after canonicalization."""
        if entity_type not in {"domain", "subdomain"}:
            return False
        try:
            canonical_entity = canonicalize_domain(entity_value)
            canonical_rule = canonicalize_domain(domain_value)
        except CanonicalizationError:
            return False
        return canonical_entity == canonical_rule

    @staticmethod
    def _match_ip(ip_value: str, entity_type: str, entity_value: str) -> bool:
        """IP address: exact match after parsing."""
        if entity_type != "ip":
            return False
        try:
            rule_addr = ipaddress.ip_address(ip_value)
            entity_addr = ipaddress.ip_address(entity_value)
        except ValueError:
            return False
        return rule_addr == entity_addr

    @staticmethod
    def _match_cidr(cidr_value: str, entity_type: str, entity_value: str) -> bool:
        """CIDR: IP containment check."""
        if entity_type != "ip":
            return False
        return _ip_in_cidr(entity_value, cidr_value)

    @staticmethod
    def _match_asn(asn_value: str, entity_type: str, entity_value: str) -> bool:
        """ASN: string match."""
        if entity_type != "asn":
            return False
        return entity_value.strip().upper() == asn_value.strip().upper()

    @staticmethod
    def _match_cloud_account(account_value: str, entity_type: str, entity_value: str) -> bool:
        """Cloud account: string match."""
        if entity_type != "cloud_account":
            return False
        return entity_value.strip() == account_value.strip()

    @staticmethod
    def _match_registrant_org(org_value: str, entity_type: str, entity_value: str) -> bool:
        """Registrant org: case-insensitive substring match."""
        if entity_type != "registrant_org":
            return False
        return org_value.strip().lower() in entity_value.strip().lower()


__all__ = [
    "ScopeMatchResult",
    "ScopeMatcher",
]
