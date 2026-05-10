"""Rich authorization scope models and matching (per SPEC §10.1).

The ``TenantAuthorizationScope`` in ``expose.collectors.tiers`` provides a
minimal membership predicate for Tier-3 dispatch gating: "is this exact
entity identifier in the scope?".  That is sufficient for the gating hot
path, but the full authorization scope described in SPEC §10.1 is richer:
apex domains, cloud accounts, registrant patterns, ASN ranges, CIDR blocks,
and exclusions.

This package implements the rich scope model and matching engine that sits
*above* the dispatch layer.  It is consumed by:

- The pipeline dispatcher to resolve whether a *discovered* entity falls
  within the tenant's authorized perimeter before promoting it through the
  graph (as distinct from the Tier-3 dispatch gate, which checks *explicit*
  identifiers).
- The scope-change diffing logic that produces
  ``DeltaRemovalReason.SCOPE_CHANGED_NOW_OUTSIDE`` events.
- The ``outside_authorized_scope_summary`` section of the canonical artifact.

Re-exports the public surface so consumers write::

    from expose.scope import (
        AuthorizationScope,
        ScopeMatchResult,
        ScopeMatcher,
        ScopeRule,
        ScopeRuleType,
    )

Matching semantics:

- **Exclusions override inclusions**: if both an include and exclude rule
  match an entity, the exclusion wins.  This is intentional — security
  teams must be able to carve out sub-domains or IP ranges that are
  technically "within" an apex but operationally off-limits (shared
  hosting, CDN, partner infra).
- Rule evaluation is short-circuit: once an exclusion matches, the entity
  is out of scope regardless of subsequent inclusion rules.
"""

from expose.scope.matcher import ScopeMatcher, ScopeMatchResult
from expose.scope.models import AuthorizationScope, ScopeRule, ScopeRuleType

__all__ = [
    "AuthorizationScope",
    "ScopeMatchResult",
    "ScopeMatcher",
    "ScopeRule",
    "ScopeRuleType",
]
