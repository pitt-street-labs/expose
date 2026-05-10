"""Collector tiering and attribution-gating helpers (per SPEC.md §6.3).

Collectors are tiered by sensitivity:

- ``TIER_1`` — Passive, broad query (CT logs, passive DNS, ASN, cloud IP ranges).
- ``TIER_2`` — Passive, targeted (internet-wide scan APIs against seed-graph hosts).
- ``TIER_3`` — Active, attribution-gated (DNS resolution, TLS handshake, HTTP
  fingerprinting, port surface). Only executed against entities whose attribution
  tier is ``confirmed`` or ``high`` OR which are explicitly in the tenant
  authorization scope.

Per ADR-008 (authorized use), Tier-3 dispatch is enforced *at the collector
dispatch layer*. Attempting to dispatch a Tier-3 job for an unattributed entity
must raise ``Tier3DispatchDeniedError`` so callers fail loud rather than silently
probing third-party assets.

Enforcement mode (per Gitea issue #29) controls how the dispatcher responds when
Tier-3 dispatch is denied:

- ``medium`` (default): The gating function returns ``False``; the caller may
  treat this as a warning and proceed at its discretion.
- ``hard``: The gating function returns ``False``; the caller MUST treat this as
  an absolute refusal. The ``EnforcementLog`` (in ``expose.pipeline.enforcement``)
  records a structured ``ScopeRefusalEvent`` for audit purposes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from expose.types.canonical import AttributionTier


class CollectorTier(StrEnum):
    """Sensitivity tier for a collector module (SPEC §6.3).

    Values are stable strings used for configuration, audit logs, and the
    ``collector_health`` artifact section.
    """

    TIER_1 = "tier_1"
    TIER_2 = "tier_2"
    TIER_3 = "tier_3"


class EnforcementMode(StrEnum):
    """Controls how the dispatcher responds to Tier-3 dispatch denials.

    Per Gitea issue #29:

    - ``MEDIUM`` — denial is advisory; the caller may log a warning and proceed.
    - ``HARD`` — denial is absolute; the caller MUST refuse and record a
      structured refusal event via ``EnforcementLog``.

    Passive collectors (Tier-1) remain unrestricted in all modes.
    """

    MEDIUM = "medium"
    HARD = "hard"


# Attribution tiers that satisfy Tier-3 dispatch on their own (SPEC §6.3).
# `requires_review` and `medium` do NOT pass — Tier 3 needs `confirmed` or
# `high`, OR an explicit authorization-scope membership for the entity.
_TIER_3_DISPATCH_ATTRIBUTION_FLOOR: frozenset[AttributionTier] = frozenset(
    {AttributionTier.CONFIRMED, AttributionTier.HIGH}
)


@dataclass(frozen=True)
class EntityAttributionView:
    """Minimal projection of an entity needed for Tier-3 gating.

    The dispatcher does not need the full canonical ``Target`` object — only
    the attribution tier and an identifier for diagnostics. This keeps the
    gating function side-effect free and easy to test in isolation.
    """

    entity_identifier: str
    attribution_tier: AttributionTier | None  # ``None`` means unattributed.


@dataclass(frozen=True)
class TenantAuthorizationScope:
    """Minimal projection of the tenant authorization scope (SPEC §10.1).

    Only the membership predicate (``contains``) is required for Tier-3 gating.
    The full scope schema (apex domains, cloud accounts, registrant patterns,
    ASN ranges, exclusions) is consumed elsewhere; here we just need to ask
    "is this entity explicitly in the scope?".

    The ``enforcement_mode`` field (default ``MEDIUM``) controls how the
    dispatcher responds when Tier-3 dispatch is denied — see ``EnforcementMode``
    for semantics.
    """

    explicit_entity_identifiers: frozenset[str]
    enforcement_mode: EnforcementMode = field(default=EnforcementMode.MEDIUM)

    def contains(self, entity_identifier: str) -> bool:
        """Return True if ``entity_identifier`` is explicitly in scope.

        Membership is exact-match on the identifier as canonicalized by the
        sanitization layer (SPEC §7.2). Pattern-based membership (e.g., apex
        domain implying subdomains) is the dispatcher's responsibility before
        calling this helper.
        """

        return entity_identifier in self.explicit_entity_identifiers


class Tier3DispatchDeniedError(PermissionError):
    """Raised when a Tier-3 collector job is dispatched for an entity that
    does not meet the attribution-or-scope gate (SPEC §6.3 / ADR-008).

    This is a ``PermissionError`` subclass so generic exception handlers that
    distinguish authorization failures from operational errors do the right
    thing.
    """


def is_tier_3_dispatch_allowed(
    entity: EntityAttributionView,
    tenant_scope: TenantAuthorizationScope,
) -> bool:
    """Return True if a Tier-3 collector may be dispatched against ``entity``.

    Per SPEC §6.3: dispatch is allowed iff
    ``entity.attribution_tier in {confirmed, high}`` OR the entity is
    explicitly in the tenant's authorization scope.

    This helper is the *single* authoritative gate. The dispatcher calls it;
    individual collectors do not. Centralizing the check keeps the policy
    auditable and avoids drift between collector implementations.
    """

    if (
        entity.attribution_tier is not None
        and entity.attribution_tier in _TIER_3_DISPATCH_ATTRIBUTION_FLOOR
    ):
        return True
    return tenant_scope.contains(entity.entity_identifier)


def assert_tier_3_dispatch_allowed(
    entity: EntityAttributionView,
    tenant_scope: TenantAuthorizationScope,
) -> None:
    """Raise ``Tier3DispatchDeniedError`` if Tier-3 dispatch is not allowed.

    Convenience wrapper for dispatcher code paths where the failure mode is
    "stop the job and surface the violation" rather than "branch on a bool".
    """

    if not is_tier_3_dispatch_allowed(entity, tenant_scope):
        msg = (
            f"Tier-3 dispatch denied for entity {entity.entity_identifier!r}: "
            f"attribution_tier={entity.attribution_tier} and entity not in "
            "authorization scope (SPEC §6.3 / ADR-008)."
        )
        raise Tier3DispatchDeniedError(msg)


__all__ = [
    "CollectorTier",
    "EnforcementMode",
    "EntityAttributionView",
    "TenantAuthorizationScope",
    "Tier3DispatchDeniedError",
    "assert_tier_3_dispatch_allowed",
    "is_tier_3_dispatch_allowed",
]
