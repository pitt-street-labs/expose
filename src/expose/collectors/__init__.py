"""Collector framework — abstract base, tier gating, and registry (per SPEC §6).

The collector framework is the contract between the dispatcher and any
specific data source (CT logs, passive DNS, cloud IP-range manifests, active
probing). Concrete collectors land sprint-by-sprint per SPEC §11.1; this
package only commits to the framework shape.

This module re-exports the public surface so out-of-tree consumers (tests,
future plugins) write::

    from expose.collectors import Collector, CollectorConfig, register_collector

rather than reaching into individual sub-modules.

Sub-modules:

- ``base`` — ``Collector`` ABC, ``CollectorConfig``, ``Observation``, ``Seed``,
  ``CollectorHealthCheck``, the catastrophic-error exception hierarchy.
- ``tiers`` — ``CollectorTier`` enum, Tier-3 attribution-gating helpers.
- ``registry`` — collector-ID-to-class registry used by the dispatcher.
"""

from expose.collectors.base import (
    Collector,
    CollectorAuthenticationError,
    CollectorConfig,
    CollectorCredential,
    CollectorError,
    CollectorHealthCheck,
    CollectorRateLimitError,
    CollectorSourceUnreachableError,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import (
    DEFAULT_REGISTRY,
    CollectorAlreadyRegisteredError,
    CollectorNotRegisteredError,
    CollectorRegistry,
    get_collector,
    register_collector,
)
from expose.collectors.tiers import (
    CollectorTier,
    EnforcementMode,
    EntityAttributionView,
    TenantAuthorizationScope,
    Tier3DispatchDeniedError,
    assert_tier_3_dispatch_allowed,
    is_tier_3_dispatch_allowed,
)

__all__ = [
    "DEFAULT_REGISTRY",
    "Collector",
    "CollectorAlreadyRegisteredError",
    "CollectorAuthenticationError",
    "CollectorConfig",
    "CollectorCredential",
    "CollectorError",
    "CollectorHealthCheck",
    "CollectorNotRegisteredError",
    "CollectorRateLimitError",
    "CollectorRegistry",
    "CollectorSourceUnreachableError",
    "CollectorTier",
    "EnforcementMode",
    "EntityAttributionView",
    "Observation",
    "ObservationSubject",
    "ObservationType",
    "Seed",
    "SeedType",
    "TenantAuthorizationScope",
    "Tier3DispatchDeniedError",
    "assert_tier_3_dispatch_allowed",
    "get_collector",
    "is_tier_3_dispatch_allowed",
    "register_collector",
]
