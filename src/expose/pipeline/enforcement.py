"""Structured enforcement logging for authorization-scope refusals (Gitea #29).

When the dispatcher denies a Tier-3 dispatch (either because the entity lacks
sufficient attribution or is not in the tenant's explicit scope), it records a
:class:`ScopeRefusalEvent` in the per-run :class:`EnforcementLog`.

The enforcement log serves two purposes:

1. **Audit trail.** Each refusal event carries the tenant, entity, collector,
   reason, and timestamp so compliance reviewers can verify the engine never
   probed unauthorized assets.
2. **Manifest inclusion.** The dispatcher can serialize the log's refusals into
   the run artifact manifest, giving downstream consumers visibility into what
   was *not* collected (and why).

Usage::

    log = EnforcementLog()
    log.record_refusal(ScopeRefusalEvent(
        tenant_id=tenant_id,
        entity_identifier="unknown.example",
        attribution_tier=None,
        enforcement_mode=EnforcementMode.HARD,
        collector_id="tls-prober",
        reason="Entity not in authorization scope and attribution tier is None",
        timestamp=datetime.now(UTC),
    ))
    assert log.refusal_count == 1
"""

from __future__ import annotations

import logging
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from expose.collectors.tiers import EnforcementMode

logger = logging.getLogger(__name__)


class ScopeRefusalEvent(BaseModel):
    """Structured record of a single scope-enforcement refusal.

    Frozen and extra-forbid so events are tamper-evident once created. All
    fields are required; ``attribution_tier`` is ``None`` when the entity has
    no attribution record at all.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    entity_identifier: str = Field(min_length=1)
    attribution_tier: str | None
    enforcement_mode: EnforcementMode
    collector_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    timestamp: datetime


class EnforcementLog:
    """Accumulates refusal events during a pipeline run.

    Designed to be instantiated once per run and passed to the dispatcher. After
    the run completes, the caller reads :attr:`refusals` for manifest inclusion.

    Thread safety: not required. The dispatcher processes jobs sequentially
    within a single async task per run.
    """

    def __init__(self) -> None:
        self._refusals: list[ScopeRefusalEvent] = []

    def record_refusal(self, event: ScopeRefusalEvent) -> None:
        """Record a refusal and emit a structured log line.

        The log message uses ``logger.warning`` so it surfaces in default
        logging configurations. The event itself is the source of truth; the
        log line is for human operators watching the run in real time.
        """
        self._refusals.append(event)
        logger.warning(
            "Scope refusal [%s]: entity=%r collector=%s tier=%s reason=%s",
            event.enforcement_mode.value,
            event.entity_identifier,
            event.collector_id,
            event.attribution_tier,
            event.reason,
        )

    @property
    def refusal_count(self) -> int:
        """Number of refusal events recorded so far."""
        return len(self._refusals)

    @property
    def refusals(self) -> list[ScopeRefusalEvent]:
        """Snapshot of all refusal events (returns a copy).

        Returning a copy prevents callers from mutating the log's internal
        state. The cost is negligible — refusal counts should be small relative
        to successful dispatches.
        """
        return list(self._refusals)


__all__ = [
    "EnforcementLog",
    "ScopeRefusalEvent",
]
