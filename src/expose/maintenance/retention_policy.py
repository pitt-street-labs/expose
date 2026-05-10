"""Per-tenant retention policy model — configurable tier lifecycle for entities
and evidence.

Extends the incidental-data pruner (``retention_pruner.py``) with a full policy
layer: hot/cold/delete tiering, litigation holds, and evidence-specific windows.
The pruner handles Postgres-level ``DELETE`` of ``not_yours`` rows past a single
``incidental_days`` threshold; this module adds the higher-level policy
evaluation that determines *what action to take* for any entity based on its
age, attribution status, and the tenant's configured retention policy.

Design notes:

- **Litigation hold** is an absolute override: when active, no entity is
  eligible for migration or deletion regardless of age. This satisfies legal
  hold obligations (FRCP, FRE, GDPR Art. 17(3)(e)) without requiring the
  operator to manually adjust every threshold.

- **Attribution-aware tiering**: ``not_yours`` (incidental) entities follow the
  short ``incidental_days`` window per SPEC §5.5 and ADR-008 §Layer 3.
  Confirmed/high/medium/requires_review entities get a much longer lifecycle
  through hot → cold → delete transitions. Unattributed entities default to
  incidental treatment (conservative: if we don't know it's ours, treat it as
  if it isn't).

- **Scheduler skeleton**: ``RetentionScheduler`` wraps ``evaluate_retention``
  for batch processing. Production use is via a daily cron job or Kubernetes
  CronJob; this sprint delivers the evaluation logic and batch interface
  without the actual S3/blob lifecycle wiring (that's issue #9, object
  storage).

References:
    - SPEC §5.5: Retention windows
    - SPEC §10.1: Tenant configuration
    - ADR-008 §Layer 3: Data minimization
    - Issue #12: Retention policy model
"""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RetentionTier(StrEnum):
    """Storage tier for an entity or evidence artifact.

    Mirrors the lifecycle stages in a typical object-storage tiering policy
    (S3 Intelligent-Tiering, GCS Nearline/Coldline, Azure Cool/Archive).
    The engine evaluates which tier an entity belongs in; actual data movement
    is handled by the storage backend (issue #9).
    """

    HOT = "hot"
    COLD = "cold"
    DELETE = "delete"


class RetentionAction(StrEnum):
    """Action the retention evaluator recommends for an entity.

    ``KEEP`` means remain in the current tier (no action needed).
    ``MIGRATE_COLD`` means move from hot to cold storage.
    ``DELETE`` means remove from all storage tiers.
    """

    KEEP = "keep"
    MIGRATE_COLD = "migrate_cold"
    DELETE = "delete"


class RetentionPolicy(BaseModel):
    """Per-tenant retention policy configuration.

    All window values are in days. Defaults match SPEC §5.5 and §10.1:
    incidental (not_yours) at 30 days, hot tier at 365 days (1 year),
    cold tier at 2555 days (~7 years, aligning with common regulatory
    retention requirements).

    Frozen and extra-forbid per project convention — a policy is a value
    object, not a mutable config bag.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    incidental_days: int = Field(
        default=30,
        gt=0,
        description="Retention window for not_yours entities (SPEC §5.5 default: 30).",
    )
    hot_tier_days: int = Field(
        default=365,
        gt=0,
        description="Days confirmed/high entities remain in fast (hot) storage.",
    )
    cold_tier_days: int = Field(
        default=2555,
        gt=0,
        description="Days in archive (cold) storage after hot tier expires (~7 years).",
    )
    evidence_hot_days: int = Field(
        default=365,
        gt=0,
        description="Days evidence artifacts remain in hot storage.",
    )
    evidence_cold_days: int = Field(
        default=2555,
        gt=0,
        description="Days evidence artifacts remain in cold storage after hot expires.",
    )
    litigation_hold: bool = Field(
        default=False,
        description=(
            "When True, overrides all deletion and migration. "
            "No entity or evidence is eligible for tier change or removal."
        ),
    )


class RetentionDecision(BaseModel):
    """Result of evaluating retention policy for a single entity.

    Frozen so callers (scheduler, audit log, test assertions) cannot mutate
    the decision after the fact — same rationale as ``PruneResult`` in the
    pruner module.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_identifier: str
    current_tier: RetentionTier
    action: RetentionAction
    reason: str
    days_since_last_observed: int


# Attribution statuses that qualify for the full hot → cold → delete lifecycle.
# Everything else is treated as incidental (conservative default).
_OWNED_STATUSES: frozenset[str] = frozenset(
    {"confirmed", "high", "medium", "requires_review"}
)


def _decide_incidental(
    entity_identifier: str,
    entity_age_days: int,
    policy: RetentionPolicy,
    *,
    status_label: str = "incidental",
) -> RetentionDecision:
    """Shared logic for incidental and unattributed entities."""
    if entity_age_days > policy.incidental_days:
        return RetentionDecision(
            entity_identifier=entity_identifier,
            current_tier=RetentionTier.DELETE,
            action=RetentionAction.DELETE,
            reason=f"{status_label} entity exceeded {policy.incidental_days}-day retention",
            days_since_last_observed=entity_age_days,
        )
    return RetentionDecision(
        entity_identifier=entity_identifier,
        current_tier=RetentionTier.HOT,
        action=RetentionAction.KEEP,
        reason=f"{status_label} entity within retention window",
        days_since_last_observed=entity_age_days,
    )


def _decide_owned(
    entity_identifier: str,
    entity_age_days: int,
    policy: RetentionPolicy,
) -> RetentionDecision:
    """Hot → cold → delete lifecycle for owned entities."""
    if entity_age_days <= policy.hot_tier_days:
        return RetentionDecision(
            entity_identifier=entity_identifier,
            current_tier=RetentionTier.HOT,
            action=RetentionAction.KEEP,
            reason="entity within hot tier window",
            days_since_last_observed=entity_age_days,
        )
    cold_deadline = policy.hot_tier_days + policy.cold_tier_days
    if entity_age_days <= cold_deadline:
        return RetentionDecision(
            entity_identifier=entity_identifier,
            current_tier=RetentionTier.COLD,
            action=RetentionAction.MIGRATE_COLD,
            reason="entity exceeded hot tier; eligible for cold storage",
            days_since_last_observed=entity_age_days,
        )
    return RetentionDecision(
        entity_identifier=entity_identifier,
        current_tier=RetentionTier.DELETE,
        action=RetentionAction.DELETE,
        reason=f"entity exceeded cold tier ({cold_deadline} days total retention)",
        days_since_last_observed=entity_age_days,
    )


def evaluate_retention(
    *,
    entity_identifier: str,
    entity_age_days: int,
    attribution_status: str,
    policy: RetentionPolicy,
) -> RetentionDecision:
    """Evaluate the retention action for a single entity against a policy.

    Args:
        entity_identifier: Canonical identifier of the entity (for the
            decision record; not used in the evaluation logic itself).
        entity_age_days: Days since the entity was last observed.
        attribution_status: Current attribution status string from the
            observation graph (e.g. "confirmed", "not_yours").
        policy: The tenant's retention policy.

    Returns:
        A ``RetentionDecision`` with the recommended action, current tier,
        and human-readable reason.
    """
    # Litigation hold is an absolute override — no deletions, no migrations.
    if policy.litigation_hold:
        return RetentionDecision(
            entity_identifier=entity_identifier,
            current_tier=RetentionTier.HOT,
            action=RetentionAction.KEEP,
            reason="litigation hold active",
            days_since_last_observed=entity_age_days,
        )

    # Incidental (not_yours) entities: short retention per SPEC §5.5.
    if attribution_status == "not_yours":
        return _decide_incidental(entity_identifier, entity_age_days, policy)

    # Owned entities: hot → cold → delete lifecycle.
    if attribution_status in _OWNED_STATUSES:
        return _decide_owned(entity_identifier, entity_age_days, policy)

    # Unattributed / unknown status: treat as incidental (conservative default).
    return _decide_incidental(
        entity_identifier,
        entity_age_days,
        policy,
        status_label=f"unattributed (status={attribution_status!r})",
    )


class RetentionScheduler:
    """Evaluates retention policies for all entities in a tenant.

    Production use: called by a daily cron job or Kubernetes CronJob.
    This sprint: skeleton that can be called programmatically.

    The scheduler does not perform any I/O — it evaluates the policy against
    entity metadata provided by the caller. Actual data movement (S3 lifecycle
    transitions, blob deletes) is the responsibility of the storage backend
    (issue #9).
    """

    def __init__(self, policy: RetentionPolicy) -> None:
        self._policy = policy

    @property
    def policy(self) -> RetentionPolicy:
        """The retention policy this scheduler evaluates against."""
        return self._policy

    def evaluate(
        self,
        entity_identifier: str,
        age_days: int,
        attribution_status: str,
    ) -> RetentionDecision:
        """Evaluate retention for a single entity.

        Convenience wrapper around the module-level ``evaluate_retention``
        function, pre-binding the scheduler's policy.

        Args:
            entity_identifier: Canonical identifier of the entity.
            age_days: Days since the entity was last observed.
            attribution_status: Current attribution status.

        Returns:
            A ``RetentionDecision`` with the recommended action.
        """
        return evaluate_retention(
            entity_identifier=entity_identifier,
            entity_age_days=age_days,
            attribution_status=attribution_status,
            policy=self._policy,
        )

    def evaluate_batch(
        self,
        entities: list[dict[str, int | str]],
    ) -> list[RetentionDecision]:
        """Evaluate retention for a batch of entities.

        Each dict must contain keys ``entity_identifier`` (str),
        ``age_days`` (int), and ``attribution_status`` (str).

        Args:
            entities: List of entity metadata dicts.

        Returns:
            List of ``RetentionDecision`` objects in the same order as input.
        """
        return [
            evaluate_retention(
                entity_identifier=str(e["entity_identifier"]),
                entity_age_days=int(e["age_days"]),
                attribution_status=str(e["attribution_status"]),
                policy=self._policy,
            )
            for e in entities
        ]
