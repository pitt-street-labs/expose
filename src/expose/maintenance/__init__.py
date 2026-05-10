"""Scheduled maintenance jobs for EXPOSE Core.

This sub-package hosts background / cron-style maintenance routines that keep
the observation graph compliant with the contracts EXPOSE has agreed to with
operators (per the ADR set) — most notably the data-minimization promise made
in ADR-008 §Layer 3.

Currently shipped:

- ``retention_pruner.IncidentalDataPruner`` — deletes ``Entity`` rows where
  ``attribution_status = 'not_yours'`` and ``last_observed_at`` is older than
  the configured retention window (default 30 days). Per-tenant, async,
  idempotent. Closes v1 deliverable issue #31. See ADR-008 §Layer 3 and
  ``docs/SPEC.md`` §5.5 for the contract.

Future maintenance jobs (evidence pruning, run-history compaction, audit-log
rotation) will land alongside this one and follow the same patterns:
``AsyncSession`` constructor injection, structured logging without entity
identifiers, deterministic clock injection for tests.
"""

from expose.maintenance.retention_pruner import (
    DEFAULT_RETENTION_DAYS,
    IncidentalDataPruner,
    PruneResult,
)

__all__ = [
    "DEFAULT_RETENTION_DAYS",
    "IncidentalDataPruner",
    "PruneResult",
]
