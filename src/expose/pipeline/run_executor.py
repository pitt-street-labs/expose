"""Run executor — orchestrates a complete pipeline run from seed to graph upsert.

The ``RunExecutor`` coordinates SPEC §2.2 pipeline stages for a single run:

1. **Seed expansion** (Stage 1) — deterministic rules via ``expand_seeds``.
2. **Collector dispatch** (Stage 2) — fan out (seed, collector_id) pairs to the
   dispatcher via ``DispatcherProtocol``.
3. **Sanitization** (Stage 3) — handled inside the collectors per SPEC §7.
4. **Graph upsert** (Stage 4) — persist observations via ``EntityRepository``.
5. **LLM enrichment** (Stage 4b/5) — out of scope for Sprint 3-4.
6. **Artifact generation** (Stage 6) — out of scope for Sprint 3-4.

The executor owns the run lifecycle state machine
(``pending -> running -> completed|failed|partial``) and produces a
``RunResult`` summary for the caller.

Loose coupling: the executor depends on ``DispatcherProtocol`` (a
``typing.Protocol``), not a concrete dispatcher implementation. This lets
tests inject a mock and lets the production wiring swap between in-process
dispatch and NATS-mediated dispatch without changing the executor.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from expose.collectors.base import Observation, Seed
from expose.compliance.misuse_detection import MisuseAlert, MisuseDetector
from expose.pipeline.enrichment import EnrichmentPipeline
from expose.pipeline.seed_expansion import expand_seeds
from expose.quotas.tracker import QuotaExceededError, QuotaTracker
from expose.repositories.entity_repo import EntityRepository
from expose.repositories.run_repo import RunRepository
from expose.types.shared import RunId, TenantId

logger = logging.getLogger(__name__)


# === State machine ============================================================

# Legal state transitions for the run lifecycle. The key is the current state;
# values are the set of states that may follow. Matches the manifest schema's
# ``pipeline.state`` enum and the ``RunRepository.update_state`` contract.
_VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    "pending": frozenset({"running"}),
    "running": frozenset({"completed", "failed", "partial"}),
}


def _validate_transition(current: str, target: str) -> None:
    """Raise ``ValueError`` if ``current -> target`` is not a legal transition."""
    allowed = _VALID_TRANSITIONS.get(current)
    if allowed is None or target not in allowed:
        msg = (
            f"Invalid run state transition {current!r} -> {target!r}; "
            f"allowed from {current!r}: {sorted(allowed) if allowed else 'none (terminal state)'}"
        )
        raise ValueError(msg)


# === Dispatcher protocol ======================================================


class DispatchJob(BaseModel):
    """One unit of work submitted to the dispatcher.

    Mirrors ``expose.pipeline.dispatcher.DispatchJob`` but is redefined here
    so the executor module does not import the concrete dispatcher.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    collector_id: str = Field(min_length=1)
    seed: Seed
    run_id: UUID
    tenant_id: UUID


class DispatchResult(BaseModel):
    """Structured outcome from a single dispatch.

    Mirrors the shape of ``expose.pipeline.dispatcher.DispatchResult`` so the
    executor can inspect ``status`` without importing the concrete module.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str
    observations: list[Observation] = Field(default_factory=list)
    error_message: str | None = None
    duration_ms: float = 0.0


@runtime_checkable
class DispatcherProtocol(Protocol):
    """Protocol for the dispatch interface consumed by ``RunExecutor``.

    Any object with an ``async dispatch(job) -> result`` method satisfies this
    contract. The concrete ``PipelineDispatcher`` implements it; tests inject
    an ``AsyncMock``.
    """

    async def dispatch(self, job: DispatchJob) -> DispatchResult: ...


# === Run result ===============================================================


class RunResult(BaseModel):
    """Summary statistics for a completed pipeline run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: UUID
    tenant_id: UUID
    final_state: str
    total_seeds: int
    expanded_seeds: int
    total_dispatches: int
    successful_dispatches: int
    failed_dispatches: int
    denied_dispatches: int
    total_observations: int
    enrichment_count: int = 0
    duration_ms: float
    misuse_alerts: list[MisuseAlert] = Field(default_factory=list)


# === Executor =================================================================


class RunExecutor:
    """Orchestrates a single pipeline run through all stages.

    Constructed once per run with the dispatcher, run repository, and entity
    repository injected. The ``execute`` coroutine drives the full lifecycle.
    """

    def __init__(
        self,
        *,
        dispatcher: DispatcherProtocol,
        run_repo: RunRepository,
        entity_repo: EntityRepository,
        quota_tracker: QuotaTracker | None = None,
        misuse_detector: MisuseDetector | None = None,
        enrichment_pipeline: EnrichmentPipeline | None = None,
    ) -> None:
        self._dispatcher = dispatcher
        self._run_repo = run_repo
        self._entity_repo = entity_repo
        self._quota_tracker = quota_tracker
        self._misuse_detector = misuse_detector
        self._enrichment = enrichment_pipeline

    async def execute(  # noqa: PLR0912, PLR0915
        self,
        *,
        run_id: UUID,
        tenant_id: UUID,
        seeds: list[Seed],
        collector_ids: list[str],
    ) -> RunResult:
        """Execute a full pipeline run.

        Stages:
          1. Seed expansion (deterministic).
          2. Dispatch each (expanded_seed, collector_id) pair.
          3. Sanitization (inside collectors per SPEC §7).
          4. Graph upsert for each observation from successful dispatches.
          4b/5/6. TODO placeholders for LLM enrichment and artifact generation.

        State machine: ``pending -> running -> completed|failed|partial``.

        Returns a ``RunResult`` summarizing the run.
        """
        start_ns = time.monotonic_ns()

        # === Validate and transition: pending -> running ======================
        run = await self._run_repo.get_by_id(
            tenant_id=TenantId(tenant_id),
            run_id=RunId(run_id),
        )
        if run is None:
            msg = f"No run found for tenant_id={tenant_id} run_id={run_id}"
            raise LookupError(msg)

        _validate_transition(run.state, "running")
        await self._run_repo.update_state(
            tenant_id=TenantId(tenant_id),
            run_id=RunId(run_id),
            new_state="running",
        )

        # === Quota pre-flight check ===========================================
        if self._quota_tracker is not None:
            try:
                self._quota_tracker.assert_run_allowed(tenant_id)
            except QuotaExceededError:
                self._quota_tracker.record_run_start(tenant_id)
                await self._run_repo.update_state(
                    tenant_id=TenantId(tenant_id),
                    run_id=RunId(run_id),
                    new_state="failed",
                )
                self._quota_tracker.record_run_complete(tenant_id)
                duration_ms = (time.monotonic_ns() - start_ns) / 1_000_000
                return RunResult(
                    run_id=run_id,
                    tenant_id=tenant_id,
                    final_state="failed",
                    total_seeds=0,
                    expanded_seeds=0,
                    total_dispatches=0,
                    successful_dispatches=0,
                    failed_dispatches=0,
                    denied_dispatches=0,
                    total_observations=0,
                    duration_ms=duration_ms,
                )
            self._quota_tracker.record_run_start(tenant_id)

        total_seeds = len(seeds)

        # === Stage 1: Seed expansion ==========================================
        expanded = expand_seeds(seeds)
        expanded_count = len(expanded)

        # === Stage 2: Dispatch ================================================
        successful = 0
        failed = 0
        denied = 0
        all_observations: list[Observation] = []

        for seed in expanded:
            for collector_id in collector_ids:
                job = DispatchJob(
                    collector_id=collector_id,
                    seed=seed,
                    run_id=run_id,
                    tenant_id=tenant_id,
                )
                try:
                    result = await self._dispatcher.dispatch(job)
                except Exception:
                    logger.exception(
                        "Dispatch raised for collector=%s seed=%s",
                        collector_id,
                        seed.value,
                    )
                    failed += 1
                    continue

                if result.status == "success":
                    successful += 1
                    all_observations.extend(result.observations)
                elif result.status == "denied":
                    denied += 1
                else:
                    failed += 1

        # === Stage 3: Sanitization (inside collectors per SPEC §7) ============
        # No action here — collectors apply sanitization before emitting
        # observations. The canonical observation flowing out of dispatch is
        # already sanitized.

        # === Stage 4: Graph upsert ============================================
        upsert_failures = 0
        for obs in all_observations:
            try:
                await self._entity_repo.create_or_update(
                    tenant_id=TenantId(tenant_id),
                    entity_type=obs.subject.identifier_type.value,
                    canonical_identifier=obs.subject.identifier_value,
                    properties=_observation_properties(obs),
                    attribution_status="unattributed",
                    attribution_confidence=Decimal("0.000"),
                )
            except Exception:
                logger.exception(
                    "Entity upsert failed for %s/%s",
                    obs.subject.identifier_type.value,
                    obs.subject.identifier_value,
                )
                upsert_failures += 1

        entities_added = len(all_observations) - upsert_failures
        if self._quota_tracker is not None and entities_added > 0:
            self._quota_tracker.record_entities_added(tenant_id, entities_added)

        # === Stage 4b: LLM enrichment ========================================
        enrichment_count = 0
        if self._enrichment is not None:
            for obs in all_observations:
                try:
                    enrichment_result = await self._enrichment.enrich_entity(
                        entity_type=obs.subject.identifier_type.value,
                        canonical_identifier=obs.subject.identifier_value,
                        properties=_observation_properties(obs),
                        attribution_confidence=float(Decimal("0.000")),
                        tenant_id=tenant_id,
                        run_id=run_id,
                    )
                    if enrichment_result:
                        enrichment_count += 1
                except Exception:
                    logger.exception(
                        "Enrichment failed for %s/%s",
                        obs.subject.identifier_type.value,
                        obs.subject.identifier_value,
                    )

        # TODO(stage-5): Artifact generation — out of scope for Sprint 3-4
        # When implemented, this stage will serialize the observation graph
        # into the canonical artifact format (schemas/canonical-artifact-v1.json),
        # compute content-addressed hashes per ADR-004, and upload to object
        # storage. See SPEC §2.2 Stage 6 and the manifest schema.

        # === Determine final state ============================================
        total_dispatches = successful + failed + denied
        if total_dispatches == 0 or (successful > 0 and failed == 0):
            final_state = "completed"
        elif successful > 0 and failed > 0:
            final_state = "partial"
        else:
            final_state = "failed"

        _validate_transition("running", final_state)
        await self._run_repo.update_state(
            tenant_id=TenantId(tenant_id),
            run_id=RunId(run_id),
            new_state=final_state,
        )

        if self._quota_tracker is not None:
            self._quota_tracker.record_run_complete(tenant_id)

        # === Misuse detection =================================================
        misuse_alerts: list[MisuseAlert] = []
        if self._misuse_detector is not None:
            misuse_alerts = self._misuse_detector.evaluate_run(
                tenant_id=tenant_id,
                run_id=run_id,
                in_scope=successful,
                out_of_scope=0,
                tier3_dispatches=0,
                total_dispatches=total_dispatches,
                denied=denied,
                run_timestamp=datetime.now(UTC),
            )

        duration_ms = (time.monotonic_ns() - start_ns) / 1_000_000

        return RunResult(
            run_id=run_id,
            tenant_id=tenant_id,
            final_state=final_state,
            total_seeds=total_seeds,
            expanded_seeds=expanded_count,
            total_dispatches=total_dispatches,
            successful_dispatches=successful,
            failed_dispatches=failed,
            denied_dispatches=denied,
            total_observations=len(all_observations),
            enrichment_count=enrichment_count,
            duration_ms=duration_ms,
            misuse_alerts=misuse_alerts,
        )


def _observation_properties(obs: Observation) -> dict[str, Any]:
    """Extract a properties dict from an observation for entity upsert.

    Combines the structured payload with collector provenance metadata.
    """
    props: dict[str, Any] = dict(obs.structured_payload)
    props["_collector_id"] = obs.collector_id
    props["_collector_version"] = obs.collector_version
    props["_observation_type"] = obs.observation_type.value
    props["_observed_at"] = obs.observed_at.isoformat()
    if obs.warnings:
        props["_warnings"] = list(obs.warnings)
    return props


__all__ = [
    "DispatchJob",
    "DispatchResult",
    "DispatcherProtocol",
    "RunExecutor",
    "RunResult",
]
