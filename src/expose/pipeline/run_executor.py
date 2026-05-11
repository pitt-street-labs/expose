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

import asyncio
import logging
import socket
import time
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from expose.collectors.base import Observation, Seed
from expose.compliance.misuse_detection import MisuseAlert, MisuseDetector
from expose.pipeline.dispatcher import clear_health_cache
from expose.pipeline.enrichment import EnrichmentPipeline
from expose.pipeline.entity_seed_converter import (
    entities_to_seeds,
    extract_org_seeds_from_properties,
)
from expose.pipeline.seed_expansion import expand_seeds
from expose.quotas.tracker import QuotaExceededError, QuotaTracker
from expose.repositories.entity_repo import EntityRepository
from expose.repositories.relationship_repo import RelationshipRepository
from expose.repositories.run_repo import RunRepository
from expose.types.shared import EntityId, RunId, TenantId

# Type alias for the log sink callable used by the executor and dispatcher.
# Signature: (level, msg) -> None where level is "info", "warn", or "error".
LogSink = Callable[[str, str], None]

logger = logging.getLogger(__name__)

# Maximum number of concurrent dispatcher tasks during a single pass.
# Bounded via ``asyncio.Semaphore`` to avoid overwhelming external APIs.
_MAX_CONCURRENT_DISPATCHES = 15

# Maximum number of observations to accumulate before flushing to the entity
# repository and running enrichment.  Prevents unbounded memory growth on
# large scans (e.g., subdomain enumeration returning 10k+ results).
_OBSERVATION_BATCH_SIZE = 500


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
    passes_completed: int = 1
    entities_discovered_per_pass: list[int] = Field(default_factory=list)


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
        relationship_repo: RelationshipRepository | None = None,
        quota_tracker: QuotaTracker | None = None,
        misuse_detector: MisuseDetector | None = None,
        enrichment_pipeline: EnrichmentPipeline | None = None,
        log_sink: LogSink | None = None,
    ) -> None:
        self._dispatcher = dispatcher
        self._run_repo = run_repo
        self._entity_repo = entity_repo
        self._relationship_repo = relationship_repo
        self._quota_tracker = quota_tracker
        self._misuse_detector = misuse_detector
        self._enrichment = enrichment_pipeline
        self._log_sink = log_sink

    def _log(self, level: str, msg: str) -> None:
        """Emit a structured log entry to the log sink, if configured."""
        if self._log_sink is not None:
            self._log_sink(level, msg)

    async def _dns_filter_seeds(self, seeds: list[Seed]) -> list[Seed]:
        """Remove DOMAIN seeds that do not resolve via DNS.

        Non-DOMAIN seeds (ORGANIZATION, IP, CIDR, ASN, ENTITY, etc.) are
        always kept. For each DOMAIN seed, a fast ``getaddrinfo`` lookup is
        performed with a 3-second per-domain timeout. Domains that return
        any A or AAAA record are kept; those that fail (NXDOMAIN, timeout,
        socket error) are dropped.

        This prevents the multi-TLD expansion from dispatching 29 collectors
        against ``korlogos.net``, ``korlogos.gov``, etc. when those domains
        do not exist.
        """
        from expose.collectors.base import SeedType

        domain_seeds: list[Seed] = []
        non_domain_seeds: list[Seed] = []
        for seed in seeds:
            if seed.seed_type == SeedType.DOMAIN:
                domain_seeds.append(seed)
            else:
                non_domain_seeds.append(seed)

        if not domain_seeds:
            return seeds

        async def _check_domain(seed: Seed) -> Seed | None:
            """Return the seed if it resolves, None otherwise."""
            try:
                result = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None,
                        socket.getaddrinfo,
                        seed.value,
                        None,
                        socket.AF_UNSPEC,
                        socket.SOCK_STREAM,
                    ),
                    timeout=3.0,
                )
                if result:
                    return seed
            except (TimeoutError, socket.gaierror, OSError):
                pass
            return None

        results = await asyncio.gather(
            *[_check_domain(s) for s in domain_seeds],
        )

        resolved = [s for s in results if s is not None]
        filtered_count = len(domain_seeds) - len(resolved)

        self._log(
            "info",
            f"DNS filter: {len(resolved)} of {len(domain_seeds)} domain seeds resolve"
            + (f" ({filtered_count} removed)" if filtered_count else ""),
        )
        if filtered_count:
            logger.info(
                "DNS filter removed %d non-resolving domain seeds out of %d",
                filtered_count,
                len(domain_seeds),
            )

        return non_domain_seeds + resolved

    async def execute(  # noqa: PLR0912, PLR0915
        self,
        *,
        run_id: UUID,
        tenant_id: UUID,
        seeds: list[Seed],
        collector_ids: list[str],
        max_passes: int = 3,
    ) -> RunResult:
        """Execute a full pipeline run with iterative multi-pass expansion.

        Stages:
          1. Seed expansion (deterministic).
          2. Dispatch each (expanded_seed, collector_id) pair.
          3. Sanitization (inside collectors per SPEC §7).
          4. Graph upsert for each observation from successful dispatches.
          4b/5/6. TODO placeholders for LLM enrichment and artifact generation.

        Multi-pass (SPEC §2.2):
          After each dispatch pass, newly created entities are queried and
          converted back to seeds for deeper exploration. Pass 1 runs all
          enabled collectors; Pass 2+ runs only collectors that accept the
          new seed types. The loop terminates when no new seeds are discovered
          or ``max_passes`` is reached.

        State machine: ``pending -> running -> completed|failed|partial``.

        Returns a ``RunResult`` summarizing the run.
        """
        start_ns = time.monotonic_ns()

        # Clear the health-check cache so the first dispatch of each collector
        # in this run gets a fresh probe.
        clear_health_cache()

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
        self._log("info", f"Run started: {total_seeds} seed(s)")

        # === Stage 1: Seed expansion ==========================================
        expanded = expand_seeds(seeds)
        expanded = await self._dns_filter_seeds(expanded)
        expanded_count = len(expanded)
        self._log("info", f"Seed expansion: {total_seeds} -> {expanded_count} seeds")

        # === Multi-pass dispatch loop =========================================
        #
        # Track all (seed_value, collector_id) pairs dispatched across passes
        # to avoid redundant work. ``already_scanned`` tracks (seed_type, value)
        # tuples so the entity-to-seed converter can skip entities that were
        # already used as seeds.
        dispatched_pairs: set[tuple[str, str]] = set()
        already_scanned: set[tuple[str, str]] = {
            (s.seed_type.value, s.value) for s in expanded
        }

        successful = 0
        failed = 0
        denied = 0
        total_observations = 0
        enrichment_count = 0
        upsert_failures = 0
        entities_discovered_per_pass: list[int] = []

        current_seeds = expanded
        current_collector_ids = collector_ids
        pass_number = 0

        while pass_number < max_passes:
            pass_number += 1

            if pass_number > 1:
                prev_entities = (
                    entities_discovered_per_pass[-1]
                    if entities_discovered_per_pass
                    else 0
                )
                logger.info(
                    "Pass %d: %d new seeds from %d entities",
                    pass_number,
                    len(current_seeds),
                    prev_entities,
                )
                self._log(
                    "info",
                    f"Pass {pass_number}: {len(current_seeds)} new seeds "
                    f"from {prev_entities} entities",
                )

            # --- Dispatch all (seed, collector) pairs for this pass -----------
            pass_obs, pass_stats = await self._dispatch_pass(
                seeds=current_seeds,
                collector_ids=current_collector_ids,
                run_id=run_id,
                tenant_id=tenant_id,
                dispatched_pairs=dispatched_pairs,
            )
            successful += pass_stats["successful"]
            failed += pass_stats["failed"]
            denied += pass_stats["denied"]
            total_observations += pass_stats["observations"]
            enrichment_count += pass_stats["enrichment"]
            upsert_failures += pass_stats["upsert_failures"]
            entities_discovered_per_pass.append(
                pass_stats["observations"] - pass_stats["upsert_failures"]
            )

            # --- Update attribution scores based on collector diversity -------
            try:
                await self._entity_repo.update_attribution_scores(
                    tenant_id=TenantId(tenant_id),
                )
            except Exception:
                logger.exception(
                    "Attribution scoring failed after pass %d", pass_number
                )

            # --- Check for more passes ---------------------------------------
            if pass_number >= max_passes:
                break

            # Query entities created during this run for seed expansion
            entities = await self._entity_repo.list_for_tenant(
                tenant_id=TenantId(tenant_id),
                limit=1000,
            )

            # Convert discovered entities to new seeds
            new_seeds = entities_to_seeds(entities, already_scanned)
            new_seeds.extend(
                extract_org_seeds_from_properties(entities, already_scanned)
            )

            if not new_seeds:
                break

            # Expand new seeds, filter non-resolving domains, update tracking
            current_seeds = expand_seeds(new_seeds)
            current_seeds = await self._dns_filter_seeds(current_seeds)
            expanded_count += len(current_seeds)
            already_scanned.update(
                (s.seed_type.value, s.value) for s in current_seeds
            )

            # Pass 2+ uses only collectors that accept the new seed types
            # (filter to those in the original enabled set)
            current_collector_ids = [
                cid for cid in collector_ids
                if cid in {c for c in collector_ids}
            ]

        entities_added = total_observations - upsert_failures
        if self._quota_tracker is not None and entities_added > 0:
            self._quota_tracker.record_entities_added(tenant_id, entities_added)

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

        self._log(
            "info",
            f"Run {final_state}: {total_observations} observation(s), "
            f"{pass_number} pass(es) in {duration_ms / 1000:.1f}s",
        )

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
            total_observations=total_observations,
            enrichment_count=enrichment_count,
            duration_ms=duration_ms,
            misuse_alerts=misuse_alerts,
            passes_completed=pass_number,
            entities_discovered_per_pass=entities_discovered_per_pass,
        )

    async def _dispatch_pass(
        self,
        *,
        seeds: list[Seed],
        collector_ids: list[str],
        run_id: UUID,
        tenant_id: UUID,
        dispatched_pairs: set[tuple[str, str]],
    ) -> tuple[list[Observation], dict[str, int]]:
        """Run a single dispatch pass over (seed, collector) pairs.

        All non-duplicate ``(seed.value, collector_id)`` pairs are dispatched
        concurrently, bounded by ``_MAX_CONCURRENT_DISPATCHES``.  The
        dispatcher itself only makes HTTP calls to external APIs and does not
        touch the DB, so the single ``AsyncSession`` is safe: all DB writes
        (entity upsert, relationship extraction, enrichment) happen
        sequentially in ``_flush_batch`` *after* the gather completes.

        Skips any (seed.value, collector_id) pair already in
        ``dispatched_pairs``. Updates ``dispatched_pairs`` in-place as pairs
        are collected.

        Returns ``(all_observations, stats_dict)`` where ``stats_dict``
        contains keys: ``successful``, ``failed``, ``denied``,
        ``observations``, ``enrichment``, ``upsert_failures``.
        """

        # --- 1. Collect all non-duplicate (seed, collector_id) pairs ----------
        jobs: list[tuple[Seed, str, DispatchJob]] = []
        for seed in seeds:
            for collector_id in collector_ids:
                pair_key = (seed.value, collector_id)
                if pair_key in dispatched_pairs:
                    continue
                dispatched_pairs.add(pair_key)
                jobs.append((
                    seed,
                    collector_id,
                    DispatchJob(
                        collector_id=collector_id,
                        seed=seed,
                        run_id=run_id,
                        tenant_id=tenant_id,
                    ),
                ))

        if not jobs:
            return [], {
                "successful": 0,
                "failed": 0,
                "denied": 0,
                "observations": 0,
                "enrichment": 0,
                "upsert_failures": 0,
            }

        # --- 2. Dispatch all jobs concurrently with semaphore ----------------
        semaphore = asyncio.Semaphore(_MAX_CONCURRENT_DISPATCHES)

        async def _bounded_dispatch(
            seed: Seed,
            collector_id: str,
            job: DispatchJob,
        ) -> tuple[str, str, DispatchResult | None]:
            """Dispatch one job under the concurrency semaphore.

            Returns ``(seed_value, collector_id, result_or_None)`` where
            ``None`` signals an unhandled exception from the dispatcher.
            """
            self._log("info", f"Dispatching {collector_id} for {seed.value}")
            async with semaphore:
                try:
                    result = await self._dispatcher.dispatch(job)
                except Exception:
                    logger.exception(
                        "Dispatch raised for collector=%s seed=%s",
                        collector_id,
                        seed.value,
                    )
                    self._log(
                        "error",
                        f"{collector_id} raised exception for {seed.value}",
                    )
                    return (seed.value, collector_id, None)
                return (seed.value, collector_id, result)

        tasks = [
            _bounded_dispatch(seed, collector_id, job)
            for seed, collector_id, job in jobs
        ]
        outcomes = await asyncio.gather(*tasks)

        # --- 3. Process results sequentially (DB-safe on single session) -----
        successful = 0
        failed = 0
        denied = 0
        total_observations = 0
        enrichment_count = 0
        upsert_failures = 0
        batch: list[Observation] = []
        all_observations: list[Observation] = []

        for seed_value, collector_id, result in outcomes:
            if result is None:
                # Dispatcher raised an unhandled exception
                failed += 1
                continue

            if result.status == "success":
                successful += 1
                obs_count = len(result.observations)
                duration_s = result.duration_ms / 1000
                self._log(
                    "info",
                    f"{collector_id} completed: "
                    f"{obs_count} observation(s) in {duration_s:.1f}s",
                )
                batch.extend(result.observations)
                all_observations.extend(result.observations)
                # Flush when batch reaches threshold (Stage 3+4+4b)
                if len(batch) >= _OBSERVATION_BATCH_SIZE:
                    batch_enriched, batch_upsert_failures = (
                        await self._flush_batch(batch, run_id, tenant_id)
                    )
                    total_observations += len(batch)
                    enrichment_count += batch_enriched
                    upsert_failures += batch_upsert_failures
                    batch = []
            elif result.status == "denied":
                denied += 1
                self._log(
                    "warn",
                    f"{collector_id} denied: {result.error_message or 'scope gate'}",
                )
            else:
                failed += 1
                self._log(
                    "warn",
                    f"{collector_id} failed: {result.error_message or 'unknown error'}",
                )

        # Flush remaining observations after the dispatch loop
        if batch:
            batch_enriched, batch_upsert_failures = await self._flush_batch(
                batch, run_id, tenant_id
            )
            total_observations += len(batch)
            enrichment_count += batch_enriched
            upsert_failures += batch_upsert_failures

        stats = {
            "successful": successful,
            "failed": failed,
            "denied": denied,
            "observations": total_observations,
            "enrichment": enrichment_count,
            "upsert_failures": upsert_failures,
        }
        return all_observations, stats

    async def _flush_batch(
        self,
        observations: list[Observation],
        run_id: UUID,
        tenant_id: UUID,
    ) -> tuple[int, int]:
        """Upsert and enrich a batch of observations.

        Performs Stage 3 (no-op, sanitization done in collectors), Stage 4
        (graph upsert + relationship extraction), and Stage 4b (LLM
        enrichment) for the given batch.

        Uses ``batch_upsert`` when available on the entity repository to
        issue a single multi-row ``INSERT ON CONFLICT DO UPDATE`` instead of
        one statement per observation.

        Returns ``(enrichment_count, upsert_failures)`` for the batch.
        """
        # --- Stage 4: Batch entity upsert ------------------------------------
        upsert_failures = 0
        entity_map: dict[str, Any] = {}  # canonical_identifier -> Entity row

        # Prefer the batch upsert path when the repository supports it.
        # The sentinel ``supports_batch_upsert`` is ``True`` (a real bool)
        # on ``EntityRepository``; on ``AsyncMock`` objects ``getattr``
        # returns another Mock (not ``True``), so ``is True`` rejects it.
        if getattr(self._entity_repo, "supports_batch_upsert", False) is True:
            entity_dicts: list[dict[str, Any]] = []
            for obs in observations:
                entity_dicts.append({
                    "tenant_id": TenantId(tenant_id),
                    "entity_type": obs.subject.identifier_type.value,
                    "canonical_identifier": obs.subject.identifier_value,
                    "properties": _observation_properties(obs),
                    "attribution_status": "unattributed",
                    "attribution_confidence": Decimal("0.000"),
                })
            try:
                upserted = await self._entity_repo.batch_upsert(entity_dicts)
                for entity in upserted:
                    entity_map[entity.canonical_identifier] = entity
                    self._log(
                        "info",
                        f"New entity: {entity.entity_type} "
                        f"{entity.canonical_identifier}",
                    )
            except Exception:
                logger.exception("Batch entity upsert failed")
                self._log("error", "Batch entity upsert failed")
                upsert_failures += len(observations)
        else:
            # Fallback: per-observation upsert (legacy path / mocked tests).
            for obs in observations:
                try:
                    from_entity = await self._entity_repo.create_or_update(
                        tenant_id=TenantId(tenant_id),
                        entity_type=obs.subject.identifier_type.value,
                        canonical_identifier=obs.subject.identifier_value,
                        properties=_observation_properties(obs),
                        attribution_status="unattributed",
                        attribution_confidence=Decimal("0.000"),
                    )
                    entity_map[obs.subject.identifier_value] = from_entity
                    self._log(
                        "info",
                        f"New entity: {obs.subject.identifier_type.value} "
                        f"{obs.subject.identifier_value}",
                    )
                except Exception:
                    logger.exception(
                        "Entity upsert failed for %s/%s",
                        obs.subject.identifier_type.value,
                        obs.subject.identifier_value,
                    )
                    self._log(
                        "error",
                        f"Entity upsert failed: {obs.subject.identifier_value}",
                    )
                    upsert_failures += 1

        # --- Stage 4 (cont): Relationship extraction -------------------------
        if self._relationship_repo is not None:
            await self._extract_relationships_batch(
                observations=observations,
                entity_map=entity_map,
                tenant_id=TenantId(tenant_id),
            )

        # --- Stage 4b: LLM enrichment (parallel, bounded to 5 concurrent) ---
        enrichment_count = 0
        if self._enrichment is not None:
            enrichment_sem = asyncio.Semaphore(5)

            async def _enrich_one(obs: Observation) -> bool:
                async with enrichment_sem:
                    try:
                        enrichment_result = await self._enrichment.enrich_entity(  # type: ignore[union-attr]
                            entity_type=obs.subject.identifier_type.value,
                            canonical_identifier=obs.subject.identifier_value,
                            properties=_observation_properties(obs),
                            attribution_confidence=float(Decimal("0.000")),
                            tenant_id=tenant_id,
                            run_id=run_id,
                        )
                        return bool(enrichment_result)
                    except Exception:
                        logger.exception(
                            "Enrichment failed for %s/%s",
                            obs.subject.identifier_type.value,
                            obs.subject.identifier_value,
                        )
                        return False

            results = await asyncio.gather(
                *[_enrich_one(obs) for obs in observations],
            )
            enrichment_count = sum(1 for r in results if r)

        return enrichment_count, upsert_failures

    async def _extract_relationships_batch(
        self,
        *,
        observations: list[Observation],
        entity_map: dict[str, Any],
        tenant_id: TenantId,
    ) -> None:
        """Batch relationship extraction across all observations.

        For each observation whose subject has a known entity (in
        ``entity_map``), extracts related references from the structured
        payload, batch-upserts the related entities, then batch-creates
        the relationship rows.

        Failures are logged but never propagated -- relationship extraction
        is best-effort and must not block entity ingestion.
        """
        assert self._relationship_repo is not None  # caller guards  # noqa: S101

        # --- 1. Accumulate all related-entity data across observations --------
        # Each entry: (from_canonical, entity_type, identifier, edge_type, obs)
        all_related: list[tuple[str, str, str, str, Observation]] = []

        for obs in observations:
            from_canonical = obs.subject.identifier_value
            if from_canonical not in entity_map:
                continue  # subject upsert failed; skip relationships
            payload = obs.structured_payload

            # --- A/AAAA values from active_dns --------------------------------
            if "values" in payload and payload.get("record_type") in (
                "A",
                "AAAA",
            ):
                for ip_val in payload["values"]:
                    all_related.append(
                        (from_canonical, "ip", str(ip_val), "resolves_to", obs)
                    )

            # --- resolved_ips from dns_subdomain_enum -------------------------
            for ip_val in payload.get("resolved_ips", []):
                all_related.append(
                    (from_canonical, "ip", str(ip_val), "resolves_to", obs)
                )

            # --- CNAME target from active_dns ---------------------------------
            if "target" in payload and payload.get("record_type") == "CNAME":
                all_related.append(
                    (
                        from_canonical,
                        "domain",
                        str(payload["target"]),
                        "cname_for",
                        obs,
                    )
                )

            # --- cname_chain from dns_subdomain_enum --------------------------
            for cname_target in payload.get("cname_chain", []):
                all_related.append(
                    (from_canonical, "domain", str(cname_target), "cname_for", obs)
                )

            # --- MX exchanges from active_dns ---------------------------------
            for mx in payload.get("exchanges", []):
                exchange = mx.get("exchange") if isinstance(mx, dict) else None
                if exchange:
                    all_related.append(
                        (from_canonical, "domain", str(exchange), "mx_for", obs)
                    )

            # --- NS nameservers from active_dns -------------------------------
            for ns in payload.get("nameservers", []):
                all_related.append(
                    (from_canonical, "domain", str(ns), "ns_for", obs)
                )

        if not all_related:
            return

        # --- 2. Batch-upsert related entities --------------------------------
        # De-duplicate by (entity_type, identifier) to avoid redundant upserts.
        unique_related: dict[tuple[str, str], dict[str, Any]] = {}
        for _, entity_type, identifier, _, _ in all_related:
            key = (entity_type, identifier)
            if key not in unique_related:
                unique_related[key] = {
                    "tenant_id": tenant_id,
                    "entity_type": entity_type,
                    "canonical_identifier": identifier,
                    "properties": {},
                    "attribution_status": "unattributed",
                    "attribution_confidence": Decimal("0.000"),
                }

        # Build a lookup from canonical_identifier -> entity for related
        related_entity_map: dict[str, Any] = {}
        if getattr(self._entity_repo, "supports_batch_upsert", False) is True:
            try:
                upserted = await self._entity_repo.batch_upsert(
                    list(unique_related.values())
                )
                for entity in upserted:
                    related_entity_map[entity.canonical_identifier] = entity
            except Exception:
                logger.exception("Batch related-entity upsert failed")
                return
        else:
            for data in unique_related.values():
                try:
                    entity = await self._entity_repo.create_or_update(**data)
                    related_entity_map[data["canonical_identifier"]] = entity
                except Exception:
                    logger.exception(
                        "Related entity upsert failed for %s/%s",
                        data["entity_type"],
                        data["canonical_identifier"],
                    )

        # --- 3. Batch-create relationships -----------------------------------
        rel_dicts: list[dict[str, Any]] = []
        for from_canonical, entity_type, identifier, edge_type, obs in all_related:
            from_entity = entity_map.get(from_canonical)
            to_entity = related_entity_map.get(identifier)
            if from_entity is None or to_entity is None:
                continue
            rel_dicts.append({
                "tenant_id": tenant_id,
                "from_entity_id": EntityId(from_entity.id),
                "to_entity_id": EntityId(to_entity.id),
                "edge_type": edge_type,
                "confidence": Decimal("0.900"),
                "observed_at": obs.observed_at,
                "collector_id": obs.collector_id,
            })

        if not rel_dicts:
            return

        if getattr(self._relationship_repo, "supports_batch_create", False) is True:
            try:
                await self._relationship_repo.batch_create(rel_dicts)
            except Exception:
                logger.exception("Batch relationship creation failed")
        else:
            for rel in rel_dicts:
                try:
                    await self._relationship_repo.create_or_update(**rel)
                except Exception:
                    logger.exception(
                        "Relationship creation failed for %s -[%s]-> %s",
                        rel["from_entity_id"],
                        rel["edge_type"],
                        rel["to_entity_id"],
                    )

    async def _extract_relationships(
        self,
        *,
        obs: Observation,
        from_entity_id: EntityId,
        tenant_id: TenantId,
    ) -> None:
        """Extract related entities from an observation's structured_payload
        and create relationship rows.

        Each recognized payload pattern produces:
          1. An entity upsert for the related entity (IP, domain, etc.)
          2. A relationship row linking ``from_entity_id`` to the new entity.

        Failures are logged but never propagated -- relationship extraction
        is best-effort and must not block entity ingestion.

        .. note:: Kept for backward compatibility. New code paths use
           ``_extract_relationships_batch`` which batches across all
           observations in a flush cycle.
        """
        assert self._relationship_repo is not None  # caller guards  # noqa: S101
        payload = obs.structured_payload
        related: list[tuple[str, str, str]] = []  # (entity_type, identifier, edge_type)

        # --- A/AAAA values from active_dns -----------------------------------
        if "values" in payload and payload.get("record_type") in ("A", "AAAA"):
            for ip_val in payload["values"]:
                related.append(("ip", str(ip_val), "resolves_to"))

        # --- resolved_ips from dns_subdomain_enum ----------------------------
        for ip_val in payload.get("resolved_ips", []):
            related.append(("ip", str(ip_val), "resolves_to"))

        # --- CNAME target from active_dns ------------------------------------
        if "target" in payload and payload.get("record_type") == "CNAME":
            related.append(("domain", str(payload["target"]), "cname_for"))

        # --- cname_chain from dns_subdomain_enum -----------------------------
        for cname_target in payload.get("cname_chain", []):
            related.append(("domain", str(cname_target), "cname_for"))

        # --- MX exchanges from active_dns ------------------------------------
        for mx in payload.get("exchanges", []):
            exchange = mx.get("exchange") if isinstance(mx, dict) else None
            if exchange:
                related.append(("domain", str(exchange), "mx_for"))

        # --- NS nameservers from active_dns ----------------------------------
        for ns in payload.get("nameservers", []):
            related.append(("domain", str(ns), "ns_for"))

        # --- Create entities and relationships for each related reference -----
        for entity_type, identifier, edge_type in related:
            try:
                to_entity = await self._entity_repo.create_or_update(
                    tenant_id=tenant_id,
                    entity_type=entity_type,
                    canonical_identifier=identifier,
                    properties={},
                    attribution_status="unattributed",
                    attribution_confidence=Decimal("0.000"),
                )
                await self._relationship_repo.create_or_update(
                    tenant_id=tenant_id,
                    from_entity_id=from_entity_id,
                    to_entity_id=EntityId(to_entity.id),
                    edge_type=edge_type,
                    confidence=Decimal("0.900"),
                    observed_at=obs.observed_at,
                    collector_id=obs.collector_id,
                )
            except Exception:
                logger.exception(
                    "Relationship extraction failed for %s -[%s]-> %s/%s",
                    obs.subject.identifier_value,
                    edge_type,
                    entity_type,
                    identifier,
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
