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
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from expose.collectors.base import Observation, ObservationType, Seed
from expose.compliance.misuse_detection import MisuseAlert, MisuseDetector
from expose.pipeline.collector_filter import filter_collectors
from expose.pipeline.dispatcher import clear_health_cache
from expose.pipeline.enrichment import EnrichmentPipeline
from expose.pipeline.supply_chain import detect_providers
from expose.pipeline.takeover_detection import TakeoverRisk, detect_takeover_risks
from expose.pipeline.entity_seed_converter import (
    entities_to_seeds,
    extract_org_seeds_from_properties,
)
from expose.pipeline.ma_expansion import expand_ma_seeds
from expose.pipeline.seed_expansion import expand_seeds
from expose.pipeline.target_profile import build_target_profile
from expose.quotas.tracker import QuotaExceededError, QuotaTracker
from expose.repositories.entity_repo import EntityRepository
from expose.repositories.relationship_repo import RelationshipRepository
from expose.repositories.run_repo import RunRepository
from expose.observability.metrics import pipeline_errors_total
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

# Maximum number of unique entities to LLM-enrich per flush batch.  When a
# batch contains more unique entities than this cap, only the first N are
# enriched, prioritised by entity type (domains first, then IPs, then
# everything else).  This prevents a single subdomain-enumeration batch from
# burning 200+ LLM calls.
_MAX_LLM_ENRICHMENTS_PER_BATCH = 50

# Priority ordering for entity-type enrichment selection.  Lower index =
# higher priority.  Types not listed sort last.
_ENRICHMENT_TYPE_PRIORITY: dict[str, int] = {
    "domain": 0,
    "subdomain": 1,
    "ip": 2,
    "cidr": 3,
    "cloud_resource": 4,
}


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
    skipped_dispatches: int = 0
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
        event_bus: Any | None = None,
        rule_pack: Any | None = None,
        scope_context: Any | None = None,
    ) -> None:
        self._dispatcher = dispatcher
        self._run_repo = run_repo
        self._entity_repo = entity_repo
        self._relationship_repo = relationship_repo
        self._quota_tracker = quota_tracker
        self._misuse_detector = misuse_detector
        self._enrichment = enrichment_pipeline
        self._log_sink = log_sink
        self._event_bus = event_bus
        self._rule_pack = rule_pack
        self._scope_context = scope_context
        self._dns_executor: ThreadPoolExecutor | None = None

    def _log(self, level: str, msg: str) -> None:
        """Emit a structured log entry to the log sink, if configured."""
        if self._log_sink is not None:
            self._log_sink(level, msg)

    async def _publish(
        self,
        event_type: str,
        run_id: UUID,
        tenant_id: UUID,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Publish a lifecycle event to the event bus, if configured.

        No-ops silently when ``event_bus`` is ``None``.  Any exception from
        the bus is caught and logged at DEBUG level so event publishing never
        breaks the pipeline run.
        """
        if self._event_bus is not None:
            try:
                from expose.api.events import RunEvent, RunEventType  # noqa: PLC0415

                await self._event_bus.publish(
                    RunEvent(
                        event_type=RunEventType(event_type),
                        run_id=run_id,
                        tenant_id=tenant_id,
                        timestamp=datetime.now(UTC),
                        data=data or {},
                    )
                )
            except Exception as exc:
                logger.debug("Failed to publish event %s", event_type)
                pipeline_errors_total.add(1, {"component": "executor", "error_type": type(exc).__name__})

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
            """Return the seed if it resolves to a non-private IP, None otherwise."""
            try:
                result = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        self._dns_executor,
                        socket.getaddrinfo,
                        seed.value,
                        None,
                        socket.AF_UNSPEC,
                        socket.SOCK_STREAM,
                    ),
                    timeout=3.0,
                )
                if result:
                    # SSRF check: reject domains that resolve to private IPs
                    from expose.egress.ip_guard import is_private_ip

                    for entry in result:
                        if is_private_ip(entry[4][0]):
                            self._log(
                                "warn",
                                f"SSRF blocked: {seed.value} resolves to "
                                f"private IP {entry[4][0]}",
                            )
                            return None
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

    async def execute(
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

        # Dedicated thread pool for DNS lookups so they don't exhaust the
        # default asyncio executor (issue #155).  Created per-run and shut
        # down in the finally block to prevent thread leaks.
        self._dns_executor = ThreadPoolExecutor(
            max_workers=8,
            thread_name_prefix="expose-dns",
        )

        try:
            return await self._execute_inner(
                run_id=run_id,
                tenant_id=tenant_id,
                seeds=seeds,
                collector_ids=collector_ids,
                max_passes=max_passes,
                start_ns=start_ns,
            )
        finally:
            self._dns_executor.shutdown(wait=False)
            self._dns_executor = None

    async def _execute_inner(  # noqa: PLR0912, PLR0915
        self,
        *,
        run_id: UUID,
        tenant_id: UUID,
        seeds: list[Seed],
        collector_ids: list[str],
        max_passes: int,
        start_ns: int,
    ) -> RunResult:
        """Inner execution body, separated so execute() can wrap with try/finally."""

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

        await self._publish("run_started", run_id, tenant_id)

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
                    skipped_dispatches=0,
                    total_observations=0,
                    duration_ms=duration_ms,
                )
            self._quota_tracker.record_run_start(tenant_id)

        # Build a frozen set of seed identifier values so _flush_batch can
        # tag seed entities as "confirmed" attribution (SPEC §6.3).
        self._seed_values: frozenset[str] = frozenset(s.value for s in seeds)

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
        skipped = 0
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
            skipped += pass_stats["skipped"]
            total_observations += pass_stats["observations"]
            enrichment_count += pass_stats["enrichment"]
            upsert_failures += pass_stats["upsert_failures"]
            entities_discovered_per_pass.append(
                pass_stats["observations"] - pass_stats["upsert_failures"]
            )

            await self._publish(
                "entities_discovered",
                run_id,
                tenant_id,
                data={
                    "pass_number": pass_number,
                    "entity_count": entities_discovered_per_pass[-1],
                },
            )

            # --- Update attribution scores based on collector diversity -------
            try:
                await self._entity_repo.update_attribution_scores(
                    tenant_id=TenantId(tenant_id),
                )
            except Exception as exc:
                logger.exception(
                    "Attribution scoring failed after pass %d", pass_number
                )
                pipeline_errors_total.add(1, {"component": "executor", "error_type": type(exc).__name__})

            # --- Stage 4a: Rule-based attribution evaluation -----------------
            try:
                from expose.pipeline.rule_evaluator import RuleEvaluator

                if hasattr(self, "_rule_pack") and self._rule_pack is not None:
                    rule_evaluator = RuleEvaluator(
                        rule_pack=self._rule_pack,
                        scope_context=getattr(self, "_scope_context", None),
                    )
                    # Early-exit: skip entirely if the rule pack has no
                    # enabled rules (avoids a DB query + O(N*M) loop).
                    enabled_rules = [
                        r
                        for r in self._rule_pack.attribution_rules
                        if r.enabled
                    ]
                    if enabled_rules:
                        eval_entities = await self._entity_repo.list_for_tenant(
                            tenant_id=TenantId(tenant_id),
                            limit=1000,
                        )
                        for entity in eval_entities:
                            entity_data = {
                                "entity_type": entity.entity_type,
                                "canonical_identifier": entity.canonical_identifier,
                                "properties": entity.properties or {},
                                "attribution_status": entity.attribution_status,
                                "attribution_confidence": float(
                                    entity.attribution_confidence
                                ),
                            }
                            eval_result = rule_evaluator.evaluate(entity_data)
                            if eval_result.matched_rules:
                                await self._entity_repo.create_or_update(
                                    tenant_id=TenantId(tenant_id),
                                    entity_type=entity.entity_type,
                                    canonical_identifier=entity.canonical_identifier,
                                    properties=entity.properties or {},
                                    attribution_status=eval_result.attribution_tier,
                                    attribution_confidence=Decimal(
                                        str(round(eval_result.final_confidence, 3))
                                    ),
                                )
                                self._log(
                                    "info",
                                    f"Rule evaluation: {entity.canonical_identifier} "
                                    f"-> {eval_result.attribution_tier} "
                                    f"({eval_result.final_confidence:.3f}), "
                                    f"rules={eval_result.matched_rules}",
                                )
            except Exception as exc:
                logger.exception(
                    "Rule evaluation failed after pass %d", pass_number
                )
                pipeline_errors_total.add(1, {"component": "rule_evaluator", "error_type": type(exc).__name__})

            # --- Check for more passes ---------------------------------------
            if pass_number >= max_passes:
                break

            # Query entities created during this run — reused for supply
            # chain inference, target profiling, and multi-pass seed expansion.
            entities = await self._entity_repo.list_for_tenant(
                tenant_id=TenantId(tenant_id),
                limit=1000,
            )

            # --- Supply chain inference ----------------------------------------
            # Scan entities for provider fingerprints and create provider
            # entities + depends_on relationships.
            try:
                await self._apply_supply_chain_detections(
                    entities=entities,
                    tenant_id=tenant_id,
                    pass_number=pass_number,
                )
            except Exception as exc:
                logger.exception(
                    "Supply chain inference failed after pass %d", pass_number
                )
                pipeline_errors_total.add(1, {"component": "supply_chain", "error_type": type(exc).__name__})

            # --- Subdomain takeover detection -----------------------------------
            # After supply chain inference, check for dangling CNAME records
            # pointing to takeover-vulnerable services (issue #95).
            try:
                await self._apply_takeover_detections(
                    entities=entities,
                    tenant_id=tenant_id,
                    pass_number=pass_number,
                )
            except Exception as exc:
                logger.exception(
                    "Takeover detection failed after pass %d", pass_number
                )
                pipeline_errors_total.add(1, {"component": "takeover_detection", "error_type": type(exc).__name__})

            # --- Target profiling & collector filtering (after Pass 1) ---
            # Build a profile of the target's infrastructure from Pass 1
            # discoveries, then filter collectors for Pass 2+ based on
            # signal-to-action rules.
            if pass_number == 1 and entities:
                try:
                    target_profile = build_target_profile(entities)
                    filter_result = filter_collectors(
                        target_profile, collector_ids,
                    )
                    collector_ids = filter_result.filtered_collector_ids
                    self._log(
                        "info",
                        f"Target profile: infra={target_profile.infrastructure_type}, "
                        f"email={target_profile.email_provider}, "
                        f"cdn={target_profile.cdn_provider}, "
                        f"voip={target_profile.has_voip}, "
                        f"certs={target_profile.cert_count}",
                    )
                    if filter_result.signals_active:
                        self._log(
                            "info",
                            f"Active signals: {filter_result.signals_active}; "
                            f"{len(filter_result.decisions)} filter decisions applied",
                        )
                except Exception as exc:
                    logger.exception(
                        "Target profiling/collector filtering failed after pass 1"
                    )
                    pipeline_errors_total.add(1, {"component": "executor", "error_type": type(exc).__name__})

            # Convert discovered entities to new seeds
            new_seeds = entities_to_seeds(entities, already_scanned)
            new_seeds.extend(
                extract_org_seeds_from_properties(entities, already_scanned)
            )

            # --- M&A seed expansion -------------------------------------------
            # Convert M&A observations into domain/organization seeds for
            # acquired companies so subsequent passes explore their attack
            # surface.
            ma_seeds = expand_ma_seeds(pass_obs)
            for ms in ma_seeds:
                key = (ms.seed_type.value, ms.value)
                if key not in already_scanned:
                    new_seeds.append(ms)

            if not new_seeds:
                break

            # Expand new seeds, filter non-resolving domains, update tracking
            current_seeds = expand_seeds(new_seeds)
            current_seeds = await self._dns_filter_seeds(current_seeds)
            expanded_count += len(current_seeds)
            already_scanned.update(
                (s.seed_type.value, s.value) for s in current_seeds
            )

            # Pass 2+ uses the (possibly filtered) collector set
            current_collector_ids = list(collector_ids)

        entities_added = total_observations - upsert_failures
        if self._quota_tracker is not None and entities_added > 0:
            self._quota_tracker.record_entities_added(tenant_id, entities_added)

        # TODO(stage-5): Artifact generation — out of scope for Sprint 3-4
        # When implemented, this stage will serialize the observation graph
        # into the canonical artifact format (schemas/canonical-artifact-v1.json),
        # compute content-addressed hashes per ADR-004, and upload to object
        # storage. See SPEC §2.2 Stage 6 and the manifest schema.

        # === Determine final state ============================================
        # Skipped dispatches (missing credentials, health-check failures) are
        # configuration gaps, not collector bugs.  They must NOT inflate the
        # failure count.  Only true collector errors (COLLECTOR_ERROR status or
        # unhandled dispatcher exceptions) count as failures for state
        # determination.
        #
        # State rules:
        #   - Zero dispatches OR all successes (no real failures) -> completed
        #   - Some successes + some real failures               -> partial
        #   - Zero successes (all failed / denied / skipped)    -> failed
        total_dispatches = successful + failed + denied + skipped
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

        await self._publish(
            "run_completed",
            run_id,
            tenant_id,
            data={"final_state": final_state},
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
            skipped_dispatches=skipped,
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
                "skipped": 0,
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
            await self._publish(
                "collector_started",
                run_id,
                tenant_id,
                data={"collector_id": collector_id, "seed_value": seed.value},
            )
            async with semaphore:
                try:
                    _dispatch_start = time.monotonic_ns()
                    result = await asyncio.wait_for(
                        self._dispatcher.dispatch(job),
                        timeout=120.0,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "Dispatch timed out after 120s for %s on %s",
                        collector_id,
                        seed.value,
                    )
                    self._log(
                        "warn",
                        f"{collector_id} dispatch timed out after 120s",
                    )
                    await self._publish(
                        "collector_failed",
                        run_id,
                        tenant_id,
                        data={"collector_id": collector_id, "error": "timeout after 120s"},
                    )
                    return (seed.value, collector_id, None)
                except Exception as e:
                    logger.warning(
                        "Dispatch exception for %s on %s",
                        collector_id,
                        seed.value,
                        exc_info=True,
                    )
                    self._log(
                        "warn",
                        f"{collector_id} dispatch exception: {type(e).__name__}",
                    )
                    await self._publish(
                        "collector_failed",
                        run_id,
                        tenant_id,
                        data={"collector_id": collector_id, "error": str(type(e).__name__)},
                    )
                    return (seed.value, collector_id, None)

                # Publish collector_completed or collector_failed based on result
                if result.status == "success":
                    await self._publish(
                        "collector_completed",
                        run_id,
                        tenant_id,
                        data={
                            "collector_id": collector_id,
                            "observation_count": len(result.observations),
                            "duration_ms": result.duration_ms,
                        },
                    )
                elif result.status in ("skipped", "health_check_failed", "denied"):
                    # Not a failure per se — skip event publishing for these
                    pass
                else:
                    await self._publish(
                        "collector_failed",
                        run_id,
                        tenant_id,
                        data={
                            "collector_id": collector_id,
                            "error": result.error_message or "unknown",
                        },
                    )

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
        skipped = 0
        total_observations = 0
        enrichment_count = 0
        upsert_failures = 0
        batch: list[Observation] = []
        all_observations: list[Observation] = []

        # Statuses that represent "could not run due to missing config or
        # unavailable data source" — distinct from a collector bug.
        _SKIP_STATUSES = frozenset({"skipped", "health_check_failed"})

        for seed_value, collector_id, result in outcomes:
            if result is None:
                # Dispatcher raised an unhandled exception — a real failure
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
            elif result.status in _SKIP_STATUSES:
                skipped += 1
                self._log(
                    "warn",
                    f"{collector_id} skipped: {result.error_message or 'unavailable'}",
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
            "skipped": skipped,
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
        use_batch = getattr(self._entity_repo, "supports_batch_upsert", False) is True
        batch_succeeded = False

        if use_batch:
            entity_dicts: list[dict[str, Any]] = []
            for obs in observations:
                is_seed = obs.subject.identifier_value in self._seed_values
                entity_dicts.append({
                    "tenant_id": TenantId(tenant_id),
                    "entity_type": obs.subject.identifier_type.value,
                    "canonical_identifier": obs.subject.identifier_value,
                    "properties": _observation_properties(obs),
                    "attribution_status": "confirmed" if is_seed else "unattributed",
                    "attribution_confidence": Decimal("1.000") if is_seed else Decimal("0.000"),
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
                batch_succeeded = True
            except Exception as exc:
                logger.exception(
                    "Batch entity upsert failed; falling back to per-entity upserts"
                )
                pipeline_errors_total.add(1, {"component": "executor", "error_type": type(exc).__name__})
                self._log(
                    "warn",
                    "Batch entity upsert failed — falling back to per-entity upserts",
                )

        if not use_batch or not batch_succeeded:
            # Fallback: per-observation upsert (legacy path / mocked tests /
            # batch failure recovery).
            for obs in observations:
                try:
                    is_seed = obs.subject.identifier_value in self._seed_values
                    from_entity = await self._entity_repo.create_or_update(
                        tenant_id=TenantId(tenant_id),
                        entity_type=obs.subject.identifier_type.value,
                        canonical_identifier=obs.subject.identifier_value,
                        properties=_observation_properties(obs),
                        attribution_status="confirmed" if is_seed else "unattributed",
                        attribution_confidence=Decimal("1.000") if is_seed else Decimal("0.000"),
                    )
                    entity_map[obs.subject.identifier_value] = from_entity
                    self._log(
                        "info",
                        f"New entity: {obs.subject.identifier_type.value} "
                        f"{obs.subject.identifier_value}",
                    )
                except Exception as exc:
                    logger.exception(
                        "Entity upsert failed for %s/%s",
                        obs.subject.identifier_type.value,
                        obs.subject.identifier_value,
                    )
                    pipeline_errors_total.add(1, {"component": "executor", "error_type": type(exc).__name__})
                    self._log(
                        "error",
                        f"Entity upsert failed: {obs.subject.identifier_value}",
                    )
                    upsert_failures += 1

        # --- Lead scoring (post-upsert, pre-relationship) -------------------
        if entity_map:
            from expose.pipeline.lead_scoring import LeadScoringEngine  # noqa: PLC0415
            from expose.pipeline.environment_classifier import (  # noqa: PLC0415
                EnvironmentClassification,
                EnvironmentClassifier,
            )

            # Pre-build O(M) lookup to avoid O(N*M) scan per entity
            obs_by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for o in observations:
                obs_by_entity[o.subject.identifier_value].append(
                    _observation_properties(o)
                )

            scorer = LeadScoringEngine()
            env_classifier = EnvironmentClassifier()
            for canonical_id, entity in entity_map.items():
                try:
                    obs_for_entity = obs_by_entity.get(canonical_id, [])
                    old_score = (entity.properties or {}).get("_lead_score")

                    # --- Extract structured data from observations for full signal wiring ---
                    scoring_kwargs: dict[str, Any] = {
                        "entity_identifier": canonical_id,
                        "observations": obs_for_entity,
                    }

                    # WAF detection: look for waf-detection collector observations
                    for obs_dict in obs_for_entity:
                        if obs_dict.get("_collector_id") == "waf-detection":
                            scoring_kwargs["waf_detected"] = obs_dict.get("waf_detected", False)
                            break

                    # DNSBL listings: collect dns-blacklist observations
                    dnsbl_obs = [
                        obs_dict for obs_dict in obs_for_entity
                        if obs_dict.get("_collector_id") == "dns-blacklist"
                    ]
                    if dnsbl_obs:
                        scoring_kwargs["dnsbl_listings"] = dnsbl_obs

                    # Environment classification from observations
                    try:
                        env_result = env_classifier.classify(
                            entity_identifier=canonical_id,
                            observations=obs_for_entity,
                        )
                        scoring_kwargs["environment"] = env_result
                    except Exception:
                        pass  # Non-critical — proceed without environment data

                    # M&A transitive: check for ma-discovery collector
                    for obs_dict in obs_for_entity:
                        if obs_dict.get("_collector_id") == "ma-discovery":
                            scoring_kwargs["is_transitive_ma"] = True
                            break

                    score_result = scorer.score_entity(**scoring_kwargs)
                    updated_props = dict(entity.properties or {})
                    updated_props["_lead_score"] = score_result.score
                    updated_props["_priority_tier"] = score_result.priority_tier.value
                    await self._entity_repo.create_or_update(
                        tenant_id=TenantId(tenant_id),
                        entity_type=entity.entity_type,
                        canonical_identifier=canonical_id,
                        properties=updated_props,
                        attribution_status=entity.attribution_status,
                        attribution_confidence=entity.attribution_confidence,
                    )

                    # Publish attribution_updated event when score changes
                    if old_score is not None and old_score != score_result.score:
                        await self._publish(
                            "attribution_updated",
                            run_id,
                            tenant_id,
                            data={
                                "entity_id": canonical_id,
                                "old_score": old_score,
                                "new_score": score_result.score,
                                "priority_tier": score_result.priority_tier.value,
                            },
                        )
                except Exception as exc:
                    logger.exception("Lead scoring failed for %s", canonical_id)
                    pipeline_errors_total.add(1, {"component": "lead_scoring", "error_type": type(exc).__name__})

            # --- Temporal analysis (post-lead-scoring) -------------------------
            # Detect progression patterns from historical observations.
            try:
                from expose.pipeline.temporal_analysis import TemporalAnalyzer  # noqa: PLC0415

                analyzer = TemporalAnalyzer()
                for canonical_id, entity in entity_map.items():
                    obs_for_entity = obs_by_entity.get(canonical_id, [])
                    if len(obs_for_entity) >= 2:  # Need at least 2 snapshots
                        try:
                            result = analyzer.analyze(canonical_id, obs_for_entity)
                            if result.patterns:
                                updated_props = dict(entity.properties or {})
                                updated_props["_temporal_patterns"] = [
                                    {
                                        "type": p.pattern_type,
                                        "severity": p.severity,
                                        "description": p.description,
                                    }
                                    for p in result.patterns
                                ]
                                updated_props["_temporal_score_delta"] = (
                                    result.temporal_score_delta
                                )
                                # Add temporal delta to lead score
                                current_score = updated_props.get("_lead_score", 0)
                                updated_props["_lead_score"] = min(
                                    100, current_score + result.temporal_score_delta
                                )
                                await self._entity_repo.create_or_update(
                                    tenant_id=TenantId(tenant_id),
                                    entity_type=entity.entity_type,
                                    canonical_identifier=canonical_id,
                                    properties=updated_props,
                                    attribution_status=entity.attribution_status,
                                    attribution_confidence=entity.attribution_confidence,
                                )
                        except Exception as exc:
                            logger.exception(
                                "Temporal analysis failed for %s", canonical_id
                            )
                            pipeline_errors_total.add(1, {"component": "temporal_analysis", "error_type": type(exc).__name__})
            except Exception as exc:
                logger.exception("Temporal analysis setup failed")
                pipeline_errors_total.add(1, {"component": "temporal_analysis", "error_type": type(exc).__name__})

        # --- Stage 4 (cont): Relationship extraction -------------------------
        if self._relationship_repo is not None:
            await self._extract_relationships_batch(
                observations=observations,
                entity_map=entity_map,
                tenant_id=TenantId(tenant_id),
            )

        # --- Stage 4b: LLM enrichment (deduplicated, capped, parallel) ------
        #
        # Many observations may reference the same entity (e.g., 391 dns-chaos
        # subdomains producing 391 observations but only ~200 unique entities).
        # Deduplicate by (entity_type, canonical_identifier) before enriching
        # to avoid redundant LLM calls.  A configurable cap
        # (_MAX_LLM_ENRICHMENTS_PER_BATCH) further limits spend; entities are
        # prioritised by type (domains first, then IPs, then others).
        enrichment_count = 0
        if self._enrichment is not None:
            # --- Deduplicate: collect first observation per unique entity -----
            seen_entities: dict[tuple[str, str], Observation] = {}
            for obs in observations:
                key = (
                    obs.subject.identifier_type.value,
                    obs.subject.identifier_value,
                )
                if key not in seen_entities:
                    seen_entities[key] = obs

            unique_obs = list(seen_entities.values())

            if len(unique_obs) < len(observations):
                self._log(
                    "info",
                    f"Enrichment dedup: {len(observations)} observations -> "
                    f"{len(unique_obs)} unique entities",
                )

            # --- Cap + prioritise by entity type -----------------------------
            if len(unique_obs) > _MAX_LLM_ENRICHMENTS_PER_BATCH:
                def _type_priority(obs: Observation) -> int:
                    return _ENRICHMENT_TYPE_PRIORITY.get(
                        obs.subject.identifier_type.value, 999
                    )

                unique_obs.sort(key=_type_priority)
                skipped = len(unique_obs) - _MAX_LLM_ENRICHMENTS_PER_BATCH
                unique_obs = unique_obs[:_MAX_LLM_ENRICHMENTS_PER_BATCH]
                self._log(
                    "info",
                    f"Enrichment cap: enriching {_MAX_LLM_ENRICHMENTS_PER_BATCH} "
                    f"of {_MAX_LLM_ENRICHMENTS_PER_BATCH + skipped} unique "
                    f"entities ({skipped} deferred)",
                )

            # --- Parallel enrichment with bounded concurrency ----------------
            enrichment_sem = asyncio.Semaphore(5)

            async def _enrich_one(obs: Observation) -> bool:
                async with enrichment_sem:
                    try:
                        enrichment_result = await asyncio.wait_for(
                            self._enrichment.enrich_entity(  # type: ignore[union-attr]
                                entity_type=obs.subject.identifier_type.value,
                                canonical_identifier=obs.subject.identifier_value,
                                properties=_observation_properties(obs),
                                attribution_confidence=float(Decimal("0.000")),
                                tenant_id=tenant_id,
                                run_id=run_id,
                            ),
                            timeout=60.0,
                        )
                        return bool(enrichment_result)
                    except asyncio.TimeoutError:
                        logger.warning(
                            "Enrichment timed out after 60s for %s/%s",
                            obs.subject.identifier_type.value,
                            obs.subject.identifier_value,
                        )
                        return False
                    except Exception as exc:
                        logger.exception(
                            "Enrichment failed for %s/%s",
                            obs.subject.identifier_type.value,
                            obs.subject.identifier_value,
                        )
                        pipeline_errors_total.add(1, {"component": "enrichment", "error_type": type(exc).__name__})
                        return False

            results = await asyncio.gather(
                *[_enrich_one(obs) for obs in unique_obs],
            )
            enrichment_count = sum(1 for r in results if r)

        # --- Stage 4c: Vision analysis (screenshot classification) ------
        #
        # When the enrichment pipeline is available (implying an LLM client),
        # collect HTTP_RESPONSE observations that carry HTML evidence blobs
        # (from the screenshot-vision collector) and run them through the
        # VisionAnalyzer for page-type classification, technology detection,
        # and security-indicator extraction.  Results are stored as entity
        # properties prefixed with ``_vision_``.
        #
        # Opt-in: skipped entirely when no enrichment pipeline (no LLM client).
        # Capped at 10 observations per batch to limit LLM spend.
        if self._enrichment is not None:
            try:
                from expose.pipeline.vision import VisionAnalyzer  # noqa: PLC0415

                # Build a VisionAnalyzer using the same LLM client that
                # the enrichment pipeline uses.
                llm_client = getattr(self._enrichment, "_client", None)
                if llm_client is not None:
                    vision = VisionAnalyzer(llm_client=llm_client)
                    _MAX_VISION_PER_BATCH = 10  # noqa: N806

                    # Collect screenshot-eligible observations: HTTP_RESPONSE
                    # observations with HTML evidence blobs.
                    screenshot_obs = [
                        obs for obs in observations
                        if (
                            obs.observation_type == ObservationType.HTTP_RESPONSE
                            and obs.evidence_blob is not None
                            and obs.evidence_blob_content_type == "text/html"
                        )
                    ][:_MAX_VISION_PER_BATCH]

                    for obs in screenshot_obs:
                        try:
                            banner_text = (
                                obs.evidence_blob.decode("utf-8", errors="replace")
                                if obs.evidence_blob
                                else None
                            )
                            url = obs.structured_payload.get(
                                "url", obs.subject.identifier_value
                            )
                            analysis = await vision.analyze_screenshot(
                                banner_text=banner_text,
                                url=url,
                                headers=obs.structured_payload.get("headers"),
                                tenant_id=tenant_id,
                                run_id=run_id,
                            )
                            if analysis is not None:
                                entity = entity_map.get(
                                    obs.subject.identifier_value
                                )
                                if entity is not None:
                                    updated_props = dict(entity.properties or {})
                                    updated_props["_vision_page_type"] = (
                                        analysis.page_type
                                    )
                                    updated_props["_vision_technologies"] = (
                                        analysis.technologies_detected
                                    )
                                    updated_props["_vision_indicators"] = [
                                        {
                                            "type": ind.indicator_type,
                                            "detail": ind.detail,
                                            "severity": ind.severity,
                                        }
                                        for ind in analysis.security_indicators
                                    ]
                                    updated_props["_vision_confidence"] = (
                                        analysis.visual_confidence
                                    )
                                    await self._entity_repo.create_or_update(
                                        tenant_id=TenantId(tenant_id),
                                        entity_type=entity.entity_type,
                                        canonical_identifier=(
                                            entity.canonical_identifier
                                        ),
                                        properties=updated_props,
                                        attribution_status=(
                                            entity.attribution_status
                                        ),
                                        attribution_confidence=(
                                            entity.attribution_confidence
                                        ),
                                    )
                                    self._log(
                                        "info",
                                        f"Vision: {entity.canonical_identifier} "
                                        f"classified as {analysis.page_type} "
                                        f"({analysis.visual_confidence:.2f})",
                                    )
                        except Exception as exc:
                            logger.exception(
                                "Vision analysis failed for %s",
                                obs.subject.identifier_value,
                            )
                            pipeline_errors_total.add(1, {"component": "enrichment", "error_type": type(exc).__name__})
            except Exception as exc:
                logger.exception("Stage 4c vision analysis setup failed")
                pipeline_errors_total.add(1, {"component": "enrichment", "error_type": type(exc).__name__})

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

            # --- M&A acquired_by from ma-discovery ----------------------------
            if (
                payload.get("_collector_id") == "ma-discovery"
                and payload.get("relationship_type") == "acquired_by"
            ):
                parent_org = payload.get("parent_organization")
                acquired_org = payload.get("acquired_organization")
                if parent_org and acquired_org:
                    all_related.append(
                        (parent_org, "organization", acquired_org, "acquired_by", obs)
                    )
                for acq_domain in payload.get("acquired_domains", []):
                    if acq_domain and parent_org:
                        all_related.append(
                            (parent_org, "domain", str(acq_domain), "acquired_by", obs)
                        )

            # --- TLS certificate SAN -> certificate_for ----------------------
            if payload.get("_collector_id") in (
                "active-tls-handshake",
                "ct-crtsh",
                "ct-censys",
                "ct-certspotter",
            ):
                for san in payload.get("cert_sans", []):
                    all_related.append(
                        (from_canonical, "domain", str(san), "certificate_for", obs)
                    )

            # --- IP resolution -> hosts --------------------------------------
            if (
                payload.get("_collector_id") == "active-dns"
                and payload.get("record_type") in ("A", "AAAA")
            ):
                for ip_val in payload.get("values", []):
                    all_related.append(
                        (from_canonical, "ip", str(ip_val), "hosts", obs)
                    )

            # --- Organization hierarchy -> belongs_to ------------------------
            if payload.get("_collector_id") == "rdap-whois":
                org_name = payload.get("registrant_organization")
                if org_name:
                    all_related.append(
                        (from_canonical, "organization", str(org_name), "belongs_to", obs)
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
            except Exception as exc:
                logger.exception("Batch related-entity upsert failed")
                pipeline_errors_total.add(1, {"component": "relationship_extraction", "error_type": type(exc).__name__})
                return
        else:
            for data in unique_related.values():
                try:
                    entity = await self._entity_repo.create_or_update(**data)
                    related_entity_map[data["canonical_identifier"]] = entity
                except Exception as exc:
                    logger.exception(
                        "Related entity upsert failed for %s/%s",
                        data["entity_type"],
                        data["canonical_identifier"],
                    )
                    pipeline_errors_total.add(1, {"component": "relationship_extraction", "error_type": type(exc).__name__})

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
            except Exception as exc:
                logger.exception("Batch relationship creation failed")
                pipeline_errors_total.add(1, {"component": "relationship_extraction", "error_type": type(exc).__name__})
                try:
                    await self._relationship_repo._session.rollback()
                except Exception:
                    pass
        else:
            for rel in rel_dicts:
                try:
                    await self._relationship_repo.create_or_update(**rel)
                except Exception as exc:
                    logger.exception(
                        "Relationship creation failed for %s -[%s]-> %s",
                        rel["from_entity_id"],
                        rel["edge_type"],
                        rel["to_entity_id"],
                    )
                    pipeline_errors_total.add(1, {"component": "relationship_extraction", "error_type": type(exc).__name__})

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

        # --- M&A acquired_by from ma-discovery -------------------------------
        if (
            payload.get("_collector_id") == "ma-discovery"
            and payload.get("relationship_type") == "acquired_by"
        ):
            parent_org = payload.get("parent_organization")
            acquired_org = payload.get("acquired_organization")
            if parent_org and acquired_org:
                related.append(("organization", acquired_org, "acquired_by"))
            for acq_domain in payload.get("acquired_domains", []):
                if acq_domain:
                    related.append(("domain", str(acq_domain), "acquired_by"))

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
            except Exception as exc:
                logger.exception(
                    "Relationship extraction failed for %s -[%s]-> %s/%s",
                    obs.subject.identifier_value,
                    edge_type,
                    entity_type,
                    identifier,
                )
                pipeline_errors_total.add(1, {"component": "relationship_extraction", "error_type": type(exc).__name__})

    async def _apply_supply_chain_detections(
        self,
        *,
        entities: Any,
        tenant_id: UUID,
        pass_number: int,
    ) -> None:
        """Run supply chain inference and persist provider entities + edges.

        For each ``ProviderDetection`` returned by ``detect_providers``:
        1. Create/update a ``provider`` entity with
           ``canonical_identifier = provider_id``.
        2. Create a ``depends_on`` relationship from the source entity to the
           provider entity.

        Failures are logged but never propagated -- supply chain inference is
        best-effort enrichment, not a critical pipeline stage.
        """
        detections = detect_providers(entities)
        if not detections:
            return

        self._log(
            "info",
            f"Supply chain: {len(detections)} provider(s) detected "
            f"in pass {pass_number}",
        )

        # Build a lookup from canonical_identifier -> Entity for source entities
        entity_lookup: dict[str, Any] = {
            e.canonical_identifier: e for e in entities
        }

        for detection in detections:
            try:
                # Upsert the provider entity
                provider_entity = await self._entity_repo.create_or_update(
                    tenant_id=TenantId(tenant_id),
                    entity_type="provider",
                    canonical_identifier=detection.provider_id,
                    properties={
                        "provider_name": detection.provider_name,
                        "category": detection.category,
                        "risk_notes": detection.risk_notes,
                    },
                    attribution_status="confirmed",
                    attribution_confidence=Decimal("1.000"),
                )

                # Find the source entity
                source = entity_lookup.get(detection.source_entity)
                if source is None:
                    logger.warning(
                        "Supply chain: source entity %s not found in lookup",
                        detection.source_entity,
                    )
                    continue

                # Create depends_on relationship
                if self._relationship_repo is not None:
                    await self._relationship_repo.create_or_update(
                        tenant_id=TenantId(tenant_id),
                        from_entity_id=EntityId(source.id),
                        to_entity_id=EntityId(provider_entity.id),
                        edge_type="depends_on",
                        confidence=Decimal("0.950"),
                        observed_at=datetime.now(UTC),
                        collector_id="supply-chain-inference",
                        evidence_ref=(
                            f"{detection.evidence_type}:"
                            f"{detection.evidence_value}"
                        ),
                        properties={
                            "evidence_type": detection.evidence_type,
                            "evidence_value": detection.evidence_value,
                            "category": detection.category,
                        },
                    )

                self._log(
                    "info",
                    f"Supply chain: {detection.source_entity} depends_on "
                    f"{detection.provider_name} ({detection.evidence_type}: "
                    f"{detection.evidence_value})",
                )
            except Exception as exc:
                logger.exception(
                    "Supply chain: failed to persist detection %s -> %s",
                    detection.source_entity,
                    detection.provider_id,
                )
                pipeline_errors_total.add(1, {"component": "supply_chain", "error_type": type(exc).__name__})

    async def _apply_takeover_detections(
        self,
        *,
        entities: Any,
        tenant_id: UUID,
        pass_number: int,
    ) -> None:
        """Run subdomain takeover detection and update at-risk entities.

        For each ``TakeoverRisk`` returned by ``detect_takeover_risks``:
        1. Update the source entity's ``attribution_status`` to
           ``requires_review``.
        2. Add ``_takeover_risk`` to the entity's properties with risk details.
        3. Log a CRITICAL-level finding to the scan log.

        Failures are logged but never propagated -- takeover detection is
        best-effort enrichment.
        """
        risks = await detect_takeover_risks(entities)
        if not risks:
            return

        self._log(
            "info",
            f"Takeover detection: {len(risks)} dangling CNAME(s) found "
            f"in pass {pass_number}",
        )

        # Build entity lookup for property updates
        entity_lookup: dict[str, Any] = {
            e.canonical_identifier: e for e in entities
        }

        for risk in risks:
            try:
                source = entity_lookup.get(risk.subdomain)
                if source is None:
                    logger.warning(
                        "Takeover detection: entity %s not found in lookup",
                        risk.subdomain,
                    )
                    continue

                # Build updated properties with takeover risk metadata
                updated_props = dict(source.properties or {})
                updated_props["_takeover_risk"] = {
                    "cname_target": risk.cname_target,
                    "provider": risk.provider,
                    "risk_level": risk.risk_level,
                    "evidence": risk.evidence,
                }

                # Update entity with requires_review status and risk data
                await self._entity_repo.create_or_update(
                    tenant_id=TenantId(tenant_id),
                    entity_type=source.entity_type,
                    canonical_identifier=source.canonical_identifier,
                    properties=updated_props,
                    attribution_status="requires_review",
                    attribution_confidence=Decimal("0.000"),
                )

                # Log as critical finding
                self._log(
                    "error",
                    f"CRITICAL: {risk.subdomain} vulnerable to subdomain "
                    f"takeover via {risk.provider} "
                    f"(CNAME -> {risk.cname_target})",
                )

                logger.critical(
                    "Subdomain takeover risk: %s -> %s (provider: %s, level: %s)",
                    risk.subdomain,
                    risk.cname_target,
                    risk.provider,
                    risk.risk_level,
                )
            except Exception as exc:
                logger.exception(
                    "Takeover detection: failed to update entity %s",
                    risk.subdomain,
                )
                pipeline_errors_total.add(1, {"component": "takeover_detection", "error_type": type(exc).__name__})


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
