"""Pipeline dispatcher — routes dispatch jobs to the appropriate collector.

The ``PipelineDispatcher`` is the coordination core between the NATS JetStream
broker and the collector framework. It consumes ``DispatchJob`` messages,
resolves the target collector from the registry, enforces Tier-3 gating per
SPEC section 6.3 / ADR-008, runs health checks and ``expand()``, then returns a
structured ``DispatchResult``.

Key design properties:

- **Single dispatch entrypoint.** ``PipelineDispatcher.dispatch`` is the only
  path from broker message to collector execution. This keeps the Tier-3 gate,
  health check, timing, and error handling in one auditable location.
- **Tenant context propagation.** A ``contextvars.ContextVar`` (``current_tenant_id``)
  is set before every dispatch so downstream code (repositories, sanitization)
  can read the active tenant without explicit threading.
- **No credential logging.** ``CollectorCredential.secret_value`` never appears
  in log output; the dispatcher builds ``CollectorConfig`` but does not log it.
- **Deterministic result typing.** Every code path returns a ``DispatchResult``
  with a ``DispatchStatus`` enum rather than raising — callers pattern-match on
  status, not exception types. ``CollectorNotRegisteredError`` is the sole
  exception that propagates (it indicates a programming error in the tenant
  config, not a runtime condition).
"""

from __future__ import annotations

import asyncio
import logging
import time
from enum import StrEnum
from typing import ClassVar
from uuid import UUID

from collections.abc import Callable

# Module-level health-check cache: maps collector_id to
# (monotonic_timestamp, CollectorHealthCheck).  TTL is 60 seconds.
_HEALTH_CACHE_TTL = 60.0
_health_cache: dict[str, tuple[float, "CollectorHealthCheck"]] = {}

# Per-collector-ID asyncio.Lock to prevent thundering-herd on concurrent
# health checks for the same collector (issue #156).  When multiple
# dispatches for the same collector_id arrive concurrently, only the first
# performs the actual health probe; the rest wait on the lock and read the
# now-cached result.
#
# Lock creation uses ``setdefault`` which is atomic in CPython (single
# bytecode op) — two concurrent coroutines for a new collector_id will
# always share the same Lock instance.  (Fixes race in #129.)
_health_locks: dict[str, asyncio.Lock] = {}

# Per-collector-ID consecutive failure counter for the circuit breaker.
# When a collector fails health checks ``_CIRCUIT_BREAKER_THRESHOLD``
# times in a row, further dispatches are short-circuited with
# ``HEALTH_CHECK_FAILED`` until the cache is cleared (next run).
_health_failure_counts: dict[str, int] = {}
_CIRCUIT_BREAKER_THRESHOLD: int = 3

# Timeout constants for wait_for wrappers (seconds).
HEALTH_CHECK_TIMEOUT = 30.0
EXPAND_TIMEOUT = 120.0

from pydantic import BaseModel, ConfigDict, Field

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorCredential,
    CollectorError,
    CollectorHealthCheck,
    CollectorSourceUnreachableError,
    Observation,
    Seed,
    SeedType,
)

# Type alias for the log sink callable.
LogSink = Callable[[str, str], None]
from expose.collectors.registry import CollectorRegistry
from expose.collectors.tiers import (
    CollectorTier,
    EnforcementMode,
    EntityAttributionView,
    TenantAuthorizationScope,
    Tier3DispatchDeniedError,
    assert_tier_3_dispatch_allowed,
)
from expose.egress.base import EgressProfile
from expose.observability import current_tenant_id
from expose.observability.metrics import pipeline_errors_total
from expose.pipeline.credential_resolver import CredentialResolutionError, CredentialResolver
from expose.pipeline.enforcement import EnforcementLog, ScopeRefusalEvent
from expose.scope.matcher import ScopeMatcher
from expose.types.canonical import CollectorStatus

logger = logging.getLogger(__name__)


# === Dispatch envelope ======================================================
class DispatchJob(BaseModel):
    """One unit of work submitted to the dispatcher.

    Mirrors the shape of a ``JobMessage`` but is a local in-process type rather
    than a wire-format envelope. The broker worker deserializes ``JobMessage``
    from NATS, rebuilds the ``Seed``, and hands a ``DispatchJob`` to the
    dispatcher.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    collector_id: str = Field(min_length=1)
    seed: Seed
    run_id: UUID
    tenant_id: UUID


# === Dispatch result ========================================================
class DispatchStatus(StrEnum):
    """Terminal status of a single dispatch attempt."""

    SUCCESS = "success"
    DENIED = "denied"
    HEALTH_CHECK_FAILED = "health_check_failed"
    COLLECTOR_ERROR = "collector_error"
    SKIPPED = "skipped"


class DispatchResult(BaseModel):
    """Structured outcome of ``PipelineDispatcher.dispatch``.

    Every dispatch attempt returns one of these rather than raising. The caller
    inspects ``status`` and acts accordingly (ack, nak, record health, etc.).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: DispatchStatus
    observations: list[Observation] = Field(default_factory=list)
    collector_health: CollectorHealthCheck | None = None
    error_message: str | None = None
    duration_ms: float = 0.0
    egress_anonymized: bool = False


# === Dispatcher =============================================================
class PipelineDispatcher:
    """Routes ``DispatchJob`` messages to the correct collector.

    Lifecycle:

    1. Look up collector class from the registry.
    2. For Tier-3 collectors, enforce the attribution/scope gate.
    3. Construct a fresh ``CollectorConfig`` and collector instance.
    4. Run ``health_check()`` — skip collector if unhealthy.
    5. Run ``expand(seed)`` — collect observations.
    6. Return a ``DispatchResult`` with status, observations, and timing.
    """

    _SEED_TYPE_TO_ENTITY_TYPE: ClassVar[dict[SeedType, str]] = {
        SeedType.DOMAIN: "domain",
        SeedType.IP: "ip",
        SeedType.CIDR: "cidr",
        SeedType.ASN: "asn",
        SeedType.CLOUD_ACCOUNT: "cloud_account",
        SeedType.ORGANIZATION: "registrant_org",
        SeedType.ENTITY: "domain",
    }

    def __init__(
        self,
        registry: CollectorRegistry,
        tenant_scope: TenantAuthorizationScope,
        tenant_id: UUID,
        egress_profile: EgressProfile | None = None,
        enforcement_log: EnforcementLog | None = None,
        scope_matcher: ScopeMatcher | None = None,
        credential_resolver: CredentialResolver | None = None,
        egress_fallbacks: list[EgressProfile] | None = None,
        log_sink: LogSink | None = None,
    ) -> None:
        self._registry = registry
        self._tenant_scope = tenant_scope
        self._tenant_id = tenant_id
        self._egress_profile = egress_profile
        self._enforcement_log = enforcement_log or EnforcementLog()
        self._scope_matcher = scope_matcher
        self._credential_resolver = credential_resolver
        self._egress_fallbacks: list[EgressProfile] = egress_fallbacks or []
        self._log_sink = log_sink

    def _log(self, level: str, msg: str) -> None:
        """Emit a structured log entry to the log sink, if configured."""
        if self._log_sink is not None:
            self._log_sink(level, msg)

    async def dispatch(self, job: DispatchJob) -> DispatchResult:
        """Execute one dispatch job and return a structured result.

        The ``CollectorNotRegisteredError`` from the registry is intentionally
        NOT caught here — it indicates a configuration bug (the tenant's
        ``collectors.enabled`` list references a collector that does not exist)
        and should propagate so the caller can term the message.
        """
        start_ns = time.monotonic_ns()
        token = current_tenant_id.set(job.tenant_id)
        try:
            return await self._dispatch_inner(job, start_ns)
        finally:
            current_tenant_id.reset(token)

    def _check_scope_matcher(self, job: DispatchJob, start_ns: int) -> DispatchResult | None:
        """Run the rich scope matcher if configured; return a DENIED result or None."""
        if self._scope_matcher is None:
            return None
        entity_type = self._SEED_TYPE_TO_ENTITY_TYPE.get(
            job.seed.seed_type, "domain",
        )
        match_result = self._scope_matcher.matches(entity_type, job.seed.value)
        if match_result.in_scope:
            return None

        from datetime import UTC, datetime  # noqa: PLC0415

        self._enforcement_log.record_refusal(ScopeRefusalEvent(
            tenant_id=job.tenant_id,
            entity_identifier=job.seed.value,
            attribution_tier=None,
            enforcement_mode=EnforcementMode.HARD,
            collector_id=job.collector_id,
            reason=match_result.reason,
            timestamp=datetime.now(tz=UTC),
        ))
        return DispatchResult(
            status=DispatchStatus.DENIED,
            error_message=match_result.reason,
            duration_ms=_elapsed_ms(start_ns),
        )

    async def _resolve_credentials(
        self,
        job: DispatchJob,
        start_ns: int,
    ) -> dict[str, CollectorCredential] | DispatchResult:
        """Resolve credentials or return a SKIPPED result on failure.

        Missing credentials are a configuration gap, not a collector bug.
        Returning ``SKIPPED`` instead of ``COLLECTOR_ERROR`` ensures that
        collectors without API keys do not inflate the failure count and
        cause the run to report ``failed`` when it should be ``partial``
        or ``completed``.
        """
        if self._credential_resolver is None:
            logger.debug(
                "No credential resolver configured — collector %s will "
                "receive empty credentials",
                job.collector_id,
            )
            return {}
        try:
            creds = await self._credential_resolver.resolve(
                job.tenant_id, job.collector_id,
            )
            if creds:
                logger.debug(
                    "Resolved %d credential(s) for collector %s: %s",
                    len(creds),
                    job.collector_id,
                    list(creds.keys()),
                )
            return creds
        except CredentialResolutionError as exc:
            logger.warning(
                "Credential resolution failed for collector %s, tenant %s: %s",
                job.collector_id,
                job.tenant_id,
                exc,
            )
            pipeline_errors_total.add(1, {"component": "dispatcher", "error_type": type(exc).__name__})
            return DispatchResult(
                status=DispatchStatus.SKIPPED,
                error_message=str(exc),
                duration_ms=_elapsed_ms(start_ns),
            )

    def _check_tier3_gate(
        self,
        job: DispatchJob,
        collector_cls: type[Collector],
        start_ns: int,
    ) -> DispatchResult | None:
        """Enforce Tier-3 attribution gate; return a DENIED result or None."""
        if collector_cls.tier != CollectorTier.TIER_3:
            return None

        # Propagate attribution_status from seed properties when available
        # so that seeds carrying attribution from prior passes (or from
        # entity-to-seed conversion) are evaluated correctly.
        from expose.types.canonical import AttributionTier as _AT  # noqa: PLC0415

        attr_status = job.seed.properties.get("attribution_status")
        attr_tier: _AT | None = None
        if attr_status is not None:
            try:
                attr_tier = _AT(attr_status)
            except ValueError:
                pass  # unrecognized status → treat as unattributed (None)

        entity = EntityAttributionView(
            entity_identifier=job.seed.value,
            attribution_tier=attr_tier,
        )
        try:
            assert_tier_3_dispatch_allowed(entity, self._tenant_scope)
        except Tier3DispatchDeniedError as exc:
            from datetime import UTC, datetime  # noqa: PLC0415

            self._enforcement_log.record_refusal(ScopeRefusalEvent(
                tenant_id=job.tenant_id,
                entity_identifier=job.seed.value,
                attribution_tier=None,
                enforcement_mode=self._tenant_scope.enforcement_mode,
                collector_id=job.collector_id,
                reason=str(exc),
                timestamp=datetime.now(tz=UTC),
            ))
            return DispatchResult(
                status=DispatchStatus.DENIED,
                error_message=str(exc),
                duration_ms=_elapsed_ms(start_ns),
            )
        return None

    def _check_tier3_attribution_gate(
        self,
        job: DispatchJob,
        collector_cls: type[Collector],
        start_ns: int,
    ) -> DispatchResult | None:
        """Deny Tier-3 dispatch when entity attribution status is insufficient.

        Checks ``attribution_status`` from the seed's ``properties`` dict.
        Entities with status ``unattributed`` or ``requires_review`` are denied
        Tier-3 active collectors with reason ``entity_not_attributed_for_tier3``.

        Operator-provided seeds (present in the tenant's explicit authorization
        scope) bypass this gate — they are implicitly authorized for active
        probing regardless of attribution status.
        """
        if collector_cls.tier != CollectorTier.TIER_3:
            return None

        # Operator-provided seeds are implicitly authorized for Tier-3
        # dispatch.  They were explicitly submitted by the operator, so
        # blocking them on attribution status that hasn't been computed
        # yet would prevent active collectors from ever firing on pass 1.
        if self._tenant_scope.contains(job.seed.value):
            return None

        attribution_status = job.seed.properties.get("attribution_status")
        if attribution_status in ("unattributed", "requires_review"):
            from datetime import UTC, datetime  # noqa: PLC0415

            reason = "entity_not_attributed_for_tier3"
            self._enforcement_log.record_refusal(ScopeRefusalEvent(
                tenant_id=job.tenant_id,
                entity_identifier=job.seed.value,
                attribution_tier=None,
                enforcement_mode=self._tenant_scope.enforcement_mode,
                collector_id=job.collector_id,
                reason=reason,
                timestamp=datetime.now(tz=UTC),
            ))
            return DispatchResult(
                status=DispatchStatus.DENIED,
                error_message=reason,
                duration_ms=_elapsed_ms(start_ns),
            )
        return None

    async def _run_expand(
        self,
        collector_cls: type[Collector],
        job: DispatchJob,
        cred_result: dict[str, CollectorCredential],
        start_ns: int,
        egress_profile: EgressProfile | None = None,
    ) -> DispatchResult:
        """Build a collector instance, health-check it, and run expand.

        Factored out of ``_dispatch_inner`` so the egress-fallback retry loop
        can re-invoke it with a different egress profile applied to the
        collector config without duplicating the health-check/expand/error
        handling.

        Health-check results are cached for 60 seconds per collector_id to
        avoid redundant probes when the same collector is dispatched many
        times within a single run.

        Parameters
        ----------
        egress_profile:
            The egress profile to use for this specific expand attempt.
            Passed explicitly to avoid mutating ``self._egress_profile``
            during fallback retries (race-condition fix).
        """
        config = CollectorConfig(
            tenant_id=job.tenant_id,
            run_id=job.run_id,
            credentials=cred_result,
        )
        collector: Collector = collector_cls(config)

        try:
            # Circuit breaker: if this collector has failed health checks
            # N times consecutively, skip it immediately without re-probing.
            fail_count = _health_failure_counts.get(job.collector_id, 0)
            if fail_count >= _CIRCUIT_BREAKER_THRESHOLD:
                logger.info(
                    "Circuit breaker open for collector %s (%d consecutive "
                    "failures, threshold %d) — skipping",
                    job.collector_id,
                    fail_count,
                    _CIRCUIT_BREAKER_THRESHOLD,
                )
                pipeline_errors_total.add(1, {"component": "dispatcher", "error_type": "CircuitBreakerOpen"})
                return DispatchResult(
                    status=DispatchStatus.HEALTH_CHECK_FAILED,
                    error_message=(
                        f"Circuit breaker open: {fail_count} consecutive "
                        f"health-check failures (threshold={_CIRCUIT_BREAKER_THRESHOLD})"
                    ),
                    duration_ms=_elapsed_ms(start_ns),
                )

            # Health check with TTL cache + per-collector lock to prevent
            # thundering-herd (issue #156) + 30-second timeout.
            #
            # ``setdefault`` is atomic in CPython (single bytecode op), so
            # two concurrent coroutines for a new collector_id will always
            # see the same Lock instance.  Fixes the check-then-set race
            # from issue #129.
            health_lock = _health_locks.setdefault(
                job.collector_id, asyncio.Lock(),
            )

            async with health_lock:
                now = time.monotonic()
                cached = _health_cache.get(job.collector_id)
                if cached is not None and (now - cached[0]) < _HEALTH_CACHE_TTL:
                    health = cached[1]
                else:
                    try:
                        health = await asyncio.wait_for(
                            collector.health_check(),
                            timeout=HEALTH_CHECK_TIMEOUT,
                        )
                    except asyncio.TimeoutError:
                        logger.warning(
                            "Health check for collector %s timed out after %ss",
                            job.collector_id,
                            HEALTH_CHECK_TIMEOUT,
                        )
                        pipeline_errors_total.add(1, {"component": "dispatcher", "error_type": "TimeoutError"})
                        _health_failure_counts[job.collector_id] = (
                            _health_failure_counts.get(job.collector_id, 0) + 1
                        )
                        return DispatchResult(
                            status=DispatchStatus.HEALTH_CHECK_FAILED,
                            error_message=f"Health check timed out after {HEALTH_CHECK_TIMEOUT}s",
                            duration_ms=_elapsed_ms(start_ns),
                        )
                    _health_cache[job.collector_id] = (now, health)

            if health.status not in (
                CollectorStatus.SUCCESS,
                CollectorStatus.PARTIAL_SUCCESS,
            ):
                pipeline_errors_total.add(1, {"component": "dispatcher", "error_type": "HealthCheckFailed"})
                _health_failure_counts[job.collector_id] = (
                    _health_failure_counts.get(job.collector_id, 0) + 1
                )
                return DispatchResult(
                    status=DispatchStatus.HEALTH_CHECK_FAILED,
                    collector_health=health,
                    error_message=health.error_message,
                    duration_ms=_elapsed_ms(start_ns),
                )

            # Health check passed — reset the failure counter.
            _health_failure_counts.pop(job.collector_id, None)

            # Run expand and collect observations with 120-second timeout
            try:
                async def _collect_observations() -> list[Observation]:
                    observations: list[Observation] = []
                    async for obs in collector.expand(job.seed):
                        observations.append(obs)
                    return observations

                observations = await asyncio.wait_for(
                    _collect_observations(),
                    timeout=EXPAND_TIMEOUT,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Collector %s expand timed out after %ss",
                    job.collector_id,
                    EXPAND_TIMEOUT,
                )
                pipeline_errors_total.add(1, {"component": "dispatcher", "error_type": "TimeoutError"})
                return DispatchResult(
                    status=DispatchStatus.COLLECTOR_ERROR,
                    collector_health=health,
                    error_message=f"Collector expand timed out after {EXPAND_TIMEOUT}s",
                    duration_ms=_elapsed_ms(start_ns),
                )
            except CollectorSourceUnreachableError:
                # Re-raise so the caller (_dispatch_inner) can attempt fallback
                raise
            except CollectorError as exc:
                logger.warning(
                    "Collector %s raised CollectorError",
                    job.collector_id,
                    exc_info=True,
                )
                pipeline_errors_total.add(1, {"component": "dispatcher", "error_type": type(exc).__name__})
                return DispatchResult(
                    status=DispatchStatus.COLLECTOR_ERROR,
                    collector_health=health,
                    error_message=str(exc),
                    duration_ms=_elapsed_ms(start_ns),
                )
            except Exception as exc:
                logger.exception(
                    "Unexpected error in collector %s",
                    job.collector_id,
                )
                pipeline_errors_total.add(1, {"component": "dispatcher", "error_type": type(exc).__name__})
                return DispatchResult(
                    status=DispatchStatus.COLLECTOR_ERROR,
                    collector_health=health,
                    error_message=f"{type(exc).__name__}: {exc}",
                    duration_ms=_elapsed_ms(start_ns),
                )

            egress_anon = (
                egress_profile.is_anonymizing
                if egress_profile is not None
                else False
            )
            return DispatchResult(
                status=DispatchStatus.SUCCESS,
                observations=observations,
                collector_health=health,
                duration_ms=_elapsed_ms(start_ns),
                egress_anonymized=egress_anon,
            )
        finally:
            # Resource cleanup: call close() if the collector supports it
            _close = getattr(collector, "close", None)
            if _close is not None and callable(_close):
                try:
                    await _close()
                except Exception as exc:
                    logger.debug(
                        "Ignoring error from collector %s close()",
                        job.collector_id,
                        exc_info=True,
                    )
                    pipeline_errors_total.add(1, {"component": "dispatcher", "error_type": type(exc).__name__})

    async def _dispatch_inner(
        self,
        job: DispatchJob,
        start_ns: int,
    ) -> DispatchResult:
        """Core dispatch logic, separated for readability.

        When a collector raises ``CollectorSourceUnreachableError`` and
        fallback egress profiles are configured, the dispatcher logs the
        primary failure and retries through each fallback in order. If all
        fallbacks also fail, the *original* error is reported.
        """
        # 1. Resolve collector class
        collector_cls = self._registry.get(job.collector_id)

        # 2. Authorization gates (scope matcher, attribution status, then Tier-3)
        auth_denial = (
            self._check_scope_matcher(job, start_ns)
            or self._check_tier3_attribution_gate(job, collector_cls, start_ns)
            or self._check_tier3_gate(job, collector_cls, start_ns)
        )
        if auth_denial is not None:
            return auth_denial

        # 3. Resolve credentials (if resolver provided) and build config
        cred_result = await self._resolve_credentials(job, start_ns)
        if isinstance(cred_result, DispatchResult):
            return cred_result

        # 4. Primary attempt via configured (or default) egress profile
        primary_egress = self._egress_profile
        primary_egress_name = (
            primary_egress.profile_type.value
            if primary_egress is not None
            else "direct"
        )
        try:
            return await self._run_expand(
                collector_cls, job, cred_result, start_ns,
                egress_profile=primary_egress,
            )
        except CollectorSourceUnreachableError as primary_exc:
            # No fallbacks configured — report the error immediately
            if not self._egress_fallbacks:
                logger.warning(
                    "Collector %s source unreachable via %s egress "
                    "(no fallbacks configured)",
                    job.collector_id,
                    primary_egress_name,
                )
                pipeline_errors_total.add(1, {"component": "dispatcher", "error_type": type(primary_exc).__name__})
                return DispatchResult(
                    status=DispatchStatus.COLLECTOR_ERROR,
                    error_message=str(primary_exc),
                    duration_ms=_elapsed_ms(start_ns),
                )

            # Fallback chain — try each in order
            logger.warning(
                "Collector %s source unreachable via %s egress, "
                "attempting %d fallback(s): %s",
                job.collector_id,
                primary_egress_name,
                len(self._egress_fallbacks),
                [fb.profile_type.value for fb in self._egress_fallbacks],
            )

            for fb_profile in self._egress_fallbacks:
                fb_name = fb_profile.profile_type.value
                logger.info(
                    "Retrying collector %s via %s egress fallback",
                    job.collector_id,
                    fb_name,
                )
                self._log(
                    "info",
                    f"Retrying {job.collector_id} via {fb_name} fallback",
                )
                try:
                    result = await self._run_expand(
                        collector_cls, job, cred_result, start_ns,
                        egress_profile=fb_profile,
                    )
                    # Fallback succeeded — annotate and return
                    logger.info(
                        "Collector %s succeeded via %s egress fallback",
                        job.collector_id,
                        fb_name,
                    )
                    return result
                except CollectorSourceUnreachableError:
                    logger.warning(
                        "Collector %s also unreachable via %s egress fallback",
                        job.collector_id,
                        fb_name,
                    )
                    continue

            # All fallbacks exhausted — report the original error
            logger.error(
                "Collector %s unreachable via primary (%s) and all "
                "fallback egress profiles; reporting original error",
                job.collector_id,
                primary_egress_name,
            )
            pipeline_errors_total.add(1, {"component": "dispatcher", "error_type": type(primary_exc).__name__})
            return DispatchResult(
                status=DispatchStatus.COLLECTOR_ERROR,
                error_message=str(primary_exc),
                duration_ms=_elapsed_ms(start_ns),
            )


def _elapsed_ms(start_ns: int) -> float:
    """Compute elapsed milliseconds from a ``time.monotonic_ns`` start."""
    return (time.monotonic_ns() - start_ns) / 1_000_000


def clear_health_cache() -> None:
    """Clear the module-level health-check cache, lock map, and failure counters.

    Call at the start of each pipeline run to ensure fresh health probes
    for the first dispatch of each collector and to reset the circuit
    breaker state.
    """
    _health_cache.clear()
    _health_locks.clear()
    _health_failure_counts.clear()


__all__ = [
    "DispatchJob",
    "DispatchResult",
    "DispatchStatus",
    "EXPAND_TIMEOUT",
    "HEALTH_CHECK_TIMEOUT",
    "PipelineDispatcher",
    "_CIRCUIT_BREAKER_THRESHOLD",
    "_health_failure_counts",
    "_health_locks",
    "clear_health_cache",
    "current_tenant_id",
]
