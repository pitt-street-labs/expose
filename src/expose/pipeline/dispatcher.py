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

import contextvars
import logging
import time
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorError,
    CollectorHealthCheck,
    Observation,
    Seed,
)
from expose.collectors.registry import CollectorRegistry
from expose.collectors.tiers import (
    CollectorTier,
    EntityAttributionView,
    TenantAuthorizationScope,
    Tier3DispatchDeniedError,
    assert_tier_3_dispatch_allowed,
)
from expose.types.canonical import CollectorStatus

logger = logging.getLogger(__name__)

# === Tenant context propagation =============================================
current_tenant_id: contextvars.ContextVar[UUID] = contextvars.ContextVar(
    "current_tenant_id",
)


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

    def __init__(
        self,
        registry: CollectorRegistry,
        tenant_scope: TenantAuthorizationScope,
        tenant_id: UUID,
    ) -> None:
        self._registry = registry
        self._tenant_scope = tenant_scope
        self._tenant_id = tenant_id

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

    async def _dispatch_inner(
        self,
        job: DispatchJob,
        start_ns: int,
    ) -> DispatchResult:
        """Core dispatch logic, separated for readability."""
        # 1. Resolve collector class
        collector_cls = self._registry.get(job.collector_id)

        # 2. Tier-3 gating (before constructing the collector instance)
        if collector_cls.tier == CollectorTier.TIER_3:
            entity = EntityAttributionView(
                entity_identifier=job.seed.value,
                attribution_tier=None,
            )
            try:
                assert_tier_3_dispatch_allowed(entity, self._tenant_scope)
            except Tier3DispatchDeniedError as exc:
                return DispatchResult(
                    status=DispatchStatus.DENIED,
                    error_message=str(exc),
                    duration_ms=_elapsed_ms(start_ns),
                )

        # 3. Build config and construct collector
        config = CollectorConfig(
            tenant_id=job.tenant_id,
            run_id=job.run_id,
        )
        collector: Collector = collector_cls(config)

        # 4. Health check
        health = await collector.health_check()
        if health.status not in (
            CollectorStatus.SUCCESS,
            CollectorStatus.PARTIAL_SUCCESS,
        ):
            return DispatchResult(
                status=DispatchStatus.HEALTH_CHECK_FAILED,
                collector_health=health,
                error_message=health.error_message,
                duration_ms=_elapsed_ms(start_ns),
            )

        # 5. Run expand and collect observations
        try:
            observations: list[Observation] = []
            async for obs in collector.expand(job.seed):
                observations.append(obs)
        except CollectorError as exc:
            logger.warning(
                "Collector %s raised CollectorError",
                job.collector_id,
                exc_info=True,
            )
            return DispatchResult(
                status=DispatchStatus.COLLECTOR_ERROR,
                collector_health=health,
                error_message=str(exc),
                duration_ms=_elapsed_ms(start_ns),
            )

        return DispatchResult(
            status=DispatchStatus.SUCCESS,
            observations=observations,
            collector_health=health,
            duration_ms=_elapsed_ms(start_ns),
        )


def _elapsed_ms(start_ns: int) -> float:
    """Compute elapsed milliseconds from a ``time.monotonic_ns`` start."""
    return (time.monotonic_ns() - start_ns) / 1_000_000


__all__ = [
    "DispatchJob",
    "DispatchResult",
    "DispatchStatus",
    "PipelineDispatcher",
    "current_tenant_id",
]
