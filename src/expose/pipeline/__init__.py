"""Pipeline coordination — dispatcher, job routing, and result types.

The pipeline package bridges the NATS JetStream broker (``expose.broker``) and
the collector framework (``expose.collectors``). The ``PipelineDispatcher`` is
the single dispatch entrypoint: it resolves collector classes from the registry,
enforces Tier-3 gating, runs health checks and ``expand()``, and returns
structured ``DispatchResult`` values.

Sub-modules:

- ``dispatcher`` — ``PipelineDispatcher``, ``DispatchJob``, ``DispatchResult``,
  ``DispatchStatus``, and the ``current_tenant_id`` context variable.
- ``nats_dispatcher`` — ``NatsDispatcher``, ``CollectorWorker``,
  ``NatsDispatcherResult`` (NATS-mediated distributed dispatch).
- ``scheduler`` — ``RunScheduler``, ``ScheduleEntry``, ``CronExpression``
  (cron-driven pipeline trigger loop).
- ``enrichment`` — ``EnrichmentPipeline`` (Stage 4b LLM enrichment).
"""

from expose.pipeline.dispatcher import (
    DispatchJob,
    DispatchResult,
    DispatchStatus,
    PipelineDispatcher,
    current_tenant_id,
)
from expose.pipeline.enrichment import EnrichmentPipeline
from expose.pipeline.nats_dispatcher import (
    CollectorWorker,
    NatsDispatcher,
    NatsDispatcherResult,
)
from expose.pipeline.scheduler import CronExpression, RunScheduler, ScheduleEntry

__all__ = [
    "CollectorWorker",
    "CronExpression",
    "DispatchJob",
    "DispatchResult",
    "DispatchStatus",
    "EnrichmentPipeline",
    "NatsDispatcher",
    "NatsDispatcherResult",
    "PipelineDispatcher",
    "RunScheduler",
    "ScheduleEntry",
    "current_tenant_id",
]
