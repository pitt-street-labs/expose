"""Pipeline coordination — dispatcher, job routing, and result types.

The pipeline package bridges the NATS JetStream broker (``expose.broker``) and
the collector framework (``expose.collectors``). The ``PipelineDispatcher`` is
the single dispatch entrypoint: it resolves collector classes from the registry,
enforces Tier-3 gating, runs health checks and ``expand()``, and returns
structured ``DispatchResult`` values.

Sub-modules:

- ``dispatcher`` — ``PipelineDispatcher``, ``DispatchJob``, ``DispatchResult``,
  ``DispatchStatus``, and the ``current_tenant_id`` context variable.
"""

from expose.pipeline.dispatcher import (
    DispatchJob,
    DispatchResult,
    DispatchStatus,
    PipelineDispatcher,
    current_tenant_id,
)

__all__ = [
    "DispatchJob",
    "DispatchResult",
    "DispatchStatus",
    "PipelineDispatcher",
    "current_tenant_id",
]
