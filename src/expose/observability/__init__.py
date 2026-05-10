"""OpenTelemetry observability primitives for EXPOSE (per SPEC section 10.2 / ADR-003).

This package provides three pillars of observability:

- **Tracing** (:mod:`expose.observability.tracing`) — distributed tracing with
  OTel ``TracerProvider``, ``BatchSpanProcessor``, and OTLP export.
- **Logging** (:mod:`expose.observability.logging`) — ``structlog``-based
  structured logging with OTel trace/span ID correlation.
- **Metrics** (:mod:`expose.observability.metrics`) — OTel ``MeterProvider``
  with counters, histograms, and up-down counters for pipeline telemetry.

Convenience:

- :func:`setup_observability` — one-call initialization of all three pillars.
- :data:`current_tenant_id` — ``contextvars.ContextVar`` for tenant propagation.

The :data:`current_tenant_id` context variable is defined here as the
single canonical source. The pipeline dispatcher imports and uses this
same variable, so ``span_context`` reads tenant context set by the
dispatcher.
"""

from __future__ import annotations

import contextvars
from uuid import UUID

from expose.observability.logging import configure_logging, get_logger
from expose.observability.metrics import (
    active_runs,
    collector_dispatch_count,
    collector_dispatch_duration,
    init_metrics,
    observations_emitted,
    run_duration,
)
from expose.observability.tracing import get_tracer, init_tracing, span_context

# Tenant context — canonical source for observability-layer code.
# The pipeline dispatcher also defines its own ContextVar; when both are
# loaded each keeps its own token but ``span_context`` reads from this one.
current_tenant_id: contextvars.ContextVar[UUID | None] = contextvars.ContextVar(
    "current_tenant_id",
    default=None,
)


def setup_observability(
    service_name: str,
    otlp_endpoint: str | None = None,
    json_logs: bool = False,
    log_level: str = "INFO",
) -> None:
    """Initialize all three observability pillars in one call.

    This is the recommended startup entrypoint. It configures tracing, logging,
    and metrics with consistent resource attributes.

    Args:
        service_name: Populates ``service.name`` across all three providers.
        otlp_endpoint: gRPC OTLP collector endpoint (e.g.
            ``"http://localhost:4317"``). When ``None``, dev-friendly console
            exporters are used.
        json_logs: Pass ``True`` in production to emit structured JSON logs.
        log_level: Minimum log level string (e.g. ``"INFO"``, ``"DEBUG"``).
    """
    init_tracing(service_name, otlp_endpoint)
    configure_logging(json_output=json_logs, level=log_level)
    init_metrics(service_name, otlp_endpoint)


__all__ = [
    "active_runs",
    "collector_dispatch_count",
    "collector_dispatch_duration",
    "configure_logging",
    "current_tenant_id",
    "get_logger",
    "get_tracer",
    "init_metrics",
    "init_tracing",
    "observations_emitted",
    "run_duration",
    "setup_observability",
    "span_context",
]
