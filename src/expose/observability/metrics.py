"""OpenTelemetry metrics configuration for EXPOSE (per SPEC section 10.2 / ADR-003).

This module defines the meter and the metric instruments used by pipeline
components. Call :func:`init_metrics` once at startup; the module-level
instrument handles are then usable from anywhere.

Instrument naming follows the OTel semantic conventions with an ``expose.``
namespace prefix to avoid collisions with auto-instrumentation metrics.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    ConsoleMetricExporter,
    MetricReader,
    PeriodicExportingMetricReader,
)

if TYPE_CHECKING:
    from opentelemetry.metrics import Counter, Histogram, UpDownCounter


def _get_service_version() -> str:
    """Resolve the installed package version, falling back to the dev marker."""
    try:
        from expose import __version__  # noqa: PLC0415

        return __version__
    except (ImportError, AttributeError):
        return "0.1.0.dev0"


def init_metrics(
    service_name: str,
    otlp_endpoint: str | None = None,
    *,
    _reader_override: MetricReader | None = None,
) -> None:
    """Configure the global OTel ``MeterProvider``.

    Args:
        service_name: Populates the ``service.name`` resource attribute (kept
            consistent with the tracing resource).
        otlp_endpoint: If provided, metrics are exported via gRPC OTLP to this
            endpoint. When ``None``, a ``ConsoleMetricExporter`` is used for
            local development.
        _reader_override: Test-only hook to inject a custom ``MetricReader``
            (e.g. ``InMemoryMetricReader``). Not part of the public API.
    """
    from opentelemetry.sdk.resources import Resource  # noqa: PLC0415

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": _get_service_version(),
        },
    )

    reader: MetricReader
    if _reader_override is not None:
        reader = _reader_override
    elif otlp_endpoint is not None:
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (  # noqa: PLC0415
            OTLPMetricExporter,
        )

        reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=otlp_endpoint),
        )
    else:
        reader = PeriodicExportingMetricReader(ConsoleMetricExporter())

    provider = MeterProvider(resource=resource, metric_readers=[reader])
    metrics.set_meter_provider(provider)

    _create_instruments(provider)


def _create_instruments(provider: MeterProvider) -> None:
    """Create the named metric instruments on the given provider.

    Called once from :func:`init_metrics`. The instruments are stored at
    module level so pipeline components can import and use them directly.
    """
    global collector_dispatch_duration  # noqa: PLW0603
    global collector_dispatch_count  # noqa: PLW0603
    global observations_emitted  # noqa: PLW0603
    global run_duration  # noqa: PLW0603
    global active_runs  # noqa: PLW0603
    global pipeline_dispatches_total  # noqa: PLW0603
    global pipeline_dispatch_duration_seconds  # noqa: PLW0603
    global pipeline_observations_total  # noqa: PLW0603
    global pipeline_runs_total  # noqa: PLW0603
    global pipeline_entities_discovered_total  # noqa: PLW0603
    global pipeline_lead_score  # noqa: PLW0603
    global api_requests_total  # noqa: PLW0603
    global pipeline_errors_total  # noqa: PLW0603

    meter = provider.get_meter("expose.metrics", _get_service_version())

    collector_dispatch_duration = meter.create_histogram(
        name="expose.collector.dispatch.duration",
        description="Time taken to dispatch a single collector invocation",
        unit="ms",
    )

    collector_dispatch_count = meter.create_counter(
        name="expose.collector.dispatch.count",
        description="Number of collector dispatch attempts",
        unit="{dispatch}",
    )

    observations_emitted = meter.create_counter(
        name="expose.observations.emitted",
        description="Number of observations emitted by collectors",
        unit="{observation}",
    )

    run_duration = meter.create_histogram(
        name="expose.run.duration",
        description="Duration of a complete pipeline run",
        unit="ms",
    )

    active_runs = meter.create_up_down_counter(
        name="expose.runs.active",
        description="Number of pipeline runs currently in progress",
        unit="{run}",
    )

    # -- Pipeline-specific instruments (Sprint 4+) ----------------------------

    pipeline_dispatches_total = meter.create_counter(
        name="expose.pipeline.dispatches_total",
        description="Total collector dispatches with outcome status",
        unit="{dispatch}",
    )

    pipeline_dispatch_duration_seconds = meter.create_histogram(
        name="expose.pipeline.dispatch_duration_seconds",
        description="Duration of individual collector dispatches in seconds",
        unit="s",
    )

    pipeline_observations_total = meter.create_counter(
        name="expose.pipeline.observations_total",
        description="Total observations produced by collectors",
        unit="{observation}",
    )

    pipeline_runs_total = meter.create_counter(
        name="expose.pipeline.runs_total",
        description="Total pipeline runs by final outcome state",
        unit="{run}",
    )

    pipeline_entities_discovered_total = meter.create_counter(
        name="expose.pipeline.entities_discovered_total",
        description="Total entities discovered across pipeline runs",
        unit="{entity}",
    )

    pipeline_lead_score = meter.create_histogram(
        name="expose.pipeline.lead_score",
        description="Distribution of computed lead scores by priority tier",
        unit="1",
    )

    api_requests_total = meter.create_counter(
        name="expose.api.requests_total",
        description="Total HTTP API requests handled",
        unit="{request}",
    )

    pipeline_errors_total = meter.create_counter(
        name="expose.pipeline.errors_total",
        description="Total swallowed exceptions in pipeline components",
        unit="{error}",
    )


# Module-level instrument handles. These are proxy objects until
# ``init_metrics`` replaces them with real SDK instruments.
_meter = metrics.get_meter("expose.metrics")

collector_dispatch_duration: Histogram = _meter.create_histogram(
    name="expose.collector.dispatch.duration",
    description="Time taken to dispatch a single collector invocation",
    unit="ms",
)

collector_dispatch_count: Counter = _meter.create_counter(
    name="expose.collector.dispatch.count",
    description="Number of collector dispatch attempts",
    unit="{dispatch}",
)

observations_emitted: Counter = _meter.create_counter(
    name="expose.observations.emitted",
    description="Number of observations emitted by collectors",
    unit="{observation}",
)

run_duration: Histogram = _meter.create_histogram(
    name="expose.run.duration",
    description="Duration of a complete pipeline run",
    unit="ms",
)

active_runs: UpDownCounter = _meter.create_up_down_counter(
    name="expose.runs.active",
    description="Number of pipeline runs currently in progress",
    unit="{run}",
)

# -- Pipeline-specific proxy instruments ------------------------------------

pipeline_dispatches_total: Counter = _meter.create_counter(
    name="expose.pipeline.dispatches_total",
    description="Total collector dispatches with outcome status",
    unit="{dispatch}",
)

pipeline_dispatch_duration_seconds: Histogram = _meter.create_histogram(
    name="expose.pipeline.dispatch_duration_seconds",
    description="Duration of individual collector dispatches in seconds",
    unit="s",
)

pipeline_observations_total: Counter = _meter.create_counter(
    name="expose.pipeline.observations_total",
    description="Total observations produced by collectors",
    unit="{observation}",
)

pipeline_runs_total: Counter = _meter.create_counter(
    name="expose.pipeline.runs_total",
    description="Total pipeline runs by final outcome state",
    unit="{run}",
)

pipeline_entities_discovered_total: Counter = _meter.create_counter(
    name="expose.pipeline.entities_discovered_total",
    description="Total entities discovered across pipeline runs",
    unit="{entity}",
)

pipeline_lead_score: Histogram = _meter.create_histogram(
    name="expose.pipeline.lead_score",
    description="Distribution of computed lead scores by priority tier",
    unit="1",
)

api_requests_total: Counter = _meter.create_counter(
    name="expose.api.requests_total",
    description="Total HTTP API requests handled",
    unit="{request}",
)

pipeline_errors_total: Counter = _meter.create_counter(
    name="expose.pipeline.errors_total",
    description="Total swallowed exceptions in pipeline components",
    unit="{error}",
)


# -- Prometheus metric reader (optional) ------------------------------------

_prometheus_reader: MetricReader | None = None


def get_prometheus_reader() -> MetricReader | None:
    """Return the active ``PrometheusMetricReader`` if configured, else ``None``.

    Called by the ``/metrics`` endpoint to check whether Prometheus scraping
    is available.
    """
    return _prometheus_reader


def init_prometheus_reader() -> MetricReader | None:
    """Create and return a ``PrometheusMetricReader``.

    Returns ``None`` if ``opentelemetry-exporter-prometheus`` is not
    installed. The reader is cached at module level and returned on
    subsequent calls.
    """
    global _prometheus_reader  # noqa: PLW0603
    if _prometheus_reader is not None:
        return _prometheus_reader
    try:
        from opentelemetry.exporter.prometheus import (  # noqa: PLC0415
            PrometheusMetricReader,
        )

        _prometheus_reader = PrometheusMetricReader()
        return _prometheus_reader
    except ImportError:
        return None


__all__ = [
    "active_runs",
    "api_requests_total",
    "collector_dispatch_count",
    "collector_dispatch_duration",
    "get_prometheus_reader",
    "init_metrics",
    "init_prometheus_reader",
    "observations_emitted",
    "pipeline_dispatch_duration_seconds",
    "pipeline_dispatches_total",
    "pipeline_entities_discovered_total",
    "pipeline_errors_total",
    "pipeline_lead_score",
    "pipeline_observations_total",
    "pipeline_runs_total",
    "run_duration",
]
