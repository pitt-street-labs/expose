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
    except Exception:
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


__all__ = [
    "active_runs",
    "collector_dispatch_count",
    "collector_dispatch_duration",
    "init_metrics",
    "observations_emitted",
    "run_duration",
]
