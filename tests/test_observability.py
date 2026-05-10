"""Tests for the observability package (tracing + logging + metrics).

Coverage:

1. ``init_tracing`` configures a ``TracerProvider`` on the global API.
2. ``get_tracer`` returns a ``Tracer`` instance.
3. ``span_context`` creates a span with custom attributes.
4. ``span_context`` injects ``tenant_id`` when the contextvar is set.
5. ``configure_logging`` sets up structlog (basic log call succeeds).
6. ``get_logger`` returns a bound logger with a ``component`` key.
7. ``init_metrics`` configures a ``MeterProvider``.
8. Metric instruments are usable (counter.add, histogram.record, up-down).
9. ``setup_observability`` calls all three init functions without error.
10. JSON logging mode produces parseable JSON output.

All tests use in-process OTel SDK components (``SimpleSpanProcessor``,
``InMemoryMetricReader``) and never require external services.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

import json
from io import StringIO
from uuid import UUID

import structlog
from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult

from expose.observability import (
    current_tenant_id,
    setup_observability,
)
from expose.observability.logging import configure_logging, get_logger
from expose.observability.metrics import (
    init_metrics,
)
from expose.observability.tracing import get_tracer, init_tracing, span_context

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _CollectingExporter(SpanExporter):
    """In-process exporter that records finished spans for assertions."""

    def __init__(self) -> None:
        self.spans: list[object] = []

    def export(self, spans: object) -> SpanExportResult:  # type: ignore[override]
        if isinstance(spans, (list, tuple)):
            self.spans.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        pass


def _reset_tracer_provider() -> None:
    """Reset the global tracer provider so each test starts clean.

    The OTel API stores the provider as a global singleton. Between tests we
    need to reset it to avoid cross-test contamination.
    """
    # Replace with a fresh proxy so the next ``set_tracer_provider`` call works.
    trace._TRACER_PROVIDER = None  # type: ignore[attr-defined]
    trace._TRACER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]


def _reset_meter_provider() -> None:
    """Reset the global meter provider between tests."""
    from opentelemetry.metrics import _internal as metrics_internal  # noqa: PLC0415

    provider = metrics.get_meter_provider()
    if isinstance(provider, MeterProvider):
        provider.shutdown()
    metrics_internal._METER_PROVIDER = None  # type: ignore[attr-defined]
    metrics_internal._METER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Tracing tests
# ---------------------------------------------------------------------------


def test_init_tracing_configures_provider() -> None:
    """init_tracing installs an SDK TracerProvider on the global API."""
    _reset_tracer_provider()
    try:
        init_tracing("expose-test")
        provider = trace.get_tracer_provider()
        assert isinstance(provider, TracerProvider)
    finally:
        _reset_tracer_provider()


def test_get_tracer_returns_tracer() -> None:
    """get_tracer returns an object that satisfies the Tracer interface."""
    _reset_tracer_provider()
    try:
        init_tracing("expose-test")
        tracer = get_tracer("expose.test.module")
        # The SDK wraps it; we verify it has `start_span`.
        assert hasattr(tracer, "start_span")
        assert hasattr(tracer, "start_as_current_span")
    finally:
        _reset_tracer_provider()


def test_span_context_creates_span_with_attributes() -> None:
    """span_context creates a span and applies custom attributes."""
    _reset_tracer_provider()
    exporter = _CollectingExporter()
    try:
        # Use SimpleSpanProcessor so spans are exported synchronously.
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        with span_context("test.operation", {"collector_id": "ct_crtsh"}):
            pass

        assert len(exporter.spans) == 1
        span_obj = exporter.spans[0]
        attrs = dict(span_obj.attributes)  # type: ignore[union-attr]
        assert attrs["collector_id"] == "ct_crtsh"
        assert span_obj.name == "test.operation"  # type: ignore[union-attr]
    finally:
        _reset_tracer_provider()


def test_span_context_injects_tenant_id() -> None:
    """span_context adds tenant_id from the contextvar when set."""
    _reset_tracer_provider()
    exporter = _CollectingExporter()
    tenant = UUID("018f1f00-0000-7000-8000-00000000a001")
    try:
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        token = current_tenant_id.set(tenant)
        try:
            with span_context("test.tenant_op"):
                pass
        finally:
            current_tenant_id.reset(token)

        assert len(exporter.spans) == 1
        attrs = dict(exporter.spans[0].attributes)  # type: ignore[union-attr]
        assert attrs["tenant_id"] == str(tenant)
    finally:
        _reset_tracer_provider()


# ---------------------------------------------------------------------------
# Logging tests
# ---------------------------------------------------------------------------


def test_configure_logging_does_not_crash() -> None:
    """configure_logging completes without error and a log call succeeds."""
    configure_logging(json_output=False, level="DEBUG")
    logger = get_logger("expose.test")
    # This must not raise — it proves structlog is configured.
    logger.info("test_event", key="value")
    # Reset structlog so other tests are not affected.
    structlog.reset_defaults()


def test_get_logger_returns_bound_logger() -> None:
    """get_logger returns a logger with the component key bound."""
    configure_logging(json_output=False, level="INFO")
    try:
        logger = get_logger("expose.collectors.test")
        # Verify it has standard log methods.
        assert callable(getattr(logger, "info", None))
        assert callable(getattr(logger, "warning", None))
        assert callable(getattr(logger, "error", None))
    finally:
        structlog.reset_defaults()


def test_json_logging_produces_parseable_json() -> None:
    """When json_output=True, log output is valid JSON."""
    output = StringIO()
    configure_logging(json_output=True, level="DEBUG")
    try:
        # Override the logger factory to capture output.
        structlog.configure(
            logger_factory=structlog.PrintLoggerFactory(file=output),
            cache_logger_on_first_use=False,
        )
        logger = structlog.get_logger(component="expose.test.json")
        logger.info("json_test_event", domain="example.com")

        raw = output.getvalue().strip()
        # Must have at least one line of output.
        assert raw, "Expected JSON log output but got nothing"
        parsed = json.loads(raw)
        assert parsed["event"] == "json_test_event"
        assert parsed["domain"] == "example.com"
        assert "timestamp" in parsed
        assert "level" in parsed
    finally:
        structlog.reset_defaults()


# ---------------------------------------------------------------------------
# Metrics tests
# ---------------------------------------------------------------------------


def test_init_metrics_configures_provider() -> None:
    """init_metrics installs an SDK MeterProvider on the global API."""
    _reset_meter_provider()
    try:
        reader = InMemoryMetricReader()
        init_metrics("expose-test", _reader_override=reader)
        provider = metrics.get_meter_provider()
        assert isinstance(provider, MeterProvider)
    finally:
        _reset_meter_provider()


def test_metric_instruments_are_usable() -> None:
    """Metric instruments accept add/record calls without error."""
    _reset_meter_provider()
    try:
        reader = InMemoryMetricReader()
        init_metrics("expose-test", _reader_override=reader)

        # Re-import to get the freshly-created instruments.
        from expose.observability import metrics as obs_metrics  # noqa: PLC0415

        # Counter — add
        obs_metrics.collector_dispatch_count.add(
            1,
            {"collector_id": "ct_crtsh", "status": "success"},
        )
        obs_metrics.observations_emitted.add(
            5,
            {"collector_id": "ct_crtsh", "tenant_id": "tenant-1"},
        )

        # Histogram — record
        obs_metrics.collector_dispatch_duration.record(
            42.5,
            {"collector_id": "ct_crtsh"},
        )
        obs_metrics.run_duration.record(1500.0)

        # UpDownCounter — add positive and negative
        obs_metrics.active_runs.add(1)
        obs_metrics.active_runs.add(-1)

        # Force a collection to verify no export errors.
        collected = reader.get_metrics_data()
        assert collected is not None
    finally:
        _reset_meter_provider()


# ---------------------------------------------------------------------------
# Integration / convenience
# ---------------------------------------------------------------------------


def test_setup_observability_calls_all_three() -> None:
    """setup_observability initializes tracing, logging, and metrics."""
    _reset_tracer_provider()
    _reset_meter_provider()
    try:
        setup_observability(
            service_name="expose-integration-test",
            otlp_endpoint=None,
            json_logs=False,
            log_level="WARNING",
        )

        # Tracing: provider must be an SDK TracerProvider.
        assert isinstance(trace.get_tracer_provider(), TracerProvider)

        # Metrics: provider must be an SDK MeterProvider.
        assert isinstance(metrics.get_meter_provider(), MeterProvider)

        # Logging: a log call must succeed.
        logger = get_logger("expose.setup_test")
        logger.warning("setup_test_event")
    finally:
        _reset_tracer_provider()
        _reset_meter_provider()
        structlog.reset_defaults()
