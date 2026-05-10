"""OpenTelemetry tracing configuration for EXPOSE (per SPEC section 10.2 / ADR-003).

This module provides the tracing initialization and convenience wrappers.
Call :func:`init_tracing` once at startup; other modules use :func:`get_tracer`
and :func:`span_context` to instrument their code paths without coupling to
the OTel SDK directly.

Tenant context propagation: when :data:`expose.observability.current_tenant_id`
is set (by the pipeline dispatcher or broker worker), :func:`span_context`
automatically adds ``tenant_id`` as a span attribute so traces are filterable
per tenant in the observability backend.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SpanExporter,
)

if TYPE_CHECKING:
    from opentelemetry.trace import Span, Tracer


def _get_service_version() -> str:
    """Resolve the installed package version, falling back to the dev marker."""
    try:
        from expose import __version__  # noqa: PLC0415

        return __version__
    except (ImportError, AttributeError):
        return "0.1.0.dev0"


def init_tracing(
    service_name: str,
    otlp_endpoint: str | None = None,
    *,
    _exporter_override: SpanExporter | None = None,
) -> None:
    """Configure the global OTel ``TracerProvider`` with a ``BatchSpanProcessor``.

    Args:
        service_name: Populates the ``service.name`` resource attribute.
        otlp_endpoint: If provided, traces are exported via gRPC OTLP to this
            endpoint (e.g. ``"http://localhost:4317"``). When ``None``, a
            ``ConsoleSpanExporter`` is used for local development.
        _exporter_override: Test-only hook to inject a custom exporter without
            needing a live OTLP endpoint. Not part of the public API.
    """
    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": _get_service_version(),
        },
    )

    exporter: SpanExporter
    if _exporter_override is not None:
        exporter = _exporter_override
    elif otlp_endpoint is not None:
        # Deferred import: the OTLP exporter pulls in grpc, which is heavy.
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # noqa: PLC0415
            OTLPSpanExporter,
        )

        exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
    else:
        exporter = ConsoleSpanExporter()

    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)


def get_tracer(name: str) -> Tracer:
    """Return an OTel ``Tracer`` for the given instrumentation scope.

    Typical usage::

        tracer = get_tracer(__name__)
    """
    return trace.get_tracer(name)


@contextmanager
def span_context(
    name: str,
    attributes: dict[str, str] | None = None,
) -> Iterator[Span]:
    """Create an OTel span as a context manager, auto-injecting tenant context.

    Example::

        with span_context("collector.expand", {"collector_id": cid}) as span:
            ...

    If :data:`expose.observability.current_tenant_id` is set in the current
    context, its string representation is added as ``tenant_id``.
    """
    tracer = trace.get_tracer("expose.observability")
    merged: dict[str, str] = dict(attributes) if attributes else {}

    # Inject tenant context when available.
    try:
        from expose.observability import current_tenant_id  # noqa: PLC0415

        tid = current_tenant_id.get(None)
        if tid is not None:
            merged["tenant_id"] = str(tid)
    except (ImportError, LookupError):
        pass

    with tracer.start_as_current_span(name, attributes=merged) as span:
        yield span


__all__ = [
    "get_tracer",
    "init_tracing",
    "span_context",
]
