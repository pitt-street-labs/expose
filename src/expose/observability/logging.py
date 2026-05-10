"""Structured logging configuration for EXPOSE (per SPEC section 10.2 / ADR-003).

Builds on ``structlog`` to provide consistently formatted, OTel-correlated log
output. Call :func:`configure_logging` once at startup; other modules obtain
loggers via :func:`get_logger`.

Trace correlation: every log event is enriched with ``otel_trace_id`` and
``otel_span_id`` from the current OTel context, so logs and traces can be
joined in the observability backend.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any

import structlog
from opentelemetry import trace


def _add_otel_context(
    _logger: Any,
    _method_name: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Structlog processor that injects OTel trace and span IDs.

    When an active span exists, its trace ID and span ID are added as
    ``otel_trace_id`` and ``otel_span_id`` (hex-encoded). When there is no
    active span, the fields are set to empty strings so downstream parsers
    always find them.
    """
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if ctx is not None and ctx.trace_id != 0:
        event_dict["otel_trace_id"] = format(ctx.trace_id, "032x")
        event_dict["otel_span_id"] = format(ctx.span_id, "016x")
    else:
        event_dict["otel_trace_id"] = ""
        event_dict["otel_span_id"] = ""
    return event_dict


def configure_logging(
    json_output: bool = False,
    level: str = "INFO",
) -> None:
    """Configure ``structlog`` with OTel correlation processors.

    Args:
        json_output: When ``True``, render log events as JSON objects (one per
            line). When ``False``, use the human-friendly console renderer.
            Production deployments should set ``True``; local development
            benefits from ``False``.
        level: Minimum log level (e.g. ``"DEBUG"``, ``"INFO"``, ``"WARNING"``).
    """
    shared_processors: list[structlog.types.Processor] = [
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        _add_otel_context,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    renderer: structlog.types.Processor
    if json_output:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            structlog._log_levels.NAME_TO_LEVEL[level.lower()],
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.BoundLogger:
    """Return a bound structlog logger for the given component name.

    The returned logger carries the ``component`` key so every log line is
    attributable to the originating module::

        logger = get_logger("expose.collectors.ct_crtsh")
        logger.info("collector.started", domain="example.com")
    """
    return structlog.get_logger(component=name)  # type: ignore[no-any-return]


__all__ = [
    "configure_logging",
    "get_logger",
]
