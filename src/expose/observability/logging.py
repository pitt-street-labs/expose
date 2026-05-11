"""Structured logging configuration for EXPOSE (per SPEC section 10.2 / ADR-003).

Builds on ``structlog`` to provide consistently formatted, OTel-correlated log
output. Call :func:`configure_logging` once at startup; other modules obtain
loggers via :func:`get_logger`.

Trace correlation: every log event is enriched with ``otel_trace_id`` and
``otel_span_id`` from the current OTel context, so logs and traces can be
joined in the observability backend.

Audit logging: :func:`configure_audit_logging` creates a dedicated stdlib
logger that writes append-only NDJSON to a file (one JSON object per line).
:func:`emit_audit_event` serializes an :class:`AuditEvent` to that logger.
The audit log path defaults to ``./audit.log`` and is overridable via the
``EXPOSE_AUDIT_LOG_PATH`` environment variable.
"""

from __future__ import annotations

import json
import logging as stdlib_logging
import os
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
            getattr(stdlib_logging, level.upper(), stdlib_logging.INFO),
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


_AUDIT_LOGGER_NAME = "expose.audit"


def configure_audit_logging(
    path: str | None = None,
) -> stdlib_logging.Logger:
    """Create (or reconfigure) the dedicated audit logger.

    The audit logger writes append-only NDJSON — one JSON object per line — to
    the file at *path*.  Each line is a complete, self-contained audit record
    that satisfies NIST AU-3 content requirements.

    Args:
        path: Filesystem path for the audit log.  When ``None``, falls back to
            the ``EXPOSE_AUDIT_LOG_PATH`` environment variable, then to
            ``"./audit.log"``.

    Returns:
        The configured :class:`logging.Logger` instance.  Callers rarely need
        the return value — :func:`emit_audit_event` obtains the logger by name
        internally.
    """
    if path is None:
        path = os.environ.get("EXPOSE_AUDIT_LOG_PATH", "./audit.log")

    logger = stdlib_logging.getLogger(_AUDIT_LOGGER_NAME)
    logger.setLevel(stdlib_logging.INFO)
    # Prevent duplicate handlers on repeated calls (e.g. test teardown/setup).
    # Close existing handlers first to avoid ResourceWarning from leaked fds.
    for handler in list(logger.handlers):
        handler.close()
    logger.handlers.clear()
    logger.propagate = False

    handler = stdlib_logging.FileHandler(path, mode="a", encoding="utf-8")
    handler.setLevel(stdlib_logging.INFO)
    # Raw message only — the JSON record is self-describing.
    handler.setFormatter(stdlib_logging.Formatter("%(message)s"))
    logger.addHandler(handler)

    return logger


def emit_audit_event(event: Any) -> None:
    """Serialize an ``AuditEvent`` to the audit log as a single JSON line.

    The *event* is expected to be a
    :class:`~expose.observability.audit_schema.AuditEvent` instance (imported
    lazily to avoid circular imports).  Any Pydantic model with a
    ``model_dump(mode="json")`` method is accepted.

    If the audit logger has not been configured (no handlers), the event is
    silently dropped rather than crashing — audit failures must never take down
    the pipeline.  The ``mode="json"`` serialization ensures UUIDs and
    datetimes are rendered as ISO-8601 strings.

    Before serialization, the ``details`` dict is passed through
    :func:`~expose.observability.audit_schema.sanitize_details` to strip
    known sensitive key patterns (passwords, secrets, tokens, API keys,
    credentials).
    """
    from expose.observability.audit_schema import sanitize_details  # noqa: PLC0415

    logger = stdlib_logging.getLogger(_AUDIT_LOGGER_NAME)
    if not logger.handlers:
        return
    try:
        record = event.model_dump(mode="json")
        if "details" in record and isinstance(record["details"], dict):
            record["details"] = sanitize_details(record["details"])
        logger.info(json.dumps(record, separators=(",", ":")))
    except Exception:  # noqa: BLE001 — audit must never crash the pipeline
        logger.error("audit_serialization_failure")


__all__ = [
    "configure_audit_logging",
    "configure_logging",
    "emit_audit_event",
    "get_logger",
]
