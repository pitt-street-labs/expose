"""Prometheus metrics scrape endpoint for EXPOSE (per SPEC section 10.2).

Exposes OTel-collected metrics at ``/metrics`` in Prometheus text format.
If ``opentelemetry-exporter-prometheus`` is not installed or the reader
has not been initialized, returns HTTP 503 with an explanatory message.

Wire into the FastAPI app via::

    from expose.api.metrics import router as metrics_router
    app.include_router(metrics_router)
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse, Response

router = APIRouter(tags=["metrics"])


@router.get(
    "/metrics",
    response_class=PlainTextResponse,
    summary="Prometheus metrics scrape endpoint",
    responses={
        200: {
            "description": "Prometheus text exposition format",
            "content": {"text/plain": {}},
        },
        503: {
            "description": "Prometheus exporter unavailable",
        },
    },
)
async def prometheus_metrics() -> Response:
    """Return OTel metrics in Prometheus text exposition format.

    The endpoint uses ``prometheus_client.generate_latest()`` which reads
    from the default Prometheus ``CollectorRegistry``.  The
    ``PrometheusMetricReader`` (from ``opentelemetry-exporter-prometheus``)
    bridges OTel metrics into that registry automatically.

    Returns 503 if the Prometheus exporter is not available (package not
    installed or reader not initialized).
    """
    try:
        from opentelemetry.exporter.prometheus import (  # noqa: PLC0415
            PrometheusMetricReader as _PrometheusCheck,  # noqa: F841
        )
    except ImportError:
        return PlainTextResponse(
            content="Prometheus exporter not available: "
            "opentelemetry-exporter-prometheus is not installed.\n",
            status_code=503,
        )

    from expose.observability.metrics import get_prometheus_reader  # noqa: PLC0415

    reader = get_prometheus_reader()
    if reader is None:
        return PlainTextResponse(
            content="Prometheus exporter not available: "
            "PrometheusMetricReader has not been initialized. "
            "Ensure enable_otel=True and init_prometheus_reader() has been called.\n",
            status_code=503,
        )

    from prometheus_client import (  # noqa: PLC0415
        CONTENT_TYPE_LATEST,
        REGISTRY,
        generate_latest,
    )

    body = generate_latest(REGISTRY)
    return Response(
        content=body,
        media_type=CONTENT_TYPE_LATEST,
        status_code=200,
    )
