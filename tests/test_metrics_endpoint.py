"""Tests for the Prometheus /metrics endpoint and pipeline metric instruments.

Coverage:

1. ``GET /metrics`` returns 200 with Prometheus text content type.
2. ``GET /metrics`` body contains expected metric families from OTel.
3. Pipeline counter instruments increment correctly and appear in output.
4. Pipeline histogram instruments record correctly and appear in output.
5. API request counter increments and is visible.
6. ``/metrics`` returns 503 when the PrometheusMetricReader is not initialized.

All tests use in-process OTel SDK components and never require external
services.  The ``prometheus_client`` global registry is cleaned up between
tests to prevent cross-contamination.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from opentelemetry import metrics as otel_metrics
from opentelemetry.sdk.metrics import MeterProvider

from expose.api.metrics import router as metrics_router
from expose.db.engine import DatabaseSettings
from expose.observability.metrics import (
    init_metrics,
    init_prometheus_reader,
)

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reset_meter_provider() -> None:
    """Reset the global meter provider between tests."""
    from opentelemetry.metrics import _internal as metrics_internal  # noqa: PLC0415

    provider = otel_metrics.get_meter_provider()
    if isinstance(provider, MeterProvider):
        provider.shutdown()
    metrics_internal._METER_PROVIDER = None  # type: ignore[attr-defined]
    metrics_internal._METER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]


def _reset_prometheus_state() -> None:
    """Reset the prometheus_client default registry and the module-level reader."""
    import expose.observability.metrics as obs_mod  # noqa: PLC0415
    from prometheus_client import REGISTRY  # noqa: PLC0415

    # Clear the module-level prometheus reader cache.
    obs_mod._prometheus_reader = None

    # Unregister all non-platform collectors from the default registry.
    collectors_to_remove = list(REGISTRY._names_to_collectors.values())
    for collector in collectors_to_remove:
        try:
            REGISTRY.unregister(collector)
        except Exception:  # noqa: BLE001
            pass


def _make_test_app() -> FastAPI:
    """Build a minimal FastAPI app with only the metrics router.

    Avoids importing the full create_app to sidestep DB/lifespan deps.
    """
    app = FastAPI(title="EXPOSE Metrics Test")

    @asynccontextmanager
    async def _noop_lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield

    app.router.lifespan_context = _noop_lifespan  # type: ignore[assignment]
    app.include_router(metrics_router)
    return app


@pytest.fixture(autouse=True)
def _clean_otel_and_prometheus() -> Iterator[None]:
    """Reset OTel meter provider and Prometheus registry around each test."""
    _reset_meter_provider()
    _reset_prometheus_state()
    yield
    _reset_meter_provider()
    _reset_prometheus_state()


def _init_otel_with_prometheus() -> None:
    """Initialize OTel metrics with a PrometheusMetricReader."""
    reader = init_prometheus_reader()
    assert reader is not None, "PrometheusMetricReader should be available"
    init_metrics("expose-test", _reader_override=reader)


# ---------------------------------------------------------------------------
# Tests: /metrics endpoint
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_metrics_endpoint_returns_200() -> None:
    """GET /metrics returns 200 with Prometheus text content type."""
    _init_otel_with_prometheus()
    app = _make_test_app()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/metrics")

    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]


@pytest.mark.anyio
async def test_metrics_endpoint_contains_otel_metrics() -> None:
    """GET /metrics body includes OTel metric families with expose prefix."""
    _init_otel_with_prometheus()

    # Record some values so metrics appear in the output.
    from expose.observability import metrics as obs_metrics  # noqa: PLC0415

    obs_metrics.collector_dispatch_count.add(
        1, {"collector_id": "ct_crtsh", "status": "success"},
    )
    obs_metrics.pipeline_dispatches_total.add(
        1, {"collector_id": "ct_crtsh", "status": "success"},
    )

    app = _make_test_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/metrics")

    body = resp.text
    # OTel Prometheus exporter converts dots to underscores and appends
    # unit suffix. Verify at least one expose metric family is present.
    assert "expose_" in body


@pytest.mark.anyio
async def test_metrics_endpoint_503_when_reader_not_initialized() -> None:
    """GET /metrics returns 503 when PrometheusMetricReader is not initialized."""
    # Do NOT call _init_otel_with_prometheus — leave reader as None.
    app = _make_test_app()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/metrics")

    assert resp.status_code == 503
    assert "not" in resp.text.lower()


@pytest.mark.anyio
async def test_metrics_endpoint_503_when_package_missing() -> None:
    """GET /metrics returns 503 when opentelemetry-exporter-prometheus is not importable."""
    app = _make_test_app()

    # Patch the import to simulate the package being absent.
    import builtins  # noqa: PLC0415

    _real_import = builtins.__import__

    def _mock_import(name: str, *args: object, **kwargs: object) -> object:
        if "opentelemetry.exporter.prometheus" in name:
            raise ImportError("mocked missing package")
        return _real_import(name, *args, **kwargs)

    with patch.object(builtins, "__import__", side_effect=_mock_import):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get("/metrics")

    assert resp.status_code == 503
    assert "not installed" in resp.text.lower()


# ---------------------------------------------------------------------------
# Tests: Pipeline metric instruments
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_pipeline_dispatches_counter() -> None:
    """pipeline_dispatches_total increments and appears in /metrics output."""
    _init_otel_with_prometheus()
    from expose.observability import metrics as obs_metrics  # noqa: PLC0415

    obs_metrics.pipeline_dispatches_total.add(
        3, {"collector_id": "dns_enum", "status": "success"},
    )
    obs_metrics.pipeline_dispatches_total.add(
        1, {"collector_id": "dns_enum", "status": "error"},
    )

    app = _make_test_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/metrics")

    body = resp.text
    assert "expose_pipeline_dispatches" in body


@pytest.mark.anyio
async def test_pipeline_dispatch_duration_histogram() -> None:
    """pipeline_dispatch_duration_seconds records and appears in output."""
    _init_otel_with_prometheus()
    from expose.observability import metrics as obs_metrics  # noqa: PLC0415

    obs_metrics.pipeline_dispatch_duration_seconds.record(
        0.45, {"collector_id": "ct_crtsh"},
    )
    obs_metrics.pipeline_dispatch_duration_seconds.record(
        1.2, {"collector_id": "ct_crtsh"},
    )

    app = _make_test_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/metrics")

    body = resp.text
    # Histogram produces _bucket, _count, _sum families.
    assert "expose_pipeline_dispatch_duration_seconds" in body


@pytest.mark.anyio
async def test_pipeline_observations_counter() -> None:
    """pipeline_observations_total increments correctly."""
    _init_otel_with_prometheus()
    from expose.observability import metrics as obs_metrics  # noqa: PLC0415

    obs_metrics.pipeline_observations_total.add(
        5, {"collector_id": "ct_crtsh", "observation_type": "certificate"},
    )
    obs_metrics.pipeline_observations_total.add(
        2, {"collector_id": "dns_enum", "observation_type": "domain"},
    )

    app = _make_test_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/metrics")

    body = resp.text
    assert "expose_pipeline_observations" in body


@pytest.mark.anyio
async def test_pipeline_runs_counter() -> None:
    """pipeline_runs_total increments with tenant and state labels."""
    _init_otel_with_prometheus()
    from expose.observability import metrics as obs_metrics  # noqa: PLC0415

    obs_metrics.pipeline_runs_total.add(
        1, {"tenant_id": "tenant-abc", "final_state": "completed"},
    )
    obs_metrics.pipeline_runs_total.add(
        1, {"tenant_id": "tenant-abc", "final_state": "failed"},
    )

    app = _make_test_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/metrics")

    body = resp.text
    assert "expose_pipeline_runs" in body


@pytest.mark.anyio
async def test_pipeline_entities_discovered_counter() -> None:
    """pipeline_entities_discovered_total records entity types."""
    _init_otel_with_prometheus()
    from expose.observability import metrics as obs_metrics  # noqa: PLC0415

    obs_metrics.pipeline_entities_discovered_total.add(
        10, {"tenant_id": "tenant-xyz", "entity_type": "Domain"},
    )
    obs_metrics.pipeline_entities_discovered_total.add(
        3, {"tenant_id": "tenant-xyz", "entity_type": "IPAddress"},
    )

    app = _make_test_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/metrics")

    body = resp.text
    assert "expose_pipeline_entities_discovered" in body


@pytest.mark.anyio
async def test_pipeline_lead_score_histogram() -> None:
    """pipeline_lead_score histogram records by priority tier."""
    _init_otel_with_prometheus()
    from expose.observability import metrics as obs_metrics  # noqa: PLC0415

    obs_metrics.pipeline_lead_score.record(0.92, {"priority_tier": "critical"})
    obs_metrics.pipeline_lead_score.record(0.65, {"priority_tier": "high"})
    obs_metrics.pipeline_lead_score.record(0.30, {"priority_tier": "medium"})

    app = _make_test_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/metrics")

    body = resp.text
    assert "expose_pipeline_lead_score" in body


@pytest.mark.anyio
async def test_api_requests_counter() -> None:
    """api_requests_total increments with method/path/status labels."""
    _init_otel_with_prometheus()
    from expose.observability import metrics as obs_metrics  # noqa: PLC0415

    obs_metrics.api_requests_total.add(
        1, {"method": "GET", "path": "/v1/tenants", "status_code": "200"},
    )
    obs_metrics.api_requests_total.add(
        1, {"method": "POST", "path": "/v1/runs", "status_code": "201"},
    )

    app = _make_test_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get("/metrics")

    body = resp.text
    assert "expose_api_requests" in body
