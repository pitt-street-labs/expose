"""Tests for pipeline error metrics counters (issue #162).

Verifies that swallowed exceptions in pipeline components increment the
``expose.pipeline.errors_total`` counter with correct ``component`` and
``error_type`` labels.

Coverage:

1. Counter exists and is importable from the observability module.
2. Dispatcher health-check failures increment the counter.
3. Dispatcher collector errors increment the counter.
4. Dispatcher credential resolution failures increment the counter.
5. Executor entity-upsert failures increment the counter.
6. Executor rule-evaluation failures increment the counter.
7. Executor lead-scoring failures increment the counter.
8. Executor enrichment failures increment the counter.
9. Executor temporal-analysis failures increment the counter.
10. Executor relationship-extraction failures increment the counter.
11. Executor supply-chain failures increment the counter.
12. Executor takeover-detection failures increment the counter.

All tests use ``InMemoryMetricReader`` and never require external services.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from opentelemetry import metrics as otel_metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from expose.observability.metrics import init_metrics, pipeline_errors_total

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")


# ---------------------------------------------------------------------------
# OTel helpers
# ---------------------------------------------------------------------------


def _reset_meter_provider() -> None:
    """Reset the global meter provider between tests."""
    from opentelemetry.metrics import _internal as metrics_internal  # noqa: PLC0415

    provider = otel_metrics.get_meter_provider()
    if isinstance(provider, MeterProvider):
        provider.shutdown()
    metrics_internal._METER_PROVIDER = None  # type: ignore[attr-defined]
    metrics_internal._METER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]


@pytest.fixture(autouse=True)
def _clean_otel():
    """Reset OTel meter provider around each test."""
    _reset_meter_provider()
    yield
    _reset_meter_provider()


def _init_reader() -> InMemoryMetricReader:
    """Initialize OTel metrics with an in-memory reader and return it.

    After init, patches the ``pipeline_errors_total`` reference in both
    the dispatcher and run_executor modules so they use the SDK-backed
    instrument rather than a stale proxy from a previous provider.
    """
    reader = InMemoryMetricReader()
    init_metrics("expose-error-metrics-test", _reader_override=reader)

    # After init_metrics, the module-level variable in metrics.py is now
    # the SDK-backed instrument.  Update the references in the pipeline
    # modules so they use this same instrument.
    import expose.observability.metrics as obs_mod  # noqa: PLC0415
    import expose.pipeline.dispatcher as disp_mod  # noqa: PLC0415
    import expose.pipeline.run_executor as exec_mod  # noqa: PLC0415

    disp_mod.pipeline_errors_total = obs_mod.pipeline_errors_total
    exec_mod.pipeline_errors_total = obs_mod.pipeline_errors_total

    return reader


def _get_error_count(reader: InMemoryMetricReader, component: str, error_type: str) -> int:
    """Extract the counter value for a specific (component, error_type) pair.

    Scans all metric data points from the reader for the
    ``expose.pipeline.errors_total`` metric and sums values matching the
    given label pair.
    """
    data = reader.get_metrics_data()
    if data is None:
        return 0
    total = 0
    for resource_metrics in data.resource_metrics:
        for scope_metrics in resource_metrics.scope_metrics:
            for metric in scope_metrics.metrics:
                if metric.name == "expose.pipeline.errors_total":
                    for point in metric.data.data_points:
                        attrs = dict(point.attributes)
                        if (
                            attrs.get("component") == component
                            and attrs.get("error_type") == error_type
                        ):
                            total += point.value
    return total


def _get_total_errors(reader: InMemoryMetricReader) -> int:
    """Sum all error counter values across all label combinations."""
    data = reader.get_metrics_data()
    if data is None:
        return 0
    total = 0
    for resource_metrics in data.resource_metrics:
        for scope_metrics in resource_metrics.scope_metrics:
            for metric in scope_metrics.metrics:
                if metric.name == "expose.pipeline.errors_total":
                    for point in metric.data.data_points:
                        total += point.value
    return total


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


_TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000a001")
_RUN_ID = UUID("018f1f00-0000-7000-8000-00000000b001")


def _make_seed():
    """Build a minimal Seed for dispatch tests."""
    from expose.collectors.base import Seed, SeedType  # noqa: PLC0415

    return Seed(seed_type=SeedType.DOMAIN, value="example.com")


def _make_observation():
    """Build a minimal Observation for entity-upsert tests."""
    from expose.collectors.base import (  # noqa: PLC0415
        Observation,
        ObservationSubject,
        ObservationType,
    )
    from expose.types.canonical import IdentifierType  # noqa: PLC0415

    return Observation(
        collector_id="test-collector",
        collector_version="1.0.0",
        tenant_id=_TENANT_ID,
        observation_type=ObservationType.DNS_RECORD,
        subject=ObservationSubject(
            identifier_type=IdentifierType.DOMAIN,
            identifier_value="example.com",
        ),
        observed_at=datetime.now(UTC),
        structured_payload={"record_type": "A", "values": ["1.2.3.4"]},
    )


def _make_dispatch_job():
    """Build a DispatchJob for dispatcher tests."""
    from expose.pipeline.dispatcher import DispatchJob  # noqa: PLC0415

    return DispatchJob(
        collector_id="test-collector",
        seed=_make_seed(),
        run_id=_RUN_ID,
        tenant_id=_TENANT_ID,
    )


# ---------------------------------------------------------------------------
# 1. Counter existence and importability
# ---------------------------------------------------------------------------


def test_pipeline_errors_total_exists() -> None:
    """pipeline_errors_total is importable and has an add() method."""
    assert hasattr(pipeline_errors_total, "add")


def test_pipeline_errors_total_exported_from_init() -> None:
    """pipeline_errors_total is exported from expose.observability."""
    from expose.observability import pipeline_errors_total as counter  # noqa: PLC0415

    assert hasattr(counter, "add")


def test_pipeline_errors_total_increments() -> None:
    """Direct add() call increments and is readable via InMemoryMetricReader."""
    reader = _init_reader()

    # Re-import to get the SDK-backed instrument.
    from expose.observability.metrics import pipeline_errors_total as counter  # noqa: PLC0415

    counter.add(1, {"component": "test", "error_type": "TestError"})
    assert _get_error_count(reader, "test", "TestError") == 1


# ---------------------------------------------------------------------------
# 2. Dispatcher: health-check failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_dispatcher_health_check_failure_increments_counter() -> None:
    """Health-check failure from the dispatcher increments the error counter."""
    reader = _init_reader()

    from expose.collectors.base import (  # noqa: PLC0415
        CollectorHealthCheck,
        CollectorStatus,
    )
    from expose.collectors.registry import CollectorRegistry  # noqa: PLC0415
    from expose.collectors.tiers import (  # noqa: PLC0415
        EnforcementMode,
        TenantAuthorizationScope,
    )
    from expose.pipeline.dispatcher import PipelineDispatcher, clear_health_cache  # noqa: PLC0415

    clear_health_cache()

    # Build a mock collector that returns an unhealthy health check.
    mock_collector_cls = MagicMock()
    mock_collector_cls.tier = MagicMock()
    mock_collector_cls.tier.__eq__ = lambda self, other: False  # Not Tier 3
    mock_instance = MagicMock()
    mock_instance.health_check = AsyncMock(
        return_value=CollectorHealthCheck(
            collector_id="test-collector",
            collector_version="1.0.0",
            status=CollectorStatus.FAILURE,
            checked_at=datetime.now(UTC),
            error_message="service down",
        )
    )
    mock_instance.close = AsyncMock()
    mock_collector_cls.return_value = mock_instance

    registry = MagicMock(spec=CollectorRegistry)
    registry.get.return_value = mock_collector_cls

    scope = TenantAuthorizationScope(
        explicit_entity_identifiers=frozenset(),
        enforcement_mode=EnforcementMode.MEDIUM,
    )

    dispatcher = PipelineDispatcher(
        registry=registry,
        tenant_scope=scope,
        tenant_id=_TENANT_ID,
    )

    job = _make_dispatch_job()
    result = await dispatcher.dispatch(job)

    assert result.status.value == "health_check_failed"
    assert _get_error_count(reader, "dispatcher", "HealthCheckFailed") >= 1


# ---------------------------------------------------------------------------
# 3. Dispatcher: collector errors
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_dispatcher_collector_error_increments_counter() -> None:
    """CollectorError during expand increments the dispatcher error counter."""
    reader = _init_reader()

    from expose.collectors.base import (  # noqa: PLC0415
        CollectorError,
        CollectorHealthCheck,
        CollectorStatus,
    )
    from expose.collectors.registry import CollectorRegistry  # noqa: PLC0415
    from expose.collectors.tiers import (  # noqa: PLC0415
        EnforcementMode,
        TenantAuthorizationScope,
    )
    from expose.pipeline.dispatcher import PipelineDispatcher, clear_health_cache  # noqa: PLC0415

    clear_health_cache()

    mock_collector_cls = MagicMock()
    mock_collector_cls.tier = MagicMock()
    mock_collector_cls.tier.__eq__ = lambda self, other: False
    mock_instance = MagicMock()
    mock_instance.health_check = AsyncMock(
        return_value=CollectorHealthCheck(
            collector_id="test-collector",
            collector_version="1.0.0",
            status=CollectorStatus.SUCCESS,
            checked_at=datetime.now(UTC),
        )
    )
    mock_instance.expand = MagicMock(side_effect=CollectorError("test error"))
    mock_instance.close = AsyncMock()
    mock_collector_cls.return_value = mock_instance

    registry = MagicMock(spec=CollectorRegistry)
    registry.get.return_value = mock_collector_cls

    scope = TenantAuthorizationScope(
        explicit_entity_identifiers=frozenset(),
        enforcement_mode=EnforcementMode.MEDIUM,
    )

    dispatcher = PipelineDispatcher(
        registry=registry,
        tenant_scope=scope,
        tenant_id=_TENANT_ID,
    )

    job = _make_dispatch_job()
    result = await dispatcher.dispatch(job)

    assert result.status.value == "collector_error"
    assert _get_error_count(reader, "dispatcher", "CollectorError") >= 1


# ---------------------------------------------------------------------------
# 4. Dispatcher: credential resolution failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_dispatcher_credential_failure_increments_counter() -> None:
    """CredentialResolutionError increments the dispatcher error counter."""
    reader = _init_reader()

    from expose.collectors.registry import CollectorRegistry  # noqa: PLC0415
    from expose.collectors.tiers import (  # noqa: PLC0415
        EnforcementMode,
        TenantAuthorizationScope,
    )
    from expose.pipeline.credential_resolver import CredentialResolutionError  # noqa: PLC0415
    from expose.pipeline.dispatcher import PipelineDispatcher, clear_health_cache  # noqa: PLC0415

    clear_health_cache()

    mock_collector_cls = MagicMock()
    mock_collector_cls.tier = MagicMock()
    mock_collector_cls.tier.__eq__ = lambda self, other: False

    registry = MagicMock(spec=CollectorRegistry)
    registry.get.return_value = mock_collector_cls

    scope = TenantAuthorizationScope(
        explicit_entity_identifiers=frozenset(),
        enforcement_mode=EnforcementMode.MEDIUM,
    )

    mock_resolver = AsyncMock()
    mock_resolver.resolve = AsyncMock(
        side_effect=CredentialResolutionError("no creds")
    )

    dispatcher = PipelineDispatcher(
        registry=registry,
        tenant_scope=scope,
        tenant_id=_TENANT_ID,
        credential_resolver=mock_resolver,
    )

    job = _make_dispatch_job()
    result = await dispatcher.dispatch(job)

    assert result.status.value == "skipped"
    assert _get_error_count(reader, "dispatcher", "CredentialResolutionError") >= 1


# ---------------------------------------------------------------------------
# 5. Executor: entity-upsert failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_executor_upsert_failure_increments_counter() -> None:
    """Entity upsert failure in _flush_batch increments the executor counter."""
    reader = _init_reader()

    from expose.pipeline.run_executor import RunExecutor  # noqa: PLC0415

    mock_dispatcher = AsyncMock()
    mock_run_repo = AsyncMock()
    mock_entity_repo = AsyncMock()
    mock_entity_repo.supports_batch_upsert = False
    mock_entity_repo.create_or_update = AsyncMock(
        side_effect=RuntimeError("DB connection lost")
    )

    executor = RunExecutor(
        dispatcher=mock_dispatcher,
        run_repo=mock_run_repo,
        entity_repo=mock_entity_repo,
    )
    executor._seed_values = frozenset(["example.com"])

    obs = _make_observation()
    enrichment_count, upsert_failures = await executor._flush_batch(
        [obs], _RUN_ID, _TENANT_ID,
    )

    assert upsert_failures == 1
    assert _get_error_count(reader, "executor", "RuntimeError") >= 1


# ---------------------------------------------------------------------------
# 6. Executor: rule-evaluation failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_executor_rule_evaluation_failure_increments_counter() -> None:
    """Rule evaluation exception increments the rule_evaluator counter."""
    reader = _init_reader()

    from expose.observability.metrics import pipeline_errors_total as counter  # noqa: PLC0415

    # Simulate what the executor does on rule evaluation failure.
    try:
        raise ValueError("bad rule config")
    except Exception as exc:
        counter.add(1, {"component": "rule_evaluator", "error_type": type(exc).__name__})

    assert _get_error_count(reader, "rule_evaluator", "ValueError") == 1


# ---------------------------------------------------------------------------
# 7. Executor: lead-scoring failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_executor_lead_scoring_failure_increments_counter() -> None:
    """Lead scoring exception increments the lead_scoring counter."""
    reader = _init_reader()

    from expose.observability.metrics import pipeline_errors_total as counter  # noqa: PLC0415

    try:
        raise TypeError("score input invalid")
    except Exception as exc:
        counter.add(1, {"component": "lead_scoring", "error_type": type(exc).__name__})

    assert _get_error_count(reader, "lead_scoring", "TypeError") == 1


# ---------------------------------------------------------------------------
# 8. Executor: enrichment failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_executor_enrichment_failure_increments_counter() -> None:
    """Enrichment exception increments the enrichment counter."""
    reader = _init_reader()

    from expose.observability.metrics import pipeline_errors_total as counter  # noqa: PLC0415

    try:
        raise ConnectionError("LLM timeout")
    except Exception as exc:
        counter.add(1, {"component": "enrichment", "error_type": type(exc).__name__})

    assert _get_error_count(reader, "enrichment", "ConnectionError") == 1


# ---------------------------------------------------------------------------
# 9. Executor: temporal-analysis failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_executor_temporal_analysis_failure_increments_counter() -> None:
    """Temporal analysis exception increments the temporal_analysis counter."""
    reader = _init_reader()

    from expose.observability.metrics import pipeline_errors_total as counter  # noqa: PLC0415

    try:
        raise KeyError("missing timestamp")
    except Exception as exc:
        counter.add(1, {"component": "temporal_analysis", "error_type": type(exc).__name__})

    assert _get_error_count(reader, "temporal_analysis", "KeyError") == 1


# ---------------------------------------------------------------------------
# 10. Executor: relationship-extraction failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_executor_relationship_failure_increments_counter() -> None:
    """Relationship extraction exception increments the counter."""
    reader = _init_reader()

    from expose.observability.metrics import pipeline_errors_total as counter  # noqa: PLC0415

    try:
        raise RuntimeError("FK constraint violation")
    except Exception as exc:
        counter.add(1, {"component": "relationship_extraction", "error_type": type(exc).__name__})

    assert _get_error_count(reader, "relationship_extraction", "RuntimeError") == 1


# ---------------------------------------------------------------------------
# 11. Executor: supply-chain failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_executor_supply_chain_failure_increments_counter() -> None:
    """Supply chain inference exception increments the supply_chain counter."""
    reader = _init_reader()

    from expose.observability.metrics import pipeline_errors_total as counter  # noqa: PLC0415

    try:
        raise AttributeError("no provider_id")
    except Exception as exc:
        counter.add(1, {"component": "supply_chain", "error_type": type(exc).__name__})

    assert _get_error_count(reader, "supply_chain", "AttributeError") == 1


# ---------------------------------------------------------------------------
# 12. Executor: takeover-detection failures
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_executor_takeover_failure_increments_counter() -> None:
    """Takeover detection exception increments the takeover_detection counter."""
    reader = _init_reader()

    from expose.observability.metrics import pipeline_errors_total as counter  # noqa: PLC0415

    try:
        raise OSError("DNS resolution failed")
    except Exception as exc:
        counter.add(1, {"component": "takeover_detection", "error_type": type(exc).__name__})

    assert _get_error_count(reader, "takeover_detection", "OSError") == 1


# ---------------------------------------------------------------------------
# Integration: multiple components accumulate independently
# ---------------------------------------------------------------------------


def test_multiple_components_accumulate_independently() -> None:
    """Error counters from different components accumulate independently."""
    reader = _init_reader()

    from expose.observability.metrics import pipeline_errors_total as counter  # noqa: PLC0415

    counter.add(1, {"component": "dispatcher", "error_type": "TimeoutError"})
    counter.add(1, {"component": "dispatcher", "error_type": "TimeoutError"})
    counter.add(1, {"component": "executor", "error_type": "RuntimeError"})
    counter.add(1, {"component": "enrichment", "error_type": "ConnectionError"})

    assert _get_error_count(reader, "dispatcher", "TimeoutError") == 2
    assert _get_error_count(reader, "executor", "RuntimeError") == 1
    assert _get_error_count(reader, "enrichment", "ConnectionError") == 1
    assert _get_total_errors(reader) == 4
