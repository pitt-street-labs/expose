"""Tests for the NATS-mediated distributed dispatcher (NatsDispatcher + CollectorWorker).

Seven unit tests — no real NATS server required. All NATS interactions are
mocked via ``AsyncMock``.

Coverage:

1.  ``test_dispatch_publishes_correct_subject`` — NatsDispatcher builds the
    correct ``expose.runs.dispatch.<tenant_id>.<collector_id>`` subject.
2.  ``test_dispatch_timeout_returns_error_result`` — NATS request timeout
    returns a DispatchResult with status ``collector_error`` and message
    ``timeout``.
3.  ``test_dispatch_success_round_trip`` — Happy path: dispatcher publishes,
    mock reply contains observations, dispatcher returns them parsed.
4.  ``test_collector_worker_calls_dispatcher_and_publishes_result`` —
    CollectorWorker delegates to PipelineDispatcher and publishes the
    serialized result on the reply subject.
5.  ``test_nats_dispatcher_result_round_trip`` — NatsDispatcherResult
    serializes to bytes and deserializes back losslessly.
6.  ``test_nats_dispatcher_result_rejects_extra_fields`` — Pydantic
    ``extra="forbid"`` rejects unknown fields.
7.  ``test_collector_worker_no_reply_subject`` — When the message has no
    reply subject, the worker still completes without publishing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from nats.errors import TimeoutError as NatsTimeoutError
from pydantic import ValidationError

from expose.broker.types import JobMessage
from expose.collectors.base import (
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.pipeline.dispatcher import DispatchResult as LocalDispatchResult
from expose.pipeline.dispatcher import DispatchStatus
from expose.pipeline.nats_dispatcher import (
    CollectorWorker,
    NatsDispatcher,
    NatsDispatcherResult,
)
from expose.pipeline.run_executor import DispatchJob
from expose.types.canonical import ExtendedIdentifierType

# === Synthetic IDs (UUIDv7-style, deterministic, greppable) ==================
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000E001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000E002")

_NOW = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)

# Suppress testcontainers DeprecationWarnings (consistent with test_broker.py).
pytestmark = [
    pytest.mark.filterwarnings("default::DeprecationWarning"),
]


# === Helpers ==================================================================


def _make_seed() -> Seed:
    """Build a minimal Seed for test assertions."""
    return Seed(seed_type=SeedType.DOMAIN, value="acme.example")


def _make_dispatch_job() -> DispatchJob:
    """Build a DispatchJob with sensible defaults for tests."""
    return DispatchJob(
        collector_id="ct-crtsh",
        seed=_make_seed(),
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
    )


def _make_observation() -> Observation:
    """Build a minimal Observation for test assertions."""
    return Observation(
        collector_id="ct-crtsh",
        collector_version="1.0.0",
        tenant_id=TENANT_ID,
        observation_type=ObservationType.CT_LOG_ENTRY,
        subject=ObservationSubject(
            identifier_type=ExtendedIdentifierType.DOMAIN,
            identifier_value="acme.example",
        ),
        observed_at=_NOW,
    )


def _mock_broker_client(*, response_data: bytes | None = None) -> MagicMock:
    """Build a mock NatsBrokerClient with a mock raw NATS client underneath.

    If ``response_data`` is provided, the raw client's ``request`` method
    returns a mock Msg with that data. Otherwise ``request`` must be
    configured per-test.
    """
    mock_client = MagicMock()
    mock_raw = AsyncMock()
    mock_client._client = mock_raw

    if response_data is not None:
        reply_msg = SimpleNamespace(data=response_data)
        mock_raw.request = AsyncMock(return_value=reply_msg)

    return mock_client


# === Test 1 — correct subject ================================================


async def test_dispatch_publishes_correct_subject() -> None:
    """NatsDispatcher publishes to expose.runs.dispatch.<tenant_id>.<collector_id>."""
    wire_result = NatsDispatcherResult(
        status="success",
        observations=[],
        duration_ms=10.0,
    )
    mock_client = _mock_broker_client(response_data=wire_result.to_bytes())
    dispatcher = NatsDispatcher(mock_client, timeout_seconds=5.0)

    job = _make_dispatch_job()
    await dispatcher.dispatch(job)

    expected_subject = f"expose.runs.dispatch.{TENANT_ID}.ct-crtsh"
    mock_client._client.request.assert_awaited_once()
    call_args = mock_client._client.request.call_args
    actual_subject = call_args[0][0]
    assert actual_subject == expected_subject


# === Test 2 — timeout handling ================================================


async def test_dispatch_timeout_returns_error_result() -> None:
    """NATS request timeout returns a collector_error result with 'timeout' message."""
    mock_client = _mock_broker_client()
    mock_client._client.request = AsyncMock(
        side_effect=NatsTimeoutError,
    )
    dispatcher = NatsDispatcher(mock_client, timeout_seconds=0.1)

    job = _make_dispatch_job()
    result = await dispatcher.dispatch(job)

    assert result.status == "collector_error"
    assert result.error_message == "timeout"
    assert result.duration_ms > 0
    assert result.observations == []


# === Test 3 — successful round-trip ==========================================


async def test_dispatch_success_round_trip() -> None:
    """Happy path: dispatcher publishes, mock reply has observations, result is correct."""
    obs = _make_observation()
    wire_result = NatsDispatcherResult(
        status="success",
        observations=[obs.model_dump(mode="json")],
        duration_ms=42.0,
    )
    mock_client = _mock_broker_client(response_data=wire_result.to_bytes())
    dispatcher = NatsDispatcher(mock_client, timeout_seconds=5.0)

    job = _make_dispatch_job()
    result = await dispatcher.dispatch(job)

    assert result.status == "success"
    assert len(result.observations) == 1
    assert result.observations[0].collector_id == "ct-crtsh"
    assert result.observations[0].subject.identifier_value == "acme.example"
    assert result.error_message is None


# === Test 4 — CollectorWorker delegates and publishes =========================


async def test_collector_worker_calls_dispatcher_and_publishes_result() -> None:
    """CollectorWorker calls the local dispatcher and publishes the result on msg.reply."""
    # Build the mock local dispatcher.
    obs = _make_observation()
    local_result = LocalDispatchResult(
        status=DispatchStatus.SUCCESS,
        observations=[obs],
        duration_ms=15.0,
    )
    mock_dispatcher = AsyncMock()
    mock_dispatcher.dispatch = AsyncMock(return_value=local_result)

    # Build the mock broker client (for publishing the reply).
    mock_client = MagicMock()
    mock_raw = AsyncMock()
    mock_client._client = mock_raw

    worker = CollectorWorker(
        mock_client,
        "expose.runs.dispatch.>",
        "dispatcher",
        dispatcher=mock_dispatcher,
    )

    # Build a mock NATS message with a reply subject.
    job_message = JobMessage(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        collector_id="ct-crtsh",
        seed={"seed_type": "domain", "value": "acme.example"},
        dispatched_at=_NOW,
    )
    mock_msg = MagicMock()
    mock_msg.reply = "_INBOX.abc123"

    await worker.handle(mock_msg, job_message)

    # The local dispatcher was called with a DispatchJob.
    mock_dispatcher.dispatch.assert_awaited_once()
    local_job = mock_dispatcher.dispatch.call_args[0][0]
    assert local_job.collector_id == "ct-crtsh"
    assert local_job.tenant_id == TENANT_ID
    assert local_job.seed.value == "acme.example"

    # A reply was published on the reply subject.
    mock_raw.publish.assert_awaited_once()
    publish_call = mock_raw.publish.call_args
    assert publish_call[0][0] == "_INBOX.abc123"

    # The reply payload is a valid NatsDispatcherResult.
    reply_bytes = publish_call[0][1]
    parsed_reply = NatsDispatcherResult.from_bytes(reply_bytes)
    assert parsed_reply.status == "success"
    assert len(parsed_reply.observations) == 1


# === Test 5 — NatsDispatcherResult round-trip ================================


def test_nats_dispatcher_result_round_trip() -> None:
    """NatsDispatcherResult -> bytes -> NatsDispatcherResult preserves all fields."""
    obs_dict = _make_observation().model_dump(mode="json")
    original = NatsDispatcherResult(
        status="success",
        observations=[obs_dict],
        error_message=None,
        duration_ms=99.5,
    )
    payload = original.to_bytes()
    assert payload.startswith(b"{") and payload.endswith(b"}")

    reconstructed = NatsDispatcherResult.from_bytes(payload)
    assert reconstructed == original
    assert reconstructed.status == "success"
    assert len(reconstructed.observations) == 1
    assert reconstructed.duration_ms == 99.5
    assert reconstructed.error_message is None


# === Test 6 — NatsDispatcherResult rejects extra fields ======================


def test_nats_dispatcher_result_rejects_extra_fields() -> None:
    """Pydantic extra='forbid' rejects unknown fields on the wire format."""
    with pytest.raises(ValidationError):
        NatsDispatcherResult(
            status="success",
            observations=[],
            duration_ms=1.0,
            unknown_field="should fail",  # type: ignore[call-arg]
        )


# === Test 7 — CollectorWorker with no reply subject ==========================


async def test_collector_worker_no_reply_subject() -> None:
    """When the message has no reply subject, the worker completes without publishing."""
    local_result = LocalDispatchResult(
        status=DispatchStatus.SUCCESS,
        observations=[],
        duration_ms=5.0,
    )
    mock_dispatcher = AsyncMock()
    mock_dispatcher.dispatch = AsyncMock(return_value=local_result)

    mock_client = MagicMock()
    mock_raw = AsyncMock()
    mock_client._client = mock_raw

    worker = CollectorWorker(
        mock_client,
        "expose.runs.dispatch.>",
        "dispatcher",
        dispatcher=mock_dispatcher,
    )

    job_message = JobMessage(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        collector_id="ct-crtsh",
        seed={"seed_type": "domain", "value": "acme.example"},
        dispatched_at=_NOW,
    )
    mock_msg = MagicMock()
    mock_msg.reply = ""  # Empty reply subject — worker-only / fire-and-forget mode.

    # Should not raise.
    await worker.handle(mock_msg, job_message)

    # The dispatcher was still called.
    mock_dispatcher.dispatch.assert_awaited_once()

    # No reply was published (empty reply subject).
    mock_raw.publish.assert_not_awaited()
