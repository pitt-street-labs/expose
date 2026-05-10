"""Tests for the EXPOSE NATS JetStream broker (per W1.A scope).

Five tests:

1. ``test_jobmessage_roundtrip`` — pure unit: bytes → JobMessage → bytes
   round-trips losslessly. No NATS required; runs on the unit-only loop.
2. ``test_ensure_streams_idempotent`` — connect, run setup twice, verify
   only one stream/consumer exists. Integration (needs NATS).
3. ``test_publish_and_consume_jobmessage`` — dispatcher publishes, a tiny
   ``Worker`` subclass receives the parsed envelope. Integration.
4. ``test_worker_acks_on_success_naks_on_failure`` — handler raises → nak
   (message redelivered); handler succeeds → ack (message removed).
   Integration.
5. ``test_subject_namespacing_carries_tenant`` — published subject of the
   form ``expose.runs.dispatch.<tenant_id>.<collector_id>`` is preserved
   through the broker so consumers can route on tenant. Integration.

Integration tests use the session-scoped ``nats_container`` fixture from
``tests/conftest.py`` (testcontainers, JetStream-enabled via ``-js``).
They are marked ``@pytest.mark.integration`` so the unit-only loop
(``pytest -m "not integration"``) skips them cleanly.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest
from nats.aio.msg import Msg

from expose.broker import (
    CONSUMER_NAME,
    STREAM_NAME,
    JobMessage,
    NatsBrokerClient,
    Worker,
    ensure_streams_and_consumers,
)

# Per-test filter override. Pyproject's global ``filterwarnings = ["error"]``
# would otherwise upgrade two DeprecationWarnings emitted by the third-party
# ``testcontainers[nats]`` extra into errors and skip every integration test
# in this module:
#
#   1. ``testcontainers/nats/__init__.py:62`` — uses the deprecated
#      ``@wait_container_is_ready`` decorator at *class-definition* time
#      (fires when the conftest fixture imports the module).
#   2. ``testcontainers/core/waiting_utils.py:300`` — ``wait_for_logs`` with
#      a string predicate is also deprecated (fires inside
#      ``container.start()``).
#
# The scope is narrow — only this module's tests — so the strict default
# remains in force everywhere else. Remove once ``testcontainers[nats]``
# adopts the structured wait strategies.
pytestmark = [
    pytest.mark.filterwarnings("default::DeprecationWarning"),
]

# === Synthetic IDs (UUIDv7-ish; deterministic for grep-friendly failures) =====
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000B001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000B002")
TENANT_ID_ALT = UUID("018f1f00-0000-7000-8000-00000000B003")


def _make_job(
    *,
    tenant_id: UUID = TENANT_ID,
    run_id: UUID = RUN_ID,
    collector_id: str = "ct-crtsh",
    seed: dict[str, Any] | None = None,
    attempt: int = 1,
) -> JobMessage:
    """Construct a JobMessage with sensible defaults for tests.

    Centralised so tests assert on field-level changes, not boilerplate.
    """
    return JobMessage(
        tenant_id=tenant_id,
        run_id=run_id,
        collector_id=collector_id,
        seed=seed if seed is not None else {"seed_type": "domain", "value": "acme.example"},
        dispatched_at=datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
        attempt=attempt,
    )


# === Test 1 — pure unit ======================================================
def test_jobmessage_roundtrip() -> None:
    """JobMessage -> bytes -> JobMessage preserves every field.

    Round-trip is the contract the broker layer relies on at every
    publish/consume hop. If this regresses, every integration test will
    cascade-fail in opaque ways — keeping it as a fast unit test surfaces
    the failure cleanly.
    """
    original = _make_job(
        seed={"seed_type": "domain", "value": "api.acme.example", "properties": {"depth": 2}},
        attempt=3,
    )
    payload = original.to_bytes()

    # Wire format must be UTF-8 JSON (per JobMessage.to_bytes contract).
    assert payload.startswith(b"{") and payload.endswith(b"}"), payload[:50]

    reconstructed = JobMessage.from_bytes(payload)

    assert reconstructed == original
    assert reconstructed.tenant_id == TENANT_ID
    assert reconstructed.run_id == RUN_ID
    assert reconstructed.collector_id == "ct-crtsh"
    assert reconstructed.seed == {
        "seed_type": "domain",
        "value": "api.acme.example",
        "properties": {"depth": 2},
    }
    assert reconstructed.attempt == 3
    assert reconstructed.dispatched_at == original.dispatched_at


# === Integration helpers =====================================================
async def _connect(nats_uri: str) -> NatsBrokerClient:
    """Connect a NatsBrokerClient against the test container.

    Caller is responsible for closing via ``await client.close()`` (or using
    the async context manager). Pulled out as a helper so each test reads
    linearly.
    """
    client = NatsBrokerClient(servers=[nats_uri], name="expose-broker-test")
    await client.connect()
    return client


class _RecordingWorker(Worker):
    """Test-only worker that records every (msg, job) pair it processes.

    Used by integration tests to assert the pull/deserialize/dispatch flow
    without needing a real collector implementation. Exposes an
    ``asyncio.Event`` (``count_reached``) that tests await on, set whenever
    the cumulative receipt count reaches a configured target. This lets the
    test loop avoid polling and stay event-driven.
    """

    def __init__(
        self,
        client: NatsBrokerClient,
        subject_pattern: str,
        consumer: str,
        *,
        fail_n_times: int = 0,
        target_count: int = 1,
    ) -> None:
        super().__init__(client, subject_pattern, consumer)
        self.received: list[tuple[Msg, JobMessage]] = []
        self.subjects: list[str] = []
        self._failures_remaining = fail_n_times
        self._target_count = target_count
        self.count_reached = asyncio.Event()

    async def handle(self, msg: Msg, job: JobMessage) -> None:
        self.received.append((msg, job))
        self.subjects.append(msg.subject)
        if len(self.received) >= self._target_count:
            self.count_reached.set()
        if self._failures_remaining > 0:
            self._failures_remaining -= 1
            raise RuntimeError("simulated transient failure")


async def _run_worker_until(
    worker: _RecordingWorker,
    *,
    deadline_seconds: float = 10.0,
) -> None:
    """Run the worker until it signals ``count_reached``, then shut down.

    Event-driven (no polling): waits on ``worker.count_reached`` which the
    worker sets once it has processed the configured ``target_count`` of
    messages. ``TimeoutError`` from ``asyncio.timeout`` propagates if the
    deadline expires before the target is reached.
    """
    run_task = asyncio.create_task(worker.run())
    try:
        async with asyncio.timeout(deadline_seconds):
            await worker.count_reached.wait()
    finally:
        worker.request_shutdown()
        # Allow the loop to drain its current pull and exit cleanly.
        with contextlib.suppress(asyncio.CancelledError):
            await run_task


# === Test 2 — idempotent setup ===============================================
@pytest.mark.integration
async def test_ensure_streams_idempotent(nats_container: Any) -> None:
    """Running ``ensure_streams_and_consumers`` twice leaves a single stream
    + consumer and does not raise.

    Idempotency matters because every worker startup path may invoke setup
    defensively, and the test suite itself reuses the session-scoped NATS
    container across multiple integration tests.
    """
    nats_uri = nats_container.nats_uri()
    client = await _connect(nats_uri)
    try:
        js = await client.jetstream()

        await ensure_streams_and_consumers(js)
        await ensure_streams_and_consumers(js)

        stream_info = await js.stream_info(STREAM_NAME)
        assert stream_info.config.name == STREAM_NAME
        assert "expose.runs.dispatch.>" in stream_info.config.subjects

        consumer_info = await js.consumer_info(STREAM_NAME, CONSUMER_NAME)
        assert consumer_info.config.durable_name == CONSUMER_NAME

        # Stream count: exactly one stream named EXPOSE_RUNS_DISPATCH.
        all_streams = await js.streams_info()
        names = [s.config.name for s in all_streams]
        assert names.count(STREAM_NAME) == 1, names
    finally:
        await client.close()


# === Test 3 — publish + consume ==============================================
@pytest.mark.integration
async def test_publish_and_consume_jobmessage(nats_container: Any) -> None:
    """A worker subclass receives JobMessages dispatched onto the stream.

    This is the end-to-end smoke for the dispatcher/worker contract: the
    envelope reaches the worker side intact, parsed back into a JobMessage
    matching what the dispatcher published.
    """
    nats_uri = nats_container.nats_uri()
    client = await _connect(nats_uri)
    try:
        js = await client.jetstream()
        await ensure_streams_and_consumers(js)

        # Drain any stale messages from prior tests sharing the session
        # container so this test only sees its own publishes.
        await js.purge_stream(STREAM_NAME)

        worker = _RecordingWorker(
            client,
            subject_pattern="expose.runs.dispatch.>",
            consumer=CONSUMER_NAME,
            target_count=1,
        )

        job = _make_job()
        subject = f"expose.runs.dispatch.{TENANT_ID}.{job.collector_id}"
        await client.publish(subject, job)

        await _run_worker_until(worker)

        assert len(worker.received) == 1
        _, received_job = worker.received[0]
        assert received_job == job
    finally:
        await client.close()


# === Test 4 — ack / nak ======================================================
@pytest.mark.integration
async def test_worker_acks_on_success_naks_on_failure(nats_container: Any) -> None:
    """Handler that raises -> message is nak'd and re-delivered; handler that
    returns normally -> message is acked and removed from the WORK_QUEUE.

    Verified end-to-end:

    1. Publish one message; worker is configured to fail handle once.
    2. Worker receives the message twice — once for the failure (nak ->
       redelivery), once for the success (ack -> removal).
    3. After the second receipt, the stream's pending count is zero,
       confirming the second receipt was acked (not nak'd into oblivion).
    """
    nats_uri = nats_container.nats_uri()
    client = await _connect(nats_uri)
    try:
        js = await client.jetstream()
        await ensure_streams_and_consumers(js)
        await js.purge_stream(STREAM_NAME)

        worker = _RecordingWorker(
            client,
            subject_pattern="expose.runs.dispatch.>",
            consumer=CONSUMER_NAME,
            fail_n_times=1,
            target_count=2,
        )

        job = _make_job()
        subject = f"expose.runs.dispatch.{TENANT_ID}.{job.collector_id}"
        await client.publish(subject, job)

        # Expect 2 receipts: failure (nak -> redelivery) then success (ack).
        await _run_worker_until(worker, deadline_seconds=20.0)

        assert len(worker.received) == 2
        assert worker.received[0][1] == worker.received[1][1] == job

        # After the successful ack, no messages remain in the stream.
        # (WORK_QUEUE retention removes acked messages.)
        stream_info = await js.stream_info(STREAM_NAME)
        assert stream_info.state.messages == 0, (
            f"Expected 0 pending messages after ack; got {stream_info.state.messages}"
        )
    finally:
        await client.close()


# === Test 5 — subject namespacing ============================================
@pytest.mark.integration
async def test_subject_namespacing_carries_tenant(nats_container: Any) -> None:
    """The subject ``expose.runs.dispatch.<tenant_id>.<collector_id>`` is
    preserved through the broker, so consumers can route on tenant.

    This protects the multi-tenant invariant per ADR-007: tenant context
    flows in two ways (envelope + subject), and the subject convention is
    what enables future per-tenant subscription scoping without protocol
    changes.
    """
    nats_uri = nats_container.nats_uri()
    client = await _connect(nats_uri)
    try:
        js = await client.jetstream()
        await ensure_streams_and_consumers(js)
        await js.purge_stream(STREAM_NAME)

        worker = _RecordingWorker(
            client,
            subject_pattern="expose.runs.dispatch.>",
            consumer=CONSUMER_NAME,
            target_count=2,
        )

        # Publish two jobs under different tenants and different collectors.
        job_a = _make_job(tenant_id=TENANT_ID, collector_id="ct-crtsh")
        subject_a = f"expose.runs.dispatch.{TENANT_ID}.ct-crtsh"
        await client.publish(subject_a, job_a)

        job_b = _make_job(tenant_id=TENANT_ID_ALT, collector_id="cloud-aws-ranges")
        subject_b = f"expose.runs.dispatch.{TENANT_ID_ALT}.cloud-aws-ranges"
        await client.publish(subject_b, job_b)

        await _run_worker_until(worker)

        # Subjects received must match the published subjects bit-for-bit.
        assert subject_a in worker.subjects
        assert subject_b in worker.subjects

        # Envelope tenant_id matches the subject's tenant_id token.
        seen_by_tenant: dict[UUID, str] = {}
        for msg, job in worker.received:
            seen_by_tenant[job.tenant_id] = msg.subject
        assert seen_by_tenant[TENANT_ID] == subject_a
        assert seen_by_tenant[TENANT_ID_ALT] == subject_b
    finally:
        await client.close()
