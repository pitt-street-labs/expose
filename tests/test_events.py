"""Tests for the SSE event bus and endpoint (``expose.api.events``).

Covers:

1.  RunEventBus publishes to subscribers
2.  Multiple subscribers receive the same event
3.  Subscribe returns events in order
4.  Unsubscribe stops receiving events
5.  Publish to run with no subscribers is a no-op
6.  RunEvent model validates correctly
7.  RunEventType has all expected values
8.  SSE endpoint returns text/event-stream content type
9.  SSE format is correct (event: ...\\ndata: ...\\n\\n)
10. Event bus is created on first access via get_event_bus
11. RunEvent rejects extra fields (frozen + extra=forbid)
12. Unsubscribe is idempotent (double-unsubscribe does not raise)
13. Subscribe context manager cleans up on exception
14. RUN_COMPLETED terminates the SSE stream
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from expose.api.events import (
    RunEvent,
    RunEventBus,
    RunEventType,
    get_event_bus,
    router,
)

# === Synthetic IDs ============================================================

TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000A001")
RUN_ID = UUID("018f1f00-0000-7000-8000-000000000001")
NOW = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)


# === Helpers ==================================================================


def _make_event(
    event_type: RunEventType = RunEventType.RUN_STARTED,
    run_id: UUID = RUN_ID,
    tenant_id: UUID = TENANT_ID,
    data: dict[str, object] | None = None,
) -> RunEvent:
    """Build a RunEvent with sensible defaults."""
    return RunEvent(
        event_type=event_type,
        run_id=run_id,
        tenant_id=tenant_id,
        timestamp=NOW,
        data=data or {},
    )


def _make_app() -> FastAPI:
    """Build a minimal FastAPI app with only the events router."""

    @asynccontextmanager
    async def _noop_lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield

    app = FastAPI(lifespan=_noop_lifespan)
    app.include_router(router)
    return app


# === 1. RunEventBus publishes to subscribers ==================================


async def test_bus_publishes_to_subscriber() -> None:
    """A single subscriber receives events published for its run_id."""
    bus = RunEventBus()
    event = _make_event()

    async with bus.subscribe(RUN_ID) as events:
        await bus.publish(event)
        received = await asyncio.wait_for(events.__anext__(), timeout=1.0)

    assert received == event
    assert received.event_type == RunEventType.RUN_STARTED
    assert received.run_id == RUN_ID


# === 2. Multiple subscribers receive the same event ===========================


async def test_bus_multiple_subscribers() -> None:
    """Two subscribers to the same run_id both receive the event."""
    bus = RunEventBus()
    event = _make_event()

    async with bus.subscribe(RUN_ID) as events_a, bus.subscribe(RUN_ID) as events_b:
        await bus.publish(event)
        received_a = await asyncio.wait_for(events_a.__anext__(), timeout=1.0)
        received_b = await asyncio.wait_for(events_b.__anext__(), timeout=1.0)

    assert received_a == event
    assert received_b == event


# === 3. Subscribe returns events in order =====================================


async def test_bus_events_in_order() -> None:
    """Events are delivered in FIFO order."""
    bus = RunEventBus()
    events_list = [
        _make_event(RunEventType.RUN_STARTED),
        _make_event(RunEventType.COLLECTOR_STARTED, data={"collector_id": "ct-crtsh"}),
        _make_event(
            RunEventType.COLLECTOR_COMPLETED,
            data={"collector_id": "ct-crtsh", "observation_count": 5},
        ),
    ]

    async with bus.subscribe(RUN_ID) as events:
        for ev in events_list:
            await bus.publish(ev)

        received = []
        for _ in range(3):
            item = await asyncio.wait_for(events.__anext__(), timeout=1.0)
            received.append(item)

    assert [e.event_type for e in received] == [
        RunEventType.RUN_STARTED,
        RunEventType.COLLECTOR_STARTED,
        RunEventType.COLLECTOR_COMPLETED,
    ]


# === 4. Unsubscribe stops receiving events ====================================


async def test_bus_unsubscribe() -> None:
    """After unsubscribe, the queue is removed and no longer receives events."""
    bus = RunEventBus()
    queue: asyncio.Queue[RunEvent] = asyncio.Queue()
    bus._subscribers[RUN_ID].append(queue)

    # Publish should reach the queue
    await bus.publish(_make_event())
    assert not queue.empty()

    # Drain and unsubscribe
    queue.get_nowait()
    bus.unsubscribe(RUN_ID, queue)

    # Publish after unsubscribe — no subscribers, no-op
    await bus.publish(_make_event())
    assert queue.empty()

    # The run key should be cleaned up
    assert RUN_ID not in bus._subscribers


# === 5. Publish to run with no subscribers is a no-op =========================


async def test_bus_publish_no_subscribers() -> None:
    """Publishing an event when nobody is listening does not raise."""
    bus = RunEventBus()
    event = _make_event()
    # Should not raise
    await bus.publish(event)


# === 6. RunEvent model validates correctly ====================================


def test_run_event_validates() -> None:
    """RunEvent roundtrips through construction and serialization."""
    event = _make_event(
        RunEventType.ENTITIES_DISCOVERED,
        data={
            "entities": [
                {
                    "id": str(uuid4()),
                    "label": "example.com",
                    "type": "domain",
                    "attribution_status": "unattributed",
                }
            ]
        },
    )
    assert event.event_type == RunEventType.ENTITIES_DISCOVERED
    assert event.run_id == RUN_ID
    assert event.tenant_id == TENANT_ID
    assert event.timestamp == NOW
    assert len(event.data["entities"]) == 1

    # Roundtrip through JSON
    payload = json.loads(event.model_dump_json())
    reconstructed = RunEvent.model_validate(payload)
    assert reconstructed == event


# === 7. RunEventType has all expected values ==================================


def test_event_type_members() -> None:
    """All seven event types are present in the enum."""
    expected = {
        "run_started",
        "collector_started",
        "collector_completed",
        "collector_failed",
        "entities_discovered",
        "attribution_updated",
        "run_completed",
    }
    actual = {member.value for member in RunEventType}
    assert actual == expected
    assert len(RunEventType) == 7


# === 8. SSE endpoint returns text/event-stream content type ===================


async def test_sse_endpoint_content_type() -> None:
    """The SSE endpoint returns Content-Type: text/event-stream."""
    app = _make_app()
    bus = RunEventBus()
    app.state.event_bus = bus

    # Publish a RUN_COMPLETED so the stream terminates
    async def _publish_after_connect() -> None:
        # Small delay so the client is connected before we publish
        await asyncio.sleep(0.05)
        await bus.publish(_make_event(RunEventType.RUN_COMPLETED))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        publish_task = asyncio.create_task(_publish_after_connect())
        resp = await client.get(
            f"/v1/tenants/{TENANT_ID}/runs/{RUN_ID}/events",
            timeout=5.0,
        )
        await publish_task

    assert resp.headers["content-type"] == "text/event-stream; charset=utf-8"


# === 9. SSE format is correct (event: ...\ndata: ...\n\n) =====================


async def test_sse_format() -> None:
    """SSE wire format matches ``event: <type>\\ndata: <json>\\n\\n``."""
    app = _make_app()
    bus = RunEventBus()
    app.state.event_bus = bus

    collector_event = _make_event(
        RunEventType.COLLECTOR_STARTED,
        data={"collector_id": "ct-crtsh"},
    )
    completed_event = _make_event(RunEventType.RUN_COMPLETED)

    async def _publish_sequence() -> None:
        await asyncio.sleep(0.05)
        await bus.publish(collector_event)
        await bus.publish(completed_event)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        publish_task = asyncio.create_task(_publish_sequence())
        resp = await client.get(
            f"/v1/tenants/{TENANT_ID}/runs/{RUN_ID}/events",
            timeout=5.0,
        )
        await publish_task

    body = resp.text
    # Split into individual SSE frames (separated by double newlines)
    frames = [f for f in body.split("\n\n") if f.strip()]
    assert len(frames) == 2

    # Validate first frame: collector_started
    lines_0 = frames[0].split("\n")
    assert lines_0[0] == "event: collector_started"
    assert lines_0[1].startswith("data: ")
    data_0 = json.loads(lines_0[1][len("data: ") :])
    assert data_0["event_type"] == "collector_started"
    assert data_0["data"]["collector_id"] == "ct-crtsh"
    assert data_0["run_id"] == str(RUN_ID)

    # Validate second frame: run_completed
    lines_1 = frames[1].split("\n")
    assert lines_1[0] == "event: run_completed"


# === 10. Event bus is created on first access via get_event_bus ===============


def test_get_event_bus_creates_on_first_access() -> None:
    """get_event_bus lazily creates a RunEventBus on app.state."""
    app = FastAPI()
    assert not hasattr(app.state, "event_bus")

    bus = get_event_bus(app)
    assert isinstance(bus, RunEventBus)
    assert hasattr(app.state, "event_bus")

    # Second call returns the same instance
    bus2 = get_event_bus(app)
    assert bus is bus2


# === 11. RunEvent rejects extra fields ========================================


def test_run_event_rejects_extra_fields() -> None:
    """RunEvent with extra=forbid rejects unknown fields."""
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RunEvent(
            event_type=RunEventType.RUN_STARTED,
            run_id=RUN_ID,
            tenant_id=TENANT_ID,
            timestamp=NOW,
            bogus_field="should_fail",  # type: ignore[call-arg]
        )


# === 12. Unsubscribe is idempotent ============================================


async def test_unsubscribe_idempotent() -> None:
    """Calling unsubscribe twice with the same queue does not raise."""
    bus = RunEventBus()
    queue: asyncio.Queue[RunEvent] = asyncio.Queue()
    bus._subscribers[RUN_ID].append(queue)

    bus.unsubscribe(RUN_ID, queue)
    # Second call — queue already removed, run key already cleaned up
    bus.unsubscribe(RUN_ID, queue)
    assert RUN_ID not in bus._subscribers


# === 13. Subscribe context manager cleans up on exception =====================


async def test_subscribe_cleanup_on_exception() -> None:
    """The subscribe context manager removes the queue even if the body raises."""
    bus = RunEventBus()

    with pytest.raises(RuntimeError, match="deliberate"):
        async with bus.subscribe(RUN_ID):
            # Verify subscription is active
            assert RUN_ID in bus._subscribers
            assert len(bus._subscribers[RUN_ID]) == 1
            raise RuntimeError("deliberate")

    # After exception, the queue should be cleaned up
    assert RUN_ID not in bus._subscribers


# === 14. RUN_COMPLETED terminates the SSE stream ==============================


async def test_sse_terminates_on_run_completed() -> None:
    """The SSE generator stops after emitting a RUN_COMPLETED event."""
    app = _make_app()
    bus = RunEventBus()
    app.state.event_bus = bus

    async def _publish_with_trailing() -> None:
        await asyncio.sleep(0.05)
        await bus.publish(_make_event(RunEventType.RUN_STARTED))
        await bus.publish(_make_event(RunEventType.RUN_COMPLETED))
        # This event should NOT be received because the stream closes
        await bus.publish(
            _make_event(
                RunEventType.COLLECTOR_STARTED,
                data={"collector_id": "should-not-appear"},
            )
        )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        publish_task = asyncio.create_task(_publish_with_trailing())
        resp = await client.get(
            f"/v1/tenants/{TENANT_ID}/runs/{RUN_ID}/events",
            timeout=5.0,
        )
        await publish_task

    body = resp.text
    frames = [f for f in body.split("\n\n") if f.strip()]
    # Should have exactly 2 frames: run_started + run_completed
    assert len(frames) == 2
    assert "run_started" in frames[0]
    assert "run_completed" in frames[1]
    assert "should-not-appear" not in body
