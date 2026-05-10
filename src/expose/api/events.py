"""Server-Sent Events endpoint and in-memory event bus for run lifecycle events.

Enables real-time dashboard updates during active pipeline runs. The UI
(HTMX SSE extension) connects to ``GET /v1/tenants/{tenant_id}/runs/{run_id}/events``
and receives typed events as collectors report back — the graph and table
animate in real-time.

Architecture:

- **``RunEventBus``** — async pub/sub using per-subscriber ``asyncio.Queue``
  instances keyed by ``run_id``. Publishers (``RunExecutor``,
  ``PipelineDispatcher``) call ``publish()``; SSE subscribers call
  ``subscribe()`` to receive an ``AsyncIterator[RunEvent]``.

- **``run_events_sse``** — FastAPI endpoint returning a ``StreamingResponse``
  with ``text/event-stream`` media type. One long-lived connection per
  (tenant, run) pair. Auto-closes on ``RUN_COMPLETED`` or client disconnect.

- **``get_event_bus``** — singleton accessor on ``app.state``. Creates the
  bus on first access so no startup wiring is needed.

Design constraints:

- No ``hashlib`` / ``secrets`` imports (FIPS adapter policy per ADR-010).
- Pydantic frozen models throughout.
- Clean disconnection handling: ``subscribe()`` context manager ensures the
  queue is removed even if the consumer raises or the client disconnects.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "RunEvent",
    "RunEventBus",
    "RunEventType",
    "get_event_bus",
    "router",
]


# === Event types ==============================================================


class RunEventType(StrEnum):
    """Typed lifecycle events emitted during a pipeline run."""

    RUN_STARTED = "run_started"
    COLLECTOR_STARTED = "collector_started"
    COLLECTOR_COMPLETED = "collector_completed"
    COLLECTOR_FAILED = "collector_failed"
    ENTITIES_DISCOVERED = "entities_discovered"
    ATTRIBUTION_UPDATED = "attribution_updated"
    RUN_COMPLETED = "run_completed"


class RunEvent(BaseModel):
    """Immutable event emitted by the pipeline and consumed by SSE subscribers.

    The ``data`` dict carries event-specific payload:

    - ``collector_started``: ``{"collector_id": "ct-crtsh"}``
    - ``collector_completed``: ``{"collector_id": "ct-crtsh", "observation_count": 5}``
    - ``collector_failed``: ``{"collector_id": "ct-crtsh", "error": "timeout"}``
    - ``entities_discovered``: ``{"entities": [{"id": "...", "label": "...",
      "type": "domain", "attribution_status": "unattributed"}]}``
    - ``attribution_updated``: ``{"entity_id": "...", "old_status":
      "unattributed", "new_status": "high"}``
    - ``run_started`` / ``run_completed``: typically empty or minimal metadata
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: RunEventType
    run_id: UUID
    tenant_id: UUID
    timestamp: datetime
    data: dict[str, Any] = Field(default_factory=dict)


# === Event bus ================================================================


class RunEventBus:
    """In-memory async event bus for run lifecycle events.

    Publishers (``RunExecutor``, ``PipelineDispatcher``) call ``publish()``.
    SSE subscribers call ``subscribe()`` to get an async generator scoped to a
    single ``run_id``.

    Thread safety: the bus is designed for single-event-loop use (one FastAPI
    worker). Multi-worker deployments should front this with Redis pub/sub or
    NATS (future work).
    """

    def __init__(self) -> None:
        self._subscribers: dict[UUID, list[asyncio.Queue[RunEvent]]] = defaultdict(list)

    async def publish(self, event: RunEvent) -> None:
        """Broadcast *event* to every subscriber watching ``event.run_id``.

        If no subscribers are registered for the run, the call is a silent
        no-op — events are fire-and-forget from the publisher's perspective.
        """
        queues = self._subscribers.get(event.run_id)
        if not queues:
            return
        for queue in queues:
            await queue.put(event)

    @asynccontextmanager
    async def subscribe(self, run_id: UUID) -> Any:
        """Context manager that yields an async iterator of events for *run_id*.

        On entry a new ``asyncio.Queue`` is registered. On exit (normal return,
        exception, or client disconnect) the queue is removed so no events leak.

        Usage::

            async with bus.subscribe(run_id) as events:
                async for event in events:
                    ...
        """
        queue: asyncio.Queue[RunEvent] = asyncio.Queue()
        self._subscribers[run_id].append(queue)
        try:
            yield _queue_iterator(queue)
        finally:
            self.unsubscribe(run_id, queue)

    def unsubscribe(self, run_id: UUID, queue: asyncio.Queue[RunEvent]) -> None:
        """Remove a subscriber's queue.

        Safe to call even if the queue has already been removed (idempotent).
        Cleans up the run key from ``_subscribers`` when the last queue for
        that run is removed.
        """
        queues = self._subscribers.get(run_id)
        if queues is None:
            return
        with contextlib.suppress(ValueError):
            queues.remove(queue)
        if not queues:
            del self._subscribers[run_id]


async def _queue_iterator(
    queue: asyncio.Queue[RunEvent],
) -> Any:
    """Drain a queue as an async iterator, yielding ``RunEvent`` instances."""
    while True:
        event = await queue.get()
        yield event


# === FastAPI endpoint =========================================================

router = APIRouter(tags=["events"])


@router.get("/v1/tenants/{tenant_id}/runs/{run_id}/events")
async def run_events_sse(
    tenant_id: UUID,
    run_id: UUID,
    request: Request,
) -> StreamingResponse:
    """SSE stream of events for a specific pipeline run.

    The client connects and receives events formatted per the SSE spec
    (``event: <type>\\ndata: <json>\\n\\n``). The connection closes when
    the run completes (``RUN_COMPLETED`` event) or the client disconnects.

    HTMX SSE extension connects here and updates the dashboard graph + table
    in real-time as collectors report back.
    """
    bus = get_event_bus(request.app)

    async def event_generator() -> Any:
        async with bus.subscribe(run_id) as events:
            async for event in events:
                if await request.is_disconnected():
                    break
                # SSE wire format: event: <type>\ndata: <json>\n\n
                yield f"event: {event.event_type.value}\ndata: {event.model_dump_json()}\n\n"
                if event.event_type == RunEventType.RUN_COMPLETED:
                    break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# === App-state accessor =======================================================


def get_event_bus(app: FastAPI) -> RunEventBus:
    """Get or create the ``RunEventBus`` singleton from ``app.state``.

    The bus is lazily created on first access so no explicit startup wiring
    is required — just call ``get_event_bus(request.app)`` from any endpoint
    or service.
    """
    if not hasattr(app.state, "event_bus"):
        app.state.event_bus = RunEventBus()
    bus: RunEventBus = app.state.event_bus
    return bus
