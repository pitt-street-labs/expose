"""NATS-mediated distributed dispatcher for the EXPOSE pipeline.

This module provides ``NatsDispatcher``, which implements the
``DispatcherProtocol`` defined in ``expose.pipeline.run_executor``. Instead of
executing collectors in-process (like ``PipelineDispatcher``), it serializes
``DispatchJob`` envelopes to NATS and waits for a worker to respond via the
request-reply pattern.

Architecture:

    RunExecutor --> NatsDispatcher --> NATS (request/reply) --> CollectorWorker
                                                                     |
                                                               PipelineDispatcher
                                                                     |
                                                                 Collector

The ``CollectorWorker`` is the other side of this bridge. It subclasses
``Worker`` from ``expose.broker.worker``, receives ``JobMessage`` envelopes
from NATS, delegates to the in-process ``PipelineDispatcher``, and publishes
the result back on the message's reply subject.

Wire format:

    The dispatcher publishes a ``JobMessage`` (via ``NatsBrokerClient``) and
    the worker replies with a ``NatsDispatcherResult`` (a Pydantic model
    serialized to JSON bytes). ``NatsDispatcherResult`` is the wire-format
    subset of ``DispatchResult`` — it intentionally omits
    ``collector_health`` (an operational detail that stays worker-local) and
    uses ``str`` for ``status`` (not ``DispatchStatus`` enum, since the
    enum is a dispatcher-internal concern).

Design constraints:

- Frozen Pydantic models throughout (construct once, never mutate).
- ``ConfigDict(extra="forbid")`` rejects unknown fields on the wire.
- Timeout handling returns a ``DispatchResult`` with status
  ``collector_error`` rather than raising — callers pattern-match on
  status, not exception types (per ``PipelineDispatcher`` convention).
- The ``NatsBrokerClient`` is injected, not constructed — lifecycle is
  the caller's concern (matches the ``Worker`` pattern).
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

from nats.aio.msg import Msg
from pydantic import BaseModel, ConfigDict, Field

from expose.broker.nats_client import NatsBrokerClient
from expose.broker.types import JobMessage
from expose.broker.worker import Worker
from expose.collectors.base import Observation, Seed
from expose.pipeline.run_executor import DispatchJob, DispatchResult

logger = logging.getLogger(__name__)

# === Wire-format result model =================================================


class NatsDispatcherResult(BaseModel):
    """Wire-format result sent from ``CollectorWorker`` back to ``NatsDispatcher``.

    This is the JSON envelope that travels on the NATS reply subject. It
    carries the subset of ``DispatchResult`` fields needed by the dispatcher
    to construct the executor-facing result. ``collector_health`` is
    intentionally omitted — it is an operational detail that stays with the
    worker for its own telemetry.

    Observations are serialized as dicts (via ``Observation.model_dump``)
    rather than full Pydantic models so the broker layer does not need a
    compile-time dependency on every field the ``Observation`` model may
    add in future sprints. The ``NatsDispatcher`` reconstructs
    ``Observation`` instances on the receive side via ``model_validate``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str
    observations: list[dict[str, Any]] = Field(default_factory=list)
    error_message: str | None = None
    duration_ms: float = 0.0

    def to_bytes(self) -> bytes:
        """Serialize to UTF-8 JSON bytes for publication on a NATS reply subject."""
        return self.model_dump_json().encode("utf-8")

    @classmethod
    def from_bytes(cls, payload: bytes) -> NatsDispatcherResult:
        """Reconstruct from UTF-8 JSON bytes received from NATS."""
        return cls.model_validate_json(payload.decode("utf-8"))


# === Default timeout ==========================================================

DEFAULT_TIMEOUT_SECONDS: float = 120.0
"""Default timeout for request-reply. Collectors typically complete in 1-30s;
120s accommodates slow external APIs and LLM enrichment paths."""


# === NatsDispatcher ===========================================================


class NatsDispatcher:
    """Distributed dispatcher that publishes jobs to NATS and awaits replies.

    Implements ``DispatcherProtocol`` from ``expose.pipeline.run_executor``
    so the ``RunExecutor`` can swap between in-process (``PipelineDispatcher``)
    and distributed (``NatsDispatcher``) dispatch without code changes.

    The dispatch flow:

    1. Convert ``DispatchJob`` to ``JobMessage`` (broker wire format).
    2. Publish to ``expose.runs.dispatch.<tenant_id>.<collector_id>`` using
       the raw NATS request-reply pattern (not JetStream publish — we need
       the reply inbox).
    3. Wait for the worker's reply with a configurable timeout.
    4. Deserialize the ``NatsDispatcherResult`` and convert to
       ``DispatchResult`` for the executor.

    Timeout handling: if the worker does not reply within ``timeout_seconds``,
    the dispatcher returns a ``DispatchResult`` with
    ``status="collector_error"`` and ``error_message="timeout"`` rather than
    raising. This matches the ``PipelineDispatcher`` convention of always
    returning a result.
    """

    def __init__(
        self,
        client: NatsBrokerClient,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        """Construct a dispatcher bound to a ``NatsBrokerClient``.

        Parameters
        ----------
        client
            A connected (or connectable) ``NatsBrokerClient``. The dispatcher
            does not own the client lifecycle — callers manage connect/close.
        timeout_seconds
            How long to wait for a worker reply before returning a timeout
            error result. Defaults to ``DEFAULT_TIMEOUT_SECONDS`` (120s).
        """
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive.")
        self._client = client
        self._timeout_seconds = timeout_seconds

    async def dispatch(self, job: DispatchJob) -> DispatchResult:
        """Publish a job to NATS and wait for the worker's reply.

        Returns a ``DispatchResult`` in all cases — never raises for
        expected failure modes (timeout, deserialization error, worker
        error). Only unexpected infrastructure failures (NATS connection
        lost mid-request) propagate as exceptions.
        """
        start_ns = time.monotonic_ns()

        # Build the JobMessage wire envelope.
        job_message = JobMessage(
            tenant_id=job.tenant_id,
            run_id=job.run_id,
            collector_id=job.collector_id,
            seed=job.seed.model_dump(),
            dispatched_at=datetime.now(UTC),
        )

        subject = f"expose.runs.dispatch.{job.tenant_id}.{job.collector_id}"

        # Use the raw NATS client for request-reply (not JetStream publish).
        # The NatsBrokerClient exposes _client for lower-level access.
        raw_client = self._client._client
        if raw_client is None:
            raise RuntimeError(
                "NatsDispatcher.dispatch() called before client connect(); "
                "use the async context manager or await connect() first."
            )

        try:
            response = await raw_client.request(
                subject,
                job_message.to_bytes(),
                timeout=self._timeout_seconds,
            )
        except Exception as exc:
            # nats.errors.TimeoutError or any connection-level error.
            elapsed_ms = (time.monotonic_ns() - start_ns) / 1_000_000
            error_msg = "timeout" if "timeout" in type(exc).__name__.lower() else str(exc)
            logger.warning(
                "NATS dispatch failed for collector=%s tenant=%s: %s",
                job.collector_id,
                job.tenant_id,
                error_msg,
            )
            return DispatchResult(
                status="collector_error",
                error_message=error_msg,
                duration_ms=elapsed_ms,
            )

        # Deserialize the worker's reply.
        try:
            wire_result = NatsDispatcherResult.from_bytes(response.data)
        except Exception as exc:
            elapsed_ms = (time.monotonic_ns() - start_ns) / 1_000_000
            logger.warning(
                "Failed to deserialize dispatch result for collector=%s: %s",
                job.collector_id,
                exc,
            )
            return DispatchResult(
                status="collector_error",
                error_message=f"result deserialization failed: {exc}",
                duration_ms=elapsed_ms,
            )

        # Reconstruct Observation models from the wire dicts.
        observations: list[Observation] = []
        for obs_dict in wire_result.observations:
            try:
                observations.append(Observation.model_validate(obs_dict))
            except Exception as exc:
                logger.warning(
                    "Skipping malformed observation in dispatch result: %s",
                    exc,
                )

        elapsed_ms = (time.monotonic_ns() - start_ns) / 1_000_000

        return DispatchResult(
            status=wire_result.status,
            observations=observations,
            error_message=wire_result.error_message,
            duration_ms=elapsed_ms,
        )


# === CollectorWorker ==========================================================


class CollectorWorker(Worker):
    """NATS worker that bridges broker messages to the in-process dispatcher.

    The worker pulls ``JobMessage`` envelopes from the NATS dispatch stream,
    converts them to ``DispatchJob`` instances, delegates to the local
    ``PipelineDispatcher``, and publishes the result back on the message's
    reply subject so the ``NatsDispatcher`` on the control-plane side receives
    the response.

    This is the worker-side complement of ``NatsDispatcher``. Together they
    form the distributed dispatch bridge::

        NatsDispatcher --(request)--> NATS --(deliver)--> CollectorWorker
                                                                |
                                                          PipelineDispatcher
                                                                |
                                                            Collector
        NatsDispatcher <--(reply)--- NATS <--(publish)--- CollectorWorker

    The worker does NOT call ``msg.ack`` / ``msg.nak`` / ``msg.term`` —
    the ``Worker`` base class manages acknowledgment flow. Returning
    normally from ``handle`` triggers an ack; raising triggers a nak.
    """

    def __init__(
        self,
        client: NatsBrokerClient,
        subject_pattern: str,
        consumer: str,
        *,
        dispatcher: Any,
    ) -> None:
        """Construct a collector worker.

        Parameters
        ----------
        client
            Connected ``NatsBrokerClient``.
        subject_pattern
            JetStream subject pattern to pull from (typically
            ``expose.runs.dispatch.>``).
        consumer
            Durable consumer name (typically ``dispatcher``).
        dispatcher
            A ``PipelineDispatcher`` (or any object implementing
            ``DispatcherProtocol``) that executes collector work locally.
            Typed as ``Any`` to avoid a circular import with the concrete
            dispatcher module — the protocol check is structural.
        """
        super().__init__(client, subject_pattern, consumer)
        self._dispatcher = dispatcher

    async def handle(self, msg: Msg, job: JobMessage) -> None:
        """Execute one dispatch job and reply with the result.

        The ``job`` (``JobMessage``) carries the seed as a plain dict. We
        reconstruct the ``Seed`` model and build a ``DispatchJob`` for the
        local ``PipelineDispatcher``.

        If the message has no reply subject (e.g., published without
        request-reply), the result is logged but not published — the
        ``Worker`` base still acks the message so it doesn't re-deliver
        indefinitely.
        """
        from expose.pipeline.dispatcher import (  # noqa: PLC0415
            DispatchJob as LocalDispatchJob,
        )

        # Reconstruct the typed Seed from the wire dict.
        seed = Seed.model_validate(job.seed)

        local_job = LocalDispatchJob(
            collector_id=job.collector_id,
            seed=seed,
            run_id=job.run_id,
            tenant_id=job.tenant_id,
        )

        result = await self._dispatcher.dispatch(local_job)

        # Build the wire-format reply.
        wire_result = NatsDispatcherResult(
            status=result.status if isinstance(result.status, str) else result.status.value,
            observations=[obs.model_dump(mode="json") for obs in result.observations],
            error_message=result.error_message,
            duration_ms=result.duration_ms,
        )

        if msg.reply:
            raw_client = self._client._client
            if raw_client is not None:
                await raw_client.publish(msg.reply, wire_result.to_bytes())
        else:
            logger.info(
                "No reply subject on dispatch message for collector=%s; "
                "result discarded (worker-only mode)",
                job.collector_id,
            )


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "CollectorWorker",
    "NatsDispatcher",
    "NatsDispatcherResult",
]
