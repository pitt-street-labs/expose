"""Abstract worker base for EXPOSE NATS JetStream consumers.

The dispatcher publishes ``JobMessage`` envelopes onto subjects of the form
``expose.runs.dispatch.<tenant_id>.<collector_id>``; this module provides the
``Worker`` base class that consumer-side implementations subclass to do
something with each message.

Design properties:

- **Async pull loop.** The worker binds to the durable ``dispatcher`` consumer
  (created by ``stream_setup.ensure_streams_and_consumers``) and pulls
  messages in batches. Pull semantics naturally throttle the consumer to its
  own processing rate without needing custom backpressure logic.
- **Explicit ack/nak/term.** Successful handle → ack (message removed from
  the WORK_QUEUE stream). Transient failure (handle raises) → nak (message
  re-delivered up to the consumer's ``max_deliver`` cap). Permanent failure
  (envelope cannot be deserialized at all) → term (message dropped without
  redelivery).
- **Tier-3 gating is the dispatcher's job, not the worker's.** Per SPEC §6.3
  / ADR-008, attribution-tier gating lives in one place: the dispatcher
  refuses to publish a Tier-3 collector job for an unattributed entity. By
  the time a worker pulls a message, that gate has already been checked.
  Workers MUST NOT re-implement it; doing so would duplicate the trust
  boundary and risk skew between the two checks.
- **Graceful shutdown.** A user-supplied ``asyncio.Event`` (or the worker's
  internal one) lets external code signal the loop to drain in-flight work
  and exit cleanly. This matches the expectation that worker pods receive
  SIGTERM and have a chance to finish before SIGKILL.
- **Tenant context propagation.** Every ``JobMessage`` carries a
  ``tenant_id``; subclasses MUST honour it when interacting with the
  observation graph or external APIs. The base class exposes the tenant on
  the resolved envelope rather than via a contextvar so subclass code is
  explicit about which tenant it is acting on.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Final

from nats.aio.msg import Msg
from nats.errors import TimeoutError as NatsTimeoutError
from pydantic import ValidationError

from expose.broker.nats_client import NatsBrokerClient
from expose.broker.stream_setup import STREAM_NAME
from expose.broker.types import JobMessage

logger = logging.getLogger(__name__)


class Worker(ABC):
    """Async pull-loop worker for the EXPOSE dispatch broker.

    Subclasses override :py:meth:`handle` to do collector- (or scanner-, or
    LLM-) specific work. The base class handles connection binding,
    fetching, deserialization, ack/nak/term, and graceful shutdown.

    Lifecycle::

        worker = MyConcreteWorker(client, "expose.runs.dispatch.>", "dispatcher")
        async with client:  # NatsBrokerClient is itself an async ctx mgr
            run_task = asyncio.create_task(worker.run())
            ...  # at shutdown
            worker.request_shutdown()
            await run_task
    """

    # === Tunables ===============================================================
    # Defined as class attributes (not constructor parameters) so subclasses
    # can override per worker family without callers needing to pass them.

    fetch_batch_size: Final[int] = 10
    """How many messages to fetch per pull call. Small batches reduce
    head-of-line blocking when one message is slow; large batches reduce
    NATS round-trips."""

    fetch_timeout_seconds: Final[float] = 5.0
    """Per-fetch timeout. Hits when no messages are available; the loop then
    checks the shutdown event and re-pulls. Short enough to be responsive
    to shutdown, long enough that idle pull is cheap."""

    def __init__(
        self,
        client: NatsBrokerClient,
        subject_pattern: str,
        consumer: str,
    ) -> None:
        """Construct an unstarted worker.

        Parameters
        ----------
        client
            A connected (or connectable) ``NatsBrokerClient``. The worker
            does not own the client lifecycle — callers manage connect/close
            via the client's async context manager so multiple workers can
            share one connection.
        subject_pattern
            JetStream subject pattern this worker pulls from. Typically
            ``expose.runs.dispatch.>`` for a generic worker; subclasses
            specializing on a collector tier may use a narrower pattern.
        consumer
            Durable consumer name to bind to. Should match the consumer
            created by ``ensure_streams_and_consumers`` (default
            ``dispatcher``); workers within a fleet share the consumer for
            natural load balancing.
        """
        if not subject_pattern:
            raise ValueError("Worker requires a non-empty subject_pattern.")
        if not consumer:
            raise ValueError("Worker requires a non-empty consumer name.")
        self._client = client
        self._subject_pattern = subject_pattern
        self._consumer = consumer
        self._shutdown_event = asyncio.Event()

    # === Public API =============================================================
    @abstractmethod
    async def handle(self, msg: Msg, job: JobMessage) -> None:
        """Process one job. Subclasses implement.

        Contract:

        - Returning normally → the base loop acks the message.
        - Raising ANY exception → the base loop naks the message; JetStream
          re-delivers up to the consumer's ``max_deliver`` cap, after which
          the message is parked on the server's max-delivery sink for
          operator inspection.
        - The raw ``msg`` is passed alongside the parsed ``job`` so subclass
          code can inspect headers, metadata, or call ``msg.in_progress()``
          to extend the ack window for long-running work — but ack/nak/term
          are managed by the base loop. Subclasses MUST NOT call ``msg.ack``
          / ``msg.nak`` / ``msg.term`` themselves (doing so creates
          double-ack races with the loop).
        - Subclasses MUST honour ``job.tenant_id`` when writing observations
          or invoking external APIs. Tier-3 gating is NOT the worker's job
          (see module docstring); the dispatcher already enforced it.
        """

    def request_shutdown(self) -> None:
        """Signal the run loop to drain in-flight work and exit.

        Idempotent. Safe to call from a signal handler or another asyncio
        task. The currently-pending fetch (if any) returns naturally on
        timeout; the loop then sees the event and exits.
        """
        self._shutdown_event.set()

    async def run(self) -> None:
        """Pull-loop entry point. Runs until ``request_shutdown`` is called.

        Each iteration:

        1. Pull up to ``fetch_batch_size`` messages, waiting at most
           ``fetch_timeout_seconds``.
        2. For each message: deserialize → handle → ack/nak/term per outcome.
        3. Check the shutdown event; loop or exit.

        The loop catches ``NatsTimeoutError`` from empty pulls (normal idle)
        and re-loops without escalating. All other exceptions from the
        broker layer propagate so the operator sees the failure and the pod
        restart loop kicks in.
        """
        js = await self._client.jetstream()
        subscription = await js.pull_subscribe(
            subject=self._subject_pattern,
            durable=self._consumer,
            stream=STREAM_NAME,
        )

        try:
            while not self._shutdown_event.is_set():
                try:
                    messages = await subscription.fetch(
                        batch=self.fetch_batch_size,
                        timeout=self.fetch_timeout_seconds,
                    )
                except NatsTimeoutError:
                    # No pending work; loop and re-check shutdown.
                    continue

                for msg in messages:
                    await self._dispatch_one(msg)
        finally:
            # Best-effort unsubscribe so the server cleans the inbox slot
            # promptly. Drain on the connection (NatsBrokerClient.close)
            # also catches this if we miss it.
            try:
                await subscription.unsubscribe()
            except Exception:
                # Broad catch on a shutdown path: we still want the worker
                # to stop cleanly even if the server has already torn the
                # inbox down. Logged at warning so operators see it but no
                # exception escapes the run() contract.
                logger.warning(
                    "Unsubscribe failed during worker shutdown",
                    exc_info=True,
                    extra={"consumer": self._consumer},
                )

    # === Internal ===============================================================
    async def _dispatch_one(self, msg: Msg) -> None:
        """Deserialize one message and route it to ``handle``, with ack flow.

        Failure modes:

        - Deserialization failure (``ValidationError``, ``ValueError``) →
          ``term``. The message will never become valid; redelivery is
          pointless. The error is logged so operators can find the offending
          payload via NATS server logs.
        - Handler exception → ``nak``. JetStream re-delivers up to the
          consumer's ``max_deliver``; after that the message is parked.
        - Handler success → ``ack``. The WORK_QUEUE retention removes it
          from the stream.
        """
        try:
            job = JobMessage.from_bytes(msg.data)
        except (ValidationError, ValueError):
            logger.exception(
                "JobMessage deserialization failed; terminating message",
                extra={"subject": msg.subject},
            )
            await msg.term()
            return

        try:
            await self.handle(msg, job)
        except Exception:
            # Broad catch by design: any handler failure becomes a nak. The
            # consumer's max_deliver caps redelivery so a poison message
            # eventually lands on the server's max-delivery sink rather
            # than looping forever.
            logger.exception(
                "Worker.handle raised; nak'ing for redelivery",
                extra={
                    "subject": msg.subject,
                    "tenant_id": str(job.tenant_id),
                    "run_id": str(job.run_id),
                    "collector_id": job.collector_id,
                    "attempt": job.attempt,
                },
            )
            await msg.nak()
            return

        await msg.ack()


__all__ = ["Worker"]
