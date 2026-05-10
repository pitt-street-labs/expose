"""Idempotent stream + consumer setup for the EXPOSE dispatch broker.

Per Sprint 3-4 plan §3, EXPOSE runs a single JetStream stream covering all
dispatcher-issued jobs, with a durable pull consumer that workers bind to.

Naming and shape:

- ``EXPOSE_RUNS_DISPATCH`` stream covers ``expose.runs.dispatch.>`` —
  i.e., any subject under the dispatch namespace including the per-tenant /
  per-collector leaves the dispatcher publishes to (``expose.runs.dispatch.
  <tenant_id>.<collector_id>``).
- Retention is ``WORK_QUEUE``: a successfully-acked message is removed from
  the stream so the broker doesn't accumulate unbounded history. This is
  appropriate for a dispatch queue (vs. an audit log).
- Max age 7 days defends against a stuck consumer holding work indefinitely
  while still being long enough for typical operator response on a failing
  collector.
- The consumer is a durable pull consumer named ``dispatcher`` with
  explicit ack policy — workers fetch in batches and ack each message
  individually so a poison message doesn't block the rest.

Idempotency note: the ``ensure_streams_and_consumers`` helper is safe to
call from any worker startup path. It probes for existing config first and
returns without writing if the desired shape already exists; this keeps the
test suite deterministic across multiple connect/disconnect cycles.
"""

from __future__ import annotations

from datetime import timedelta

from nats.js import JetStreamContext
from nats.js.api import (
    AckPolicy,
    ConsumerConfig,
    DeliverPolicy,
    DiscardPolicy,
    ReplayPolicy,
    RetentionPolicy,
    StorageType,
    StreamConfig,
)
from nats.js.errors import NotFoundError

# === Public constants =========================================================
# Exposed at module level so callers (dispatcher, workers, tests) reference a
# single source of truth rather than duplicating string literals.

STREAM_NAME = "EXPOSE_RUNS_DISPATCH"
"""Name of the single dispatch stream. Singular by design — per-tenant
isolation lives in subjects, not streams, per Sprint 3-4 plan §3."""

CONSUMER_NAME = "dispatcher"
"""Durable pull consumer name. Workers bind to this consumer rather than
creating their own so that a fleet of worker pods naturally load-balances
across the queue."""

SUBJECT_PATTERN = "expose.runs.dispatch.>"
"""Token-tree subject pattern. The ``.>`` suffix matches any number of
trailing tokens, allowing the dispatcher to publish to
``expose.runs.dispatch.<tenant_id>.<collector_id>`` (and finer
sub-namespaces if future work needs them) without re-configuring the
stream."""

_MAX_AGE_DAYS = 7
"""Stream retention window. See module docstring for rationale."""

_ACK_WAIT_SECONDS = 60
"""How long after delivery the consumer waits for an ack before
re-delivering. Tuned for collector latencies in the 1-30s range with
buffer for slow LLM enrichment paths."""

_MAX_DELIVER = 5
"""Maximum redelivery attempts before the consumer gives up on a message.
Combined with the worker's nak/term semantics, this caps poison-message
amplification."""


# === Helpers ==================================================================
async def _stream_exists(js: JetStreamContext, name: str) -> bool:
    """Return True iff a stream with ``name`` is configured on the server."""
    try:
        await js.stream_info(name)
    except NotFoundError:
        return False
    return True


async def _consumer_exists(js: JetStreamContext, stream: str, consumer: str) -> bool:
    """Return True iff ``consumer`` exists on ``stream``."""
    try:
        await js.consumer_info(stream, consumer)
    except NotFoundError:
        return False
    return True


# === Public API ==============================================================
async def ensure_streams_and_consumers(js: JetStreamContext) -> None:
    """Create the EXPOSE_RUNS_DISPATCH stream + dispatcher consumer if absent.

    This is the only setup function callers should invoke from worker /
    dispatcher startup paths. It is idempotent: if the stream and consumer
    already exist with the expected shape, no writes occur.

    Notes on the explicit shape:

    - ``RetentionPolicy.WORK_QUEUE`` removes acked messages — appropriate
      for a dispatch queue.
    - ``DiscardPolicy.OLD`` (default) drops oldest pending messages on
      backpressure rather than rejecting new publishes; this keeps the
      dispatcher unblocked at the cost of bounded job loss under sustained
      overload (which is itself a signal the operator should react to via
      the OTel telemetry).
    - ``StorageType.FILE`` ensures messages survive a JetStream restart.
      Memory storage would be faster but loses dispatched work on restart.
    - ``AckPolicy.EXPLICIT`` requires the worker to ack each message
      individually, matching the per-job semantics needed for poison-message
      isolation.
    - ``ReplayPolicy.INSTANT`` delivers as fast as the consumer pulls (no
      original-rate replay simulation, which is a streaming-replay feature
      we don't need).
    - ``filter_subject`` constrains the consumer to the dispatch pattern;
      if other streams ever publish under ``expose.>``, the consumer still
      sees only dispatch jobs.
    """

    if not await _stream_exists(js, STREAM_NAME):
        max_age_seconds = int(timedelta(days=_MAX_AGE_DAYS).total_seconds())
        await js.add_stream(
            StreamConfig(
                name=STREAM_NAME,
                subjects=[SUBJECT_PATTERN],
                retention=RetentionPolicy.WORK_QUEUE,
                discard=DiscardPolicy.OLD,
                max_age=max_age_seconds,
                storage=StorageType.FILE,
                description=(
                    "EXPOSE dispatcher → worker job queue. "
                    "WORK_QUEUE retention; one message per (collector_id, seed). "
                    "Subjects follow expose.runs.dispatch.<tenant_id>.<collector_id>."
                ),
            )
        )

    if not await _consumer_exists(js, STREAM_NAME, CONSUMER_NAME):
        await js.add_consumer(
            stream=STREAM_NAME,
            config=ConsumerConfig(
                durable_name=CONSUMER_NAME,
                name=CONSUMER_NAME,
                filter_subject=SUBJECT_PATTERN,
                ack_policy=AckPolicy.EXPLICIT,
                ack_wait=_ACK_WAIT_SECONDS,
                max_deliver=_MAX_DELIVER,
                deliver_policy=DeliverPolicy.ALL,
                replay_policy=ReplayPolicy.INSTANT,
                description=(
                    "Durable pull consumer; worker fleets bind to this name "
                    "for natural load balancing across the queue."
                ),
            ),
        )


__all__ = [
    "CONSUMER_NAME",
    "STREAM_NAME",
    "SUBJECT_PATTERN",
    "ensure_streams_and_consumers",
]
