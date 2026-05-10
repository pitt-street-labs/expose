"""NATS JetStream broker for the EXPOSE dispatch path (per SPEC §10.3).

Per closed issue #36, EXPOSE uses NATS JetStream as the work queue between
the dispatcher (control plane) and worker fleets (collector / scanner / LLM).
The choice is documented in ``docs/strategy/sprint-3-4-plan.md`` §3 and
defaulted by SPEC §12.

This package provides:

- :class:`JobMessage` — typed envelope dispatcher → worker.
- :class:`NatsBrokerClient` — async lifecycle wrapper around ``nats-py``.
- :func:`ensure_streams_and_consumers` — idempotent stream + consumer setup.
- :class:`Worker` — abstract base for pull-loop consumers.

The public surface is re-exported here so consumers write::

    from expose.broker import (
        JobMessage,
        NatsBrokerClient,
        Worker,
        ensure_streams_and_consumers,
        STREAM_NAME,
        CONSUMER_NAME,
        SUBJECT_PATTERN,
    )

rather than reaching into individual sub-modules.

Subject convention: ``expose.runs.dispatch.<tenant_id>.<collector_id>``
(see :mod:`expose.broker.stream_setup` for the full pattern). Tier-3 dispatch
gating (SPEC §6.3) is enforced by the dispatcher BEFORE publication; workers
do not re-check the gate.
"""

from expose.broker.nats_client import NatsBrokerClient
from expose.broker.stream_setup import (
    CONSUMER_NAME,
    STREAM_NAME,
    SUBJECT_PATTERN,
    ensure_streams_and_consumers,
)
from expose.broker.types import JobMessage
from expose.broker.worker import Worker

__all__ = [
    "CONSUMER_NAME",
    "STREAM_NAME",
    "SUBJECT_PATTERN",
    "JobMessage",
    "NatsBrokerClient",
    "Worker",
    "ensure_streams_and_consumers",
]
