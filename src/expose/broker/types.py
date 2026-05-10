"""Typed envelopes flowing through the NATS JetStream broker (per SPEC §10.3).

The dispatcher (control plane) places one ``JobMessage`` per
``(collector_id, seed)`` pair onto a tenant-namespaced subject. Workers
(collector / scanner / LLM) consume those messages, execute the work, and ack
or nak per outcome.

The envelope is intentionally narrow:

- ``tenant_id`` and ``run_id`` carry the multi-tenant + per-run context
  required by ADR-007 and SPEC §4.2's control-plane / data-plane separation.
- ``collector_id`` selects which concrete collector module the worker
  instantiates. The worker resolves credentials just-in-time via the
  per-tenant secrets backend (SPEC §6.4); credentials NEVER ride in the
  envelope.
- ``seed`` is the typed input the collector will consume. It is shaped as a
  ``dict`` here (rather than the full ``Seed`` Pydantic model) because the
  broker layer must remain decoupled from the collector framework — workers
  rebuild the ``Seed`` value on the consume side.
- ``dispatched_at`` enables queue-latency telemetry per the OTel hooks the
  dispatcher emits.
- ``attempt`` lets workers and the dispatcher reason about retry posture
  without consulting JetStream's ``num_delivered`` metadata.

Design constraints:

- Frozen models: enforces "construct once, never mutate" so envelopes can be
  treated as values across asyncio task boundaries without defensive copies.
- ``model_config = ConfigDict(extra="forbid")``: rejects unknown fields so a
  silently-evolving sender cannot put garbage in front of an older consumer.
- JSON wire format via Pydantic's ``model_dump_json`` / ``model_validate_json``:
  matches the rest of the EXPOSE artifact contract (SPEC §9) and avoids
  pickling adversary-influenced bytes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class JobMessage(BaseModel):
    """One unit of work flowing through the JetStream broker.

    Constructed by the dispatcher, serialized to JSON, published to a subject
    of the form ``expose.runs.dispatch.<tenant_id>.<collector_id>``, then
    delivered to a worker that calls :py:meth:`from_bytes` to reconstruct the
    envelope before acting on it.

    The model is frozen so that workers cannot accidentally mutate a message
    they intend to nak — this matters when error-handling paths re-enqueue
    via the dispatcher rather than relying on JetStream redelivery alone.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    tenant_id: UUID
    """Tenant context for the work — every observation produced under this
    job MUST carry this same ``tenant_id`` (ADR-007 belt-and-braces)."""

    run_id: UUID
    """Run identifier. All jobs within a single dispatcher-issued run share
    this value so per-run aggregation and the artifact's collector-health
    section can group them."""

    collector_id: str = Field(min_length=1)
    """Stable identifier of the collector module the worker will invoke
    (e.g., ``ct-crtsh``, ``cloud-aws-ranges``, ``active-dns-resolve``).
    Resolution to the concrete class happens worker-side via the registry."""

    seed: dict[str, Any]
    """The collector's input. Encoded as a plain dict so the broker layer
    has no compile-time dependency on the collector framework's ``Seed``
    type. Workers re-validate via ``Seed.model_validate(job.seed)``."""

    dispatched_at: datetime
    """When the dispatcher published this job. Used for queue-latency
    telemetry (delivered_at - dispatched_at). Always UTC; the dispatcher is
    responsible for normalising tz-naive inputs."""

    attempt: int = Field(default=1, ge=1)
    """1-indexed attempt counter. The dispatcher may bump this when
    re-enqueueing a job that was nak'd; JetStream's own ``num_delivered``
    counts native redelivery and is recorded separately for telemetry."""

    # === Wire format ============================================================
    def to_bytes(self) -> bytes:
        """Serialize to UTF-8 JSON bytes for publication on a NATS subject.

        Pydantic's ``model_dump_json`` handles UUID and datetime serialisation
        consistently with the rest of EXPOSE (RFC 4122 string for UUIDs, ISO
        8601 with timezone for datetimes).
        """
        return self.model_dump_json().encode("utf-8")

    @classmethod
    def from_bytes(cls, payload: bytes) -> JobMessage:
        """Reconstruct from UTF-8 JSON bytes received from a NATS subject.

        Validation errors propagate as ``pydantic.ValidationError`` — the
        worker base treats that as a permanent (term) failure: the message
        cannot be made consumable by retrying.
        """
        return cls.model_validate_json(payload.decode("utf-8"))


__all__ = ["JobMessage"]
