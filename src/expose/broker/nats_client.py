"""Async NATS JetStream client wrapper for the EXPOSE broker layer.

Per the Sprint 3-4 plan (§3) and SPEC §10.3, EXPOSE uses NATS JetStream as
its dispatch broker. This module wraps ``nats-py`` in a thin async context
manager so the dispatcher and workers don't repeat connection bookkeeping.

Why a wrapper instead of using ``nats.connect`` directly?

- **Lifecycle discipline.** Every consumer paths needs ``connect`` /
  ``close`` symmetry; the context-manager pattern prevents leaks when
  exceptions surface mid-pull-loop.
- **JetStream context caching.** ``client.jetstream()`` instantiates a
  ``JetStreamContext``; doing so eagerly per call wastes CPU and obscures
  intent. The cached property here keeps that cost one-shot per connection.
- **Test seam.** The dispatcher / worker accept a ``NatsBrokerClient``
  rather than a raw ``NATS`` instance, which keeps test doubles trivial.

This module deliberately exposes only what the dispatcher and worker need —
``connect``, ``close``, ``publish``, ``jetstream``. Lower-level NATS APIs
(direct subscribe, key-value, object store) are accessible via
``self._client`` for components that need them, but the recommended path is
through the broker primitives in this package.
"""

from __future__ import annotations

from types import TracebackType

import nats
from nats.aio.client import Client as NATSClient
from nats.js import JetStreamContext

from expose.broker.types import JobMessage


class NatsBrokerClient:
    """Thin async lifecycle wrapper around ``nats-py``'s ``Client``.

    Usage::

        async with NatsBrokerClient(servers=["nats://localhost:4222"]) as broker:
            js = await broker.jetstream()
            await ensure_streams_and_consumers(js)
            await broker.publish("expose.runs.dispatch.<tid>.<cid>", job)

    The class is intentionally NOT a Pydantic model — it owns I/O resources
    that don't survive serialization, and Pydantic frozen-by-default would
    prevent the late-bound ``_client`` / ``_js`` assignments.
    """

    def __init__(
        self,
        servers: list[str],
        name: str | None = None,
    ) -> None:
        """Hold connection parameters; no I/O until :py:meth:`connect`.

        Parameters
        ----------
        servers
            One or more ``nats://host:port`` URIs. List form supports cluster
            failover natively per ``nats-py``.
        name
            Optional client name surfaced in NATS server logs and the
            management API. Useful when correlating broker events with
            specific worker pods. Defaults to ``None`` (server assigns one).
        """
        if not servers:
            raise ValueError("NatsBrokerClient requires at least one NATS server URI.")
        self._servers = list(servers)
        self._name = name
        self._client: NATSClient | None = None
        self._js: JetStreamContext | None = None

    # === Connection lifecycle ===================================================
    async def connect(self) -> None:
        """Open the connection to NATS.

        Idempotent — calling ``connect`` on an already-connected client is a
        no-op so the dispatcher can defensively re-call without breaking
        long-running workers that hold the same handle.
        """
        if self._client is not None and self._client.is_connected:
            return
        self._client = await nats.connect(servers=self._servers, name=self._name)

    async def close(self) -> None:
        """Drain in-flight messages and close the connection.

        ``drain`` (rather than the harder ``close``) lets pending publishes
        flush before the socket goes away. Safe to call from a finally block
        even if ``connect`` was never reached.
        """
        if self._client is None:
            return
        if self._client.is_connected:
            # ``drain`` blocks until subscriptions are unsubscribed and
            # outstanding publishes are flushed. It also closes the
            # connection, so we don't need a separate ``close`` after.
            await self._client.drain()
        self._client = None
        self._js = None

    async def __aenter__(self) -> NatsBrokerClient:
        """Connect on entry — see :py:meth:`connect`."""
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Close on exit even if an exception is propagating."""
        await self.close()

    # === JetStream context ======================================================
    async def jetstream(self) -> JetStreamContext:
        """Lazily build and cache the JetStream context for this connection.

        The first call instantiates ``JetStreamContext`` from the underlying
        ``nats-py`` client; subsequent calls return the same instance so
        callers can use it as if it were a regular field.

        Raises ``RuntimeError`` if invoked before :py:meth:`connect`. This is
        the operationally clearer failure mode than letting the underlying
        library raise an attribute error on ``None``.
        """
        if self._client is None:
            raise RuntimeError(
                "NatsBrokerClient.jetstream() called before connect(); "
                "use the async context manager or await connect() first."
            )
        if self._js is None:
            self._js = self._client.jetstream()
        return self._js

    # === Publishing =============================================================
    async def publish(self, subject: str, message: JobMessage) -> None:
        """Publish a ``JobMessage`` to the given JetStream subject.

        Uses ``JetStreamContext.publish`` so the message is durably persisted
        in the stream covering the subject; a non-JetStream publish (raw
        ``client.publish``) would not be retained.

        ``subject`` must match the convention
        ``expose.runs.dispatch.<tenant_id>.<collector_id>`` so the configured
        EXPOSE_RUNS_DISPATCH stream catches it. This wrapper does not enforce
        the convention itself — the dispatcher validates subjects before
        publishing.
        """
        js = await self.jetstream()
        await js.publish(subject, message.to_bytes())


__all__ = ["NatsBrokerClient"]
