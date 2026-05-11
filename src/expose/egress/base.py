"""EgressProfile ABC and supporting value types (per SPEC §6.3 / issue #1).

An egress profile controls how active (Tier-3) collectors route their outbound
connections. EXPOSE's two active collectors — ``active-dns-resolve`` (dnspython)
and ``active-http-fingerprint`` (httpx) — default to direct connectivity from
the operator's host. Deploying an egress profile lets operators route probing
traffic through controlled exit points (SOCKS5, WireGuard, HTTP CONNECT proxy)
so active scanning is not attributed to the operator's infrastructure.

The ABC commits to three methods:

- :meth:`EgressProfile.configure_httpx_client` — returns kwargs injected into
  ``httpx.AsyncClient(**kwargs)`` at collector construction time.
- :meth:`EgressProfile.configure_dns_resolver` — returns kwargs injected into
  ``dns.asyncresolver.Resolver`` configuration.
- :meth:`EgressProfile.health_check` — async probe that verifies the egress
  path is functional before dispatching active collectors.

Concrete implementations:

- :class:`expose.egress.direct.DirectEgressProfile` — pass-through, no proxy.
- Stubs for SOCKS5, WireGuard, and HTTP CONNECT (``NotImplementedError``).

The :class:`EgressHealthCheck` Pydantic model captures the result of a health
check in a frozen, serialisable form for inclusion in run metadata.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict


class EgressProfileType(StrEnum):
    """Supported egress profile types.

    Each value corresponds to a concrete :class:`EgressProfile` subclass.
    The ``DIRECT`` type ships fully implemented; others are stubs pending
    egress infrastructure deployment.
    """

    DIRECT = "direct"
    SOCKS5 = "socks5"
    TOR = "tor"
    WIREGUARD = "wireguard"
    HTTP_CONNECT = "http_connect"


class EgressHealthCheck(BaseModel):
    """Result of an egress path health probe.

    Frozen and extra-forbid per project convention. Serialisable for inclusion
    in run metadata so operators can audit which egress path was active (and
    healthy) at scan time.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_type: EgressProfileType
    healthy: bool
    latency_ms: float | None = None
    error_message: str | None = None
    checked_at: datetime
    egress_anonymized: bool = False


class EgressProfile(ABC):
    """Controls how active collectors route outbound connections.

    Subclasses set :attr:`profile_type` as a class variable so the factory
    and registry can identify them without instantiation side effects.
    """

    profile_type: EgressProfileType

    @property
    @abstractmethod
    def is_anonymizing(self) -> bool:
        """Whether this profile routes through anonymizing infrastructure.

        Returns ``True`` when the egress path masks the operator's origin
        (e.g. Tor circuits, public SOCKS5 proxies with DNS-through-proxy).
        Downstream consumers use this flag — surfaced as
        ``egress_anonymized`` in :class:`EgressHealthCheck` — to record
        provenance about scan origin visibility.
        """

    @abstractmethod
    def configure_httpx_client(self, **kwargs: Any) -> dict[str, Any]:
        """Return kwargs to pass to ``httpx.AsyncClient`` constructor.

        For proxied profiles, this adds proxy/transport configuration.
        For direct, this is a pass-through (empty dict).
        """

    @abstractmethod
    def configure_dns_resolver(self, **kwargs: Any) -> dict[str, Any]:
        """Return kwargs for ``dns.asyncresolver.Resolver`` configuration.

        For proxied profiles, this may set nameservers to a forwarder on the
        egress host. For direct, this is a pass-through (empty dict).
        """

    @abstractmethod
    async def health_check(self) -> EgressHealthCheck:
        """Verify the egress path is functional.

        Returns an :class:`EgressHealthCheck` with ``healthy=True`` if the
        path is usable, or ``healthy=False`` with an ``error_message``
        describing the failure.
        """


__all__ = [
    "EgressHealthCheck",
    "EgressProfile",
    "EgressProfileType",
]
