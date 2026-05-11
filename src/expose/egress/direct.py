"""Direct (no-proxy) egress profile — the default for all deployments.

When no egress infrastructure is deployed, active collectors connect directly
from the operator's host. This profile is a pass-through: both
:meth:`configure_httpx_client` and :meth:`configure_dns_resolver` return empty
dicts, and :meth:`health_check` always reports healthy (if the host has network
connectivity, direct egress works).

This is the only fully-implemented egress profile in v1. SOCKS5, WireGuard,
and HTTP CONNECT profiles are stubs pending egress infrastructure deployment.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from expose.egress.base import EgressHealthCheck, EgressProfile, EgressProfileType


class DirectEgressProfile(EgressProfile):
    """Direct connectivity — no proxy, no tunnel.

    Active collectors using this profile connect from the operator's own IP
    address. This is the correct default for internal / lab deployments where
    attribution to the operator's infrastructure is acceptable.
    """

    profile_type: EgressProfileType = EgressProfileType.DIRECT

    @property
    def is_anonymizing(self) -> bool:
        """Direct egress is never anonymizing — traffic exits from the operator's IP."""
        return False

    def configure_httpx_client(self, **kwargs: Any) -> dict[str, Any]:
        """Return empty dict — no proxy configuration needed."""
        return {}

    def configure_dns_resolver(self, **kwargs: Any) -> dict[str, Any]:
        """Return empty dict — use system resolver."""
        return {}

    async def health_check(self) -> EgressHealthCheck:
        """Direct egress is always healthy if the host has network."""
        return EgressHealthCheck(
            profile_type=EgressProfileType.DIRECT,
            healthy=True,
            latency_ms=0.0,
            checked_at=datetime.now(tz=UTC),
        )


__all__ = ["DirectEgressProfile"]
