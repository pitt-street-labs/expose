"""HTTP CONNECT egress profile stub.

Routes active collector traffic through an HTTP CONNECT proxy (e.g., Squid,
tinyproxy). The proxy establishes a TCP tunnel to the target host on behalf
of the client, so the target sees the proxy's IP. HTTP CONNECT is the most
widely-supported proxy method for HTTPS traffic.

This is a stub — all methods raise ``NotImplementedError``. The class exists
so the egress profile registry can discover and reference the type. Full
implementation lands when egress infrastructure is deployed.
"""

from __future__ import annotations

from typing import Any

from expose.egress.base import EgressHealthCheck, EgressProfile, EgressProfileType


class HttpConnectEgressProfile(EgressProfile):
    """HTTP CONNECT proxy egress — stub, not yet implemented."""

    profile_type: EgressProfileType = EgressProfileType.HTTP_CONNECT

    def configure_httpx_client(self, **kwargs: Any) -> dict[str, Any]:
        """Not yet implemented."""
        raise NotImplementedError("HTTP CONNECT egress profile not yet implemented")

    def configure_dns_resolver(self, **kwargs: Any) -> dict[str, Any]:
        """Not yet implemented."""
        raise NotImplementedError("HTTP CONNECT egress profile not yet implemented")

    async def health_check(self) -> EgressHealthCheck:
        """Not yet implemented."""
        raise NotImplementedError("HTTP CONNECT egress profile not yet implemented")


__all__ = ["HttpConnectEgressProfile"]
