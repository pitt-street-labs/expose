"""SOCKS5 egress profile stub.

Routes active collector traffic through a SOCKS5 proxy so outbound connections
originate from the proxy host rather than the operator's infrastructure.
Requires a running SOCKS5 proxy (e.g., Dante, microsocks, or an SSH tunnel).

This is a stub — all methods raise ``NotImplementedError``. The class exists
so the egress profile registry can discover and reference the type. Full
implementation lands when egress infrastructure is deployed.
"""

from __future__ import annotations

from typing import Any

from expose.egress.base import EgressHealthCheck, EgressProfile, EgressProfileType


class Socks5EgressProfile(EgressProfile):
    """SOCKS5 proxy egress — stub, not yet implemented."""

    profile_type: EgressProfileType = EgressProfileType.SOCKS5

    def configure_httpx_client(self, **kwargs: Any) -> dict[str, Any]:
        """Not yet implemented."""
        raise NotImplementedError("SOCKS5 egress profile not yet implemented")

    def configure_dns_resolver(self, **kwargs: Any) -> dict[str, Any]:
        """Not yet implemented."""
        raise NotImplementedError("SOCKS5 egress profile not yet implemented")

    async def health_check(self) -> EgressHealthCheck:
        """Not yet implemented."""
        raise NotImplementedError("SOCKS5 egress profile not yet implemented")


__all__ = ["Socks5EgressProfile"]
