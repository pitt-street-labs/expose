"""WireGuard egress profile stub.

Routes active collector traffic through a WireGuard tunnel so outbound
connections originate from the tunnel endpoint. Requires a configured WireGuard
interface (e.g., ``wg0``) with a peer that provides egress to the target
networks.

This is a stub — all methods raise ``NotImplementedError``. The class exists
so the egress profile registry can discover and reference the type. Full
implementation lands when egress infrastructure is deployed.
"""

from __future__ import annotations

from typing import Any

from expose.egress.base import EgressHealthCheck, EgressProfile, EgressProfileType


class WireguardEgressProfile(EgressProfile):
    """WireGuard tunnel egress — stub, not yet implemented."""

    profile_type: EgressProfileType = EgressProfileType.WIREGUARD

    def configure_httpx_client(self, **kwargs: Any) -> dict[str, Any]:
        """Not yet implemented."""
        raise NotImplementedError("WireGuard egress profile not yet implemented")

    def configure_dns_resolver(self, **kwargs: Any) -> dict[str, Any]:
        """Not yet implemented."""
        raise NotImplementedError("WireGuard egress profile not yet implemented")

    async def health_check(self) -> EgressHealthCheck:
        """Not yet implemented."""
        raise NotImplementedError("WireGuard egress profile not yet implemented")


__all__ = ["WireguardEgressProfile"]
