"""WireGuard egress profile.

Routes active collector traffic through a WireGuard tunnel so outbound
connections originate from the tunnel endpoint. Requires a configured WireGuard
interface (e.g., ``wg0``) with a peer that provides egress to the target
networks.

Unlike proxy-based profiles (SOCKS5, HTTP CONNECT), WireGuard operates at the
network level. The OS routing table directs traffic through the tunnel
interface; the httpx client does not need proxy configuration. The profile
optionally binds the client to the tunnel interface's source address so that
connections are guaranteed to exit via the tunnel even when default routing
does not cover all destinations.
"""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from expose.egress.base import EgressHealthCheck, EgressProfile, EgressProfileType

_IFACE_RE = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")


def _check_interface(interface_name: str) -> tuple[bool, str | None]:
    """Synchronous check for a WireGuard network interface.

    Inspects ``/sys/class/net/<interface_name>/operstate`` for presence and
    link status. Returns ``(healthy, error_message)``.
    """
    if not _IFACE_RE.match(interface_name):
        return False, f"Invalid interface name: {interface_name!r}"
    iface_path = Path(f"/sys/class/net/{interface_name}")

    if not iface_path.is_dir():
        return False, f"Interface {interface_name} does not exist"

    operstate_path = iface_path / "operstate"
    operstate = operstate_path.read_text().strip() if operstate_path.is_file() else "unknown"
    # WireGuard interfaces report "unknown" as operstate — this is normal
    # and indicates the interface is up. "down" means it's not active.
    if operstate == "down":
        return False, f"Interface {interface_name} is down"
    return True, None


class WireguardEgressProfile(EgressProfile):
    """WireGuard tunnel egress — routes traffic through a WG interface.

    Typical deployment: ``wg-quick up wg0`` with a peer that provides egress.

    Args:
        interface_name: WireGuard interface name (default ``"wg0"``).
        source_address: If provided, bind httpx transport to this local address
            to ensure traffic exits through the tunnel. Typically the address
            assigned to the WireGuard interface (e.g. ``"10.0.0.2"``).
    """

    profile_type: EgressProfileType = EgressProfileType.WIREGUARD

    def __init__(
        self, interface_name: str = "wg0", source_address: str | None = None
    ) -> None:
        self._interface_name = interface_name
        self._source_address = source_address

    def configure_httpx_client(self, **kwargs: Any) -> dict[str, Any]:
        """Return httpx transport kwargs for WireGuard source binding.

        If a ``source_address`` was provided, return an
        :class:`httpx.AsyncHTTPTransport` bound to that address. Otherwise
        return an empty dict and rely on OS routing.
        """
        if self._source_address:
            return {
                "transport": httpx.AsyncHTTPTransport(local_address=self._source_address),
            }
        return {}

    def configure_dns_resolver(self, **kwargs: Any) -> dict[str, Any]:
        """Return empty dict — DNS routes through the WG tunnel via OS routing."""
        return {}

    async def health_check(self) -> EgressHealthCheck:
        """Verify the WireGuard interface exists and is operational.

        Checks ``/sys/class/net/<interface_name>/operstate`` for interface
        presence and link status. The blocking filesystem read is offloaded
        to a thread via :func:`asyncio.to_thread`.
        """
        start = asyncio.get_running_loop().time()
        try:
            healthy, error_message = await asyncio.to_thread(
                _check_interface, self._interface_name
            )
            latency = (asyncio.get_running_loop().time() - start) * 1000
            return EgressHealthCheck(
                profile_type=self.profile_type,
                healthy=healthy,
                latency_ms=latency,
                error_message=error_message,
                checked_at=datetime.now(tz=UTC),
            )
        except Exception as exc:
            latency = (asyncio.get_running_loop().time() - start) * 1000
            return EgressHealthCheck(
                profile_type=self.profile_type,
                healthy=False,
                latency_ms=latency,
                error_message=str(exc),
                checked_at=datetime.now(tz=UTC),
            )


__all__ = ["WireguardEgressProfile"]
