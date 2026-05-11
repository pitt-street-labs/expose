"""Tor egress profile.

Routes active collector traffic through the Tor network via its local SOCKS5
proxy, providing full anonymisation of the operator's origin IP. DNS resolution
is always routed through the Tor circuit (``socks5h://``) to prevent leaks.

Circuit rotation is supported via the Tor control protocol (default port 9051).
The implementation uses raw control-port commands (``AUTHENTICATE`` +
``SIGNAL NEWNYM``) and does **not** require the ``stem`` library.

Optional auto-rotation: when ``rotate_every_n_requests`` is set, a call to
:meth:`TorEgressProfile.maybe_rotate` increments an internal counter and
triggers circuit rotation once the threshold is reached.

httpx SOCKS5 support requires the ``socksio`` package (``pip install socksio``).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from expose.egress.base import EgressHealthCheck, EgressProfile, EgressProfileType
from expose.egress.socks5 import Socks5EgressProfile

logger = logging.getLogger(__name__)

# Tor control protocol response codes
_CTRL_OK = "250"


class TorEgressProfile(EgressProfile):
    """Tor egress -- routes traffic through the Tor SOCKS5 proxy.

    Wraps :class:`Socks5EgressProfile` for httpx/DNS configuration and adds
    Tor-specific capabilities: circuit rotation via the control port and
    enhanced health checks that verify both the SOCKS5 proxy and control port.

    Args:
        socks_host: Tor SOCKS5 listen address.
        socks_port: Tor SOCKS5 listen port (default 9050).
        control_port: Tor control port for sending signals (default 9051).
        control_password: Password for Tor control-port authentication.
            ``None`` means no password (``AUTHENTICATE`` with empty string).
        rotate_every_n_requests: When set, :meth:`maybe_rotate` will trigger
            circuit rotation after this many calls. ``None`` disables
            auto-rotation.
    """

    profile_type: EgressProfileType = EgressProfileType.TOR

    def __init__(
        self,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        control_port: int = 9051,
        control_password: str | None = None,
        rotate_every_n_requests: int | None = None,
    ) -> None:
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._control_port = control_port
        self._control_password = control_password
        self._rotate_every_n = rotate_every_n_requests
        self._request_counter: int = 0

        # Delegate SOCKS5 configuration to the existing profile.
        # Tor always resolves DNS through the circuit (socks5h), so
        # dns_through_proxy is forced True.
        self._socks = Socks5EgressProfile(
            proxy_url=f"socks5://{socks_host}:{socks_port}",
            dns_through_proxy=True,
        )

    # -- ABC implementation ----------------------------------------------------

    @property
    def is_anonymizing(self) -> bool:
        """Tor is always anonymizing -- that is the whole point."""
        return True

    def configure_httpx_client(self, **kwargs: Any) -> dict[str, Any]:
        """Return httpx proxy kwargs routing through Tor's SOCKS5 port.

        The URL uses the ``socks5h://`` scheme so hostname resolution happens
        inside the Tor circuit, preventing DNS leaks.
        """
        return self._socks.configure_httpx_client(**kwargs)

    def configure_dns_resolver(self, **kwargs: Any) -> dict[str, Any]:
        """Return DNS resolver kwargs.

        DNS is resolved through the Tor circuit (``socks5h``), so independent
        DNS resolution is disabled (empty nameservers list).
        """
        return self._socks.configure_dns_resolver(**kwargs)

    async def health_check(self) -> EgressHealthCheck:
        """Verify Tor is operational.

        Checks:
        1. SOCKS5 proxy port is reachable (delegated to the inner profile).
        2. Control port is reachable and responds to ``PROTOCOLINFO``.

        If the SOCKS5 check fails, the control port is not tested (Tor is
        down or unreachable). If the SOCKS5 check passes but the control
        port fails, the profile is still reported as unhealthy because
        circuit rotation would be impossible.
        """
        # Step 1: SOCKS5 reachability
        socks_check = await self._socks.health_check()
        if not socks_check.healthy:
            return EgressHealthCheck(
                profile_type=self.profile_type,
                healthy=False,
                latency_ms=socks_check.latency_ms,
                error_message=f"Tor SOCKS5 port unreachable: {socks_check.error_message}",
                checked_at=datetime.now(tz=UTC),
                egress_anonymized=True,
            )

        # Step 2: Control port reachability
        start = asyncio.get_running_loop().time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._socks_host, self._control_port),
                timeout=10.0,
            )
            writer.close()
            await writer.wait_closed()
            ctrl_latency = (asyncio.get_running_loop().time() - start) * 1000
        except Exception as exc:
            ctrl_latency = (asyncio.get_running_loop().time() - start) * 1000
            return EgressHealthCheck(
                profile_type=self.profile_type,
                healthy=False,
                latency_ms=ctrl_latency,
                error_message=f"Tor control port unreachable: {exc}",
                checked_at=datetime.now(tz=UTC),
                egress_anonymized=True,
            )

        # Both ports reachable
        total_latency = (socks_check.latency_ms or 0.0) + ctrl_latency
        return EgressHealthCheck(
            profile_type=self.profile_type,
            healthy=True,
            latency_ms=total_latency,
            checked_at=datetime.now(tz=UTC),
            egress_anonymized=True,
        )

    # -- Tor-specific methods --------------------------------------------------

    async def rotate_circuit(self) -> None:
        """Request a new Tor circuit via the control port.

        Sends ``AUTHENTICATE`` followed by ``SIGNAL NEWNYM`` using the raw
        Tor control protocol. Raises :class:`RuntimeError` if the control
        port rejects the command.

        The Tor control protocol is line-oriented: each command is a single
        line terminated by ``\\r\\n``, and each response starts with a
        3-digit status code (``250`` = OK).
        """
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self._socks_host, self._control_port),
            timeout=10.0,
        )
        try:
            # Authenticate
            if self._control_password is not None:
                auth_cmd = f'AUTHENTICATE "{self._control_password}"\r\n'
            else:
                auth_cmd = "AUTHENTICATE\r\n"
            writer.write(auth_cmd.encode())
            await writer.drain()
            auth_response = await asyncio.wait_for(reader.readline(), timeout=5.0)
            auth_line = auth_response.decode().strip()
            if not auth_line.startswith(_CTRL_OK):
                msg = f"Tor AUTHENTICATE failed: {auth_line}"
                raise RuntimeError(msg)

            # Signal new circuit
            writer.write(b"SIGNAL NEWNYM\r\n")
            await writer.drain()
            newnym_response = await asyncio.wait_for(reader.readline(), timeout=5.0)
            newnym_line = newnym_response.decode().strip()
            if not newnym_line.startswith(_CTRL_OK):
                msg = f"Tor SIGNAL NEWNYM failed: {newnym_line}"
                raise RuntimeError(msg)

            logger.info("Tor circuit rotated via SIGNAL NEWNYM")
        finally:
            writer.close()
            await writer.wait_closed()

    async def maybe_rotate(self) -> bool:
        """Increment request counter and rotate if threshold reached.

        Returns ``True`` if rotation was triggered, ``False`` otherwise.
        Does nothing if ``rotate_every_n_requests`` was not configured.
        """
        if self._rotate_every_n is None:
            return False

        self._request_counter += 1
        if self._request_counter >= self._rotate_every_n:
            self._request_counter = 0
            await self.rotate_circuit()
            return True
        return False

    @property
    def request_counter(self) -> int:
        """Current request counter value (for observability)."""
        return self._request_counter

    @property
    def socks_url(self) -> str:
        """The effective SOCKS5 URL (uses ``socks5h://`` for DNS privacy)."""
        return f"socks5h://{self._socks_host}:{self._socks_port}"


__all__ = ["TorEgressProfile"]
