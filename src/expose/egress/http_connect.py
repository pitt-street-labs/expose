"""HTTP CONNECT egress profile.

Routes active collector traffic through an HTTP CONNECT proxy (e.g., Squid,
tinyproxy). The proxy establishes a TCP tunnel to the target host on behalf
of the client, so the target sees the proxy's IP. HTTP CONNECT is the most
widely-supported proxy method for HTTPS traffic.

DNS resolution is handled by the proxy, so the operator's system resolver
is not exposed to target infrastructure.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from expose.egress.base import EgressHealthCheck, EgressProfile, EgressProfileType


class HttpConnectEgressProfile(EgressProfile):
    """HTTP CONNECT proxy egress — routes traffic through an HTTP proxy.

    Typical deployment: Squid, tinyproxy, or any proxy supporting the
    ``CONNECT`` method for HTTPS tunnelling.

    Args:
        proxy_url: HTTP proxy URL, e.g. ``"http://proxy.internal:3128"``.
    """

    profile_type: EgressProfileType = EgressProfileType.HTTP_CONNECT

    @property
    def is_anonymizing(self) -> bool:
        """HTTP CONNECT proxies are not anonymizing by default.

        Corporate forward proxies (Squid, tinyproxy) are operator-controlled
        infrastructure — they change the exit IP but do not anonymize in the
        Tor/public-proxy sense. Operators deploying through an anonymizing
        HTTP proxy should subclass and override this property.
        """
        return False

    def __init__(self, proxy_url: str = "http://127.0.0.1:3128") -> None:
        self._proxy_url = proxy_url

    def configure_httpx_client(self, **kwargs: Any) -> dict[str, Any]:
        """Return httpx proxy kwargs for HTTP CONNECT tunnelling."""
        return {"proxy": self._proxy_url}

    def configure_dns_resolver(self, **kwargs: Any) -> dict[str, Any]:
        """Return empty dict — DNS is resolved on the proxy side.

        HTTP CONNECT proxies receive the target hostname in the ``CONNECT``
        request line and resolve it themselves, so the operator's resolver
        is not exposed.
        """
        return {}

    async def health_check(self) -> EgressHealthCheck:
        """Verify the HTTP CONNECT proxy is reachable via TCP connect probe.

        Attempts a raw TCP connection to the proxy host:port. This validates
        that the proxy daemon is listening; it does *not* send an HTTP CONNECT
        request (that requires a target host).
        """
        parsed = urlparse(self._proxy_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 3128

        start = asyncio.get_running_loop().time()
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10.0,
            )
            writer.close()
            await writer.wait_closed()
            latency = (asyncio.get_running_loop().time() - start) * 1000
            return EgressHealthCheck(
                profile_type=self.profile_type,
                healthy=True,
                latency_ms=latency,
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


__all__ = ["HttpConnectEgressProfile"]
