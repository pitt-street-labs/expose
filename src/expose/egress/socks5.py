"""SOCKS5 egress profile.

Routes active collector traffic through a SOCKS5 proxy so outbound connections
originate from the proxy host rather than the operator's infrastructure.
Requires a running SOCKS5 proxy (e.g., Dante, microsocks, or an SSH tunnel).

When ``dns_through_proxy`` is ``True`` (the default), the profile rewrites the
proxy URL from ``socks5://`` to ``socks5h://`` so the *proxy* resolves
hostnames on behalf of the client. This prevents DNS leaks that would reveal
the operator's resolver to target infrastructure.

httpx SOCKS5 support requires the ``socksio`` package (``pip install socksio``).
If ``socksio`` is not installed, :meth:`Socks5EgressProfile.configure_httpx_client`
raises a clear ``RuntimeError`` at call time rather than failing with a cryptic
import error deep in httpx internals.
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from expose.egress.base import EgressHealthCheck, EgressProfile, EgressProfileType

logger = logging.getLogger(__name__)


def _socksio_available() -> bool:
    """Check whether the ``socksio`` package is importable."""
    return importlib.util.find_spec("socksio") is not None


class Socks5EgressProfile(EgressProfile):
    """SOCKS5 proxy egress — routes traffic through a SOCKS5 proxy.

    Typical deployment: ``ssh -D 10899 user@exit-node`` or a dedicated SOCKS5
    daemon (Dante, microsocks). For Tor, the default proxy is
    ``socks5://127.0.0.1:9050``.

    Args:
        proxy_url: SOCKS5 proxy URL, e.g. ``"socks5://127.0.0.1:10899"``.
        dns_through_proxy: If ``True`` (default), resolve DNS through the proxy
            (``socks5h://`` protocol) to prevent DNS leaks. If ``False``, the
            operator's system resolver is used.
    """

    profile_type: EgressProfileType = EgressProfileType.SOCKS5

    def __init__(
        self, proxy_url: str = "socks5://127.0.0.1:1080", dns_through_proxy: bool = True
    ) -> None:
        self._proxy_url = proxy_url
        self._dns_through_proxy = dns_through_proxy

    @property
    def is_anonymizing(self) -> bool:
        """SOCKS5 is anonymizing when DNS is also routed through the proxy.

        When ``dns_through_proxy`` is ``True``, both TCP traffic and DNS
        resolution exit through the proxy — the operator's origin is fully
        masked. When ``False``, the operator's system resolver is exposed,
        so the profile is not fully anonymizing.
        """
        return self._dns_through_proxy

    @property
    def proxy_url(self) -> str:
        """The configured SOCKS5 proxy URL."""
        return self._proxy_url

    def configure_httpx_client(self, **kwargs: Any) -> dict[str, Any]:
        """Return httpx proxy kwargs for SOCKS5 tunnelling.

        When ``dns_through_proxy`` is enabled, the ``socks5://`` scheme is
        rewritten to ``socks5h://`` so httpx instructs the proxy to resolve
        DNS on the operator's behalf — preventing DNS leaks.

        Raises:
            RuntimeError: If the ``socksio`` package is not installed.
        """
        if not _socksio_available():
            msg = (
                "SOCKS5 egress requires the 'socksio' package. "
                "Install it with: pip install socksio"
            )
            raise RuntimeError(msg)

        effective_url = self._proxy_url
        if self._dns_through_proxy and effective_url.startswith("socks5://"):
            effective_url = "socks5h://" + effective_url[len("socks5://") :]
        return {"proxy": effective_url}

    def configure_dns_resolver(self, **kwargs: Any) -> dict[str, Any]:
        """Return DNS resolver kwargs.

        When ``dns_through_proxy`` is ``True``, return empty nameservers to
        signal to collectors that independent DNS resolution should be skipped
        (the proxy handles it). Otherwise, return an empty dict to use the
        system resolver.
        """
        if self._dns_through_proxy:
            return {"nameservers": []}
        return {}

    async def health_check(self) -> EgressHealthCheck:
        """Verify the SOCKS5 proxy is reachable via TCP connect probe.

        Attempts a raw TCP connection to the proxy host:port. This validates
        that the proxy daemon is listening; it does *not* negotiate SOCKS5
        auth or tunnel traffic (that requires a target host).
        """
        parsed = urlparse(self._proxy_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 1080

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


__all__ = ["Socks5EgressProfile"]
