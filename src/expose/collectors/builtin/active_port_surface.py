"""Active port-surface collector (Tier 3, per SPEC.md section 6.3).

Light port-surface enumeration on attributed IP addresses.  Probes a curated
set of common service ports to identify exposed services.  This is NOT a
full Nmap-style scan — it's a targeted check of high-value ports.

This is a Tier-3 (active, attribution-gated) collector: the dispatcher is
responsible for ensuring that Tier-3 dispatch gating (SPEC section 6.3 /
ADR-008) is satisfied before calling ``expand()``.  This collector does
NOT self-gate.

Credential requirements: none.  Port probing uses raw TCP connect and does
not require API keys.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, ClassVar

from expose.collectors.base import (
    Collector,
    CollectorHealthCheck,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.sanitization.canonicalize import canonicalize_ip
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

logger = logging.getLogger(__name__)

# Curated set of common service ports.  Deliberately small (<30 entries) so
# that ``asyncio.gather`` over the full list stays bounded.
DEFAULT_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 1433, 1521, 2222, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 8888, 9090, 9200, 9443,
    27017,
]

# Default TCP connect timeout per port (seconds).
_DEFAULT_PROBE_TIMEOUT: float = 3.0

# Health-check target — Google public DNS, port 53 (highly available).
_HEALTH_CHECK_HOST = "8.8.8.8"
_HEALTH_CHECK_PORT = 53


async def _probe_port(host: str, port: int, probe_timeout: float) -> bool:
    """Return True if a TCP connection to ``host:port`` succeeds.

    Uses ``asyncio.open_connection`` with a short timeout.  Any failure
    (connection refused, timeout, OS-level error) is treated as the port
    being closed or filtered — not an error.
    """
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=probe_timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, TimeoutError):
        return False


@register_collector
class ActivePortSurfaceCollector(Collector):
    """Probe a curated set of TCP ports on an IP seed.

    Tier-3 active collector.  Dispatch gating is the dispatcher's
    responsibility per SPEC section 6.3 — this collector does not import
    or call ``assert_tier_3_dispatch_allowed``.
    """

    collector_id: str = "active-port-surface"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_3
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None
    technique_ids: ClassVar[list[str]] = ["T1046"]

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Probe ports on an IP seed and yield a single observation.

        Skips non-IP seeds with a warning.  Uses ``asyncio.gather`` with
        ``return_exceptions=True`` to probe all ports concurrently.  Yields
        exactly one observation per seed (even when no ports are open —
        the absence of open ports is informative).
        """
        if seed.seed_type != SeedType.IP:
            logger.warning(
                "active-port-surface: skipping non-IP seed type %s",
                seed.seed_type,
            )
            return

        ip = seed.value
        canonical_ip = canonicalize_ip(ip)

        # Allow per-seed port list override via seed properties.
        ports: list[int] = seed.properties.get("ports", DEFAULT_PORTS)

        timeout: float = self.config.extra.get(
            "probe_timeout_seconds", _DEFAULT_PROBE_TIMEOUT
        )

        # Probe all ports concurrently.
        results = await asyncio.gather(
            *(_probe_port(ip, port, timeout) for port in ports),
            return_exceptions=True,
        )

        open_ports: list[int] = []
        for port, result in zip(ports, results, strict=True):
            # Exceptions from gather are treated as closed (belt-and-braces
            # — _probe_port already catches internally, but an unexpected
            # exception from asyncio internals should not crash the run).
            if result is True:
                open_ports.append(port)

        closed_count = len(ports) - len(open_ports)

        payload: dict[str, Any] = {
            "open_ports": sorted(open_ports),
            "closed_ports_probed": closed_count,
            "total_ports_probed": len(ports),
            "probe_timeout_seconds": timeout,
        }

        yield Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.PORT_SCAN_RESULT,
            subject=ObservationSubject(
                identifier_type=ExtendedIdentifierType.IP,
                identifier_value=canonical_ip,
            ),
            observed_at=datetime.now(UTC),
            structured_payload=payload,
        )

    async def health_check(self) -> CollectorHealthCheck:
        """Probe a well-known host:port to verify TCP connectivity works.

        Returns a ``CollectorHealthCheck`` with SUCCESS or FAILURE status.
        Does not raise.
        """
        start = datetime.now(UTC)
        try:
            result = await _probe_port(
                _HEALTH_CHECK_HOST,
                _HEALTH_CHECK_PORT,
                probe_timeout=self.config.request_timeout_seconds,
            )
            elapsed_ms = (datetime.now(UTC) - start).total_seconds() * 1000
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=(
                    CollectorStatus.SUCCESS if result else CollectorStatus.FAILURE
                ),
                checked_at=start,
                latency_ms=elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = (datetime.now(UTC) - start).total_seconds() * 1000
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.FAILURE,
                checked_at=start,
                latency_ms=elapsed_ms,
                error_message=str(exc),
            )


__all__ = [
    "DEFAULT_PORTS",
    "ActivePortSurfaceCollector",
]
