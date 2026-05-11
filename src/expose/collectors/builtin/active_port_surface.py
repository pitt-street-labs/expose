"""Active port-surface collector (Tier 3, per SPEC.md section 6.3).

Light port-surface enumeration on attributed IP addresses.  Probes a curated
set of common service ports to identify exposed services, grabs service
banners, classifies ports by risk category, and maps well-known ports to
expected service names.  This is NOT a full Nmap-style scan — it's a
targeted check of high-value ports.

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
from expose.sanitization.text import SanitizationFieldKind, sanitize_field
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

logger = logging.getLogger(__name__)

# Top-100 curated service ports.  Covers common services plus commonly-
# attacked management, database, and application ports.  Concurrency is
# bounded by _PROBE_SEMAPHORE_LIMIT rather than list size.
DEFAULT_PORTS: list[int] = sorted([
    # Original 27 ports
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 1433, 1521, 2222, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 8888, 9090, 9200, 9443,
    27017,
    # Expanded commonly-attacked ports
    135,    # MSRPC
    139,    # NetBIOS
    161,    # SNMP
    389,    # LDAP
    514,    # Syslog
    636,    # LDAPS
    1080,   # SOCKS proxy
    1883,   # MQTT
    2049,   # NFS
    2083,   # cPanel
    2087,   # WHM
    3000,   # Grafana / Node.js
    4443,   # Various HTTPS alt
    5000,   # Docker Registry
    5060,   # SIP
    5222,   # XMPP
    5601,   # Kibana
    5672,   # AMQP / RabbitMQ
    6443,   # Kubernetes API
    7443,   # Various HTTPS alt
    8000,   # Alt HTTP
    8081,   # Alt HTTP
    8181,   # Alt HTTP
    8444,   # Alt HTTPS
    8880,   # Alt HTTP
    9000,   # SonarQube
    9042,   # Cassandra
    9100,   # JetDirect
    10000,  # Webmin
    11211,  # Memcached
    15672,  # RabbitMQ Management
    27018,  # MongoDB shard
    50000,  # Jenkins
])

# Default TCP connect timeout per port (seconds).
_DEFAULT_PROBE_TIMEOUT: float = 3.0

# Banner read timeout (seconds).  Many services send banners on connect
# (SSH, SMTP, FTP, etc.).  Keep short to avoid blocking on silent ports.
_DEFAULT_BANNER_TIMEOUT: float = 2.0

# Maximum banner read size (bytes).
_BANNER_MAX_BYTES: int = 1024

# Maximum concurrent TCP probes.  Prevents socket exhaustion when probing
# the full port list against many seeds.
_PROBE_SEMAPHORE_LIMIT: int = 50

# Health-check target — Google public DNS, port 53 (highly available).
_HEALTH_CHECK_HOST = "8.8.8.8"
_HEALTH_CHECK_PORT = 53


# === Service identification ===================================================
# Maps well-known ports to expected service names.

PORT_SERVICE_MAP: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    514: "syslog",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    1883: "mqtt",
    2049: "nfs",
    2083: "cpanel",
    2087: "whm",
    2222: "alt-ssh",
    3000: "grafana",
    3306: "mysql",
    3389: "rdp",
    4443: "alt-https",
    5000: "docker-registry",
    5060: "sip",
    5222: "xmpp",
    5432: "postgresql",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    6379: "redis",
    6443: "k8s-api",
    7443: "alt-https",
    8000: "alt-http",
    8080: "alt-http",
    8081: "alt-http",
    8181: "alt-http",
    8443: "alt-https",
    8444: "alt-https",
    8880: "alt-http",
    8888: "alt-http",
    9000: "sonarqube",
    9042: "cassandra",
    9090: "alt-http",
    9100: "jetdirect",
    9200: "elasticsearch",
    9443: "alt-https",
    10000: "webmin",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
    27018: "mongodb-shard",
    50000: "jenkins",
}


# === Port risk categories =====================================================

_MANAGEMENT_PORTS: frozenset[int] = frozenset([
    22, 23, 2222,       # SSH / Telnet
    3389,               # RDP
    5900,               # VNC
    10000,              # Webmin
    2083, 2087,         # cPanel / WHM
    135, 139, 445,      # Windows management
    161,                # SNMP
])

_DATABASE_PORTS: frozenset[int] = frozenset([
    1433,   # MSSQL
    1521,   # Oracle
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    9200,   # Elasticsearch
    9042,   # Cassandra
    11211,  # Memcached
    27017,  # MongoDB
    27018,  # MongoDB shard
])

_WEB_PORTS: frozenset[int] = frozenset([
    80, 443,
    4443, 7443, 8000, 8080, 8081, 8181, 8443, 8444, 8880, 8888,
    9000, 9090, 9443,
    3000,   # Grafana / Node.js
    5601,   # Kibana
    15672,  # RabbitMQ Management UI
    50000,  # Jenkins
])


def classify_port(port: int) -> str:
    """Return the risk category for a port.

    Categories: ``management``, ``database``, ``web``, ``other``.
    """
    if port in _MANAGEMENT_PORTS:
        return "management"
    if port in _DATABASE_PORTS:
        return "database"
    if port in _WEB_PORTS:
        return "web"
    return "other"


def identify_service(port: int) -> str:
    """Return the expected service name for a port, or ``unknown``."""
    return PORT_SERVICE_MAP.get(port, "unknown")


# === Probe function ===========================================================

async def _probe_port(
    host: str,
    port: int,
    probe_timeout: float,
    semaphore: asyncio.Semaphore | None = None,
    grab_banner: bool = True,
    banner_timeout: float = _DEFAULT_BANNER_TIMEOUT,
) -> tuple[bool, str | None]:
    """Probe a single TCP port and optionally grab its service banner.

    Returns ``(is_open, banner_or_none)``.  Uses ``asyncio.open_connection``
    with a short timeout.  Any failure (connection refused, timeout,
    OS-level error) is treated as the port being closed or filtered.

    When ``semaphore`` is provided, acquires it before connecting to bound
    concurrency.  When ``grab_banner`` is True, reads up to
    ``_BANNER_MAX_BYTES`` with ``banner_timeout`` seconds.
    """
    async def _do_probe() -> tuple[bool, str | None]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=probe_timeout,
            )
        except (OSError, TimeoutError):
            return False, None

        banner: str | None = None
        if grab_banner:
            try:
                raw = await asyncio.wait_for(
                    reader.read(_BANNER_MAX_BYTES),
                    timeout=banner_timeout,
                )
                if raw:
                    sanitized = sanitize_field(
                        raw.decode("utf-8", errors="replace"),
                        SanitizationFieldKind.GENERIC,
                    )
                    banner = sanitized.value
            except (OSError, TimeoutError, UnicodeDecodeError):
                # Banner grab is best-effort; port is still open.
                pass

        writer.close()
        await writer.wait_closed()
        return True, banner

    if semaphore is not None:
        async with semaphore:
            return await _do_probe()
    return await _do_probe()


@register_collector
class ActivePortSurfaceCollector(Collector):
    """Probe a curated set of TCP ports on an IP seed.

    Tier-3 active collector.  Dispatch gating is the dispatcher's
    responsibility per SPEC section 6.3 — this collector does not import
    or call ``assert_tier_3_dispatch_allowed``.
    """

    collector_id: str = "active-port-surface"
    collector_version: str = "0.2.0"
    tier: CollectorTier = CollectorTier.TIER_3
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None
    technique_ids: ClassVar[list[str]] = ["T1046"]

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Probe ports on an IP seed and yield a single observation.

        Skips non-IP seeds with a warning.  Uses ``asyncio.gather`` with
        ``return_exceptions=True`` to probe all ports concurrently, bounded
        by a semaphore (max 50 concurrent probes) to prevent socket
        exhaustion.  Yields exactly one observation per seed (even when no
        ports are open — the absence of open ports is informative).
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

        # Semaphore bounds concurrent probes to prevent socket exhaustion.
        semaphore = asyncio.Semaphore(_PROBE_SEMAPHORE_LIMIT)

        # Probe all ports concurrently (bounded by semaphore).
        results = await asyncio.gather(
            *(
                _probe_port(ip, port, timeout, semaphore=semaphore)
                for port in ports
            ),
            return_exceptions=True,
        )

        open_ports: list[int] = []
        banners: dict[int, str] = {}
        services: dict[int, str] = {}
        port_categories: dict[int, str] = {}

        for port, result in zip(ports, results, strict=True):
            # Exceptions from gather are treated as closed (belt-and-braces
            # — _probe_port already catches internally, but an unexpected
            # exception from asyncio internals should not crash the run).
            if isinstance(result, BaseException):
                continue
            is_open, banner = result
            if is_open:
                open_ports.append(port)
                services[port] = identify_service(port)
                port_categories[port] = classify_port(port)
                if banner:
                    banners[port] = banner

        closed_count = len(ports) - len(open_ports)

        payload: dict[str, Any] = {
            "open_ports": sorted(open_ports),
            "closed_ports_probed": closed_count,
            "total_ports_probed": len(ports),
            "probe_timeout_seconds": timeout,
            "banners": {
                str(p): banners[p] for p in sorted(banners)
            },
            "services": {
                str(p): services[p] for p in sorted(services)
            },
            "port_categories": {
                str(p): port_categories[p] for p in sorted(port_categories)
            },
            "_collector_id": "active-port-surface",
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
            is_open, _banner = await _probe_port(
                _HEALTH_CHECK_HOST,
                _HEALTH_CHECK_PORT,
                probe_timeout=self.config.request_timeout_seconds,
                grab_banner=False,
            )
            elapsed_ms = (datetime.now(UTC) - start).total_seconds() * 1000
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=(
                    CollectorStatus.SUCCESS if is_open else CollectorStatus.FAILURE
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
    "PORT_SERVICE_MAP",
    "ActivePortSurfaceCollector",
    "classify_port",
    "identify_service",
]
