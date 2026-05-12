"""Active port-probe collector (Tier 3, per SPEC.md section 6.3).

Direct TCP connect scanning on discovered IP and domain entities, filling the
gap when Shodan/Censys don't index the target.  For DOMAIN seeds, resolves
the domain to an IP first via ``socket.getaddrinfo``, then scans the first
resolved address.  For IP seeds, scans directly.

On TLS-capable ports (443, 8443, 993, 995), a basic TLS handshake is
attempted to extract certificate metadata (subject CN, issuer CN, expiry,
negotiated TLS version).

This is a Tier-3 (active, attribution-gated) collector: the dispatcher is
responsible for ensuring that Tier-3 dispatch gating (SPEC section 6.3 /
ADR-008) is satisfied before calling ``expand()``.  This collector does
NOT self-gate.

Credential requirements: none.  Port probing uses raw TCP connect and stdlib
TLS; no API keys needed.

Dependencies: stdlib only (``asyncio``, ``ssl``, ``socket``).
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
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
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

logger = logging.getLogger(__name__)

# Top 30 most commonly exposed service ports.
DEFAULT_PORTS: list[int] = sorted([
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 8888, 9090, 9200, 9300, 27017, 27018,
])

# Ports where a TLS handshake should be attempted for certificate extraction.
_TLS_PROBE_PORTS: frozenset[int] = frozenset({443, 8443, 993, 995})

# Default TCP connect timeout per port (seconds).
_DEFAULT_PROBE_TIMEOUT: float = 3.0

# Maximum concurrent TCP probes to avoid overwhelming the target.
_PROBE_SEMAPHORE_LIMIT: int = 20

# Health-check target -- Google public DNS, port 53 (highly available).
_HEALTH_CHECK_HOST = "8.8.8.8"
_HEALTH_CHECK_PORT = 53


# === DNS resolution ===========================================================


def _resolve_domain(domain: str) -> str | None:
    """Resolve a domain to its first IPv4 address via ``socket.getaddrinfo``.

    Returns ``None`` if resolution fails.  Only returns the first resolved
    address to respect the "scan first resolved IP only" policy.
    """
    try:
        results = socket.getaddrinfo(
            domain, None, socket.AF_INET, socket.SOCK_STREAM,
        )
        if results:
            # getaddrinfo returns (family, type, proto, canonname, sockaddr)
            # sockaddr for AF_INET is (address, port)
            return results[0][4][0]
    except (socket.gaierror, OSError):
        logger.warning(
            "active-port-probe: DNS resolution failed for %r", domain,
        )
    return None


# === TCP probe ================================================================


async def _probe_port(
    host: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> bool:
    """Probe a single TCP port.

    Returns ``True`` if the port is open (connection succeeded).
    Any failure (connection refused, timeout, OS-level error) is treated
    as closed/filtered.
    """
    async with semaphore:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, TimeoutError, asyncio.TimeoutError):
            return False


# === TLS probe ================================================================


async def _probe_tls(
    host: str,
    port: int,
    timeout: float,
) -> dict[str, Any] | None:
    """Attempt a TLS handshake on the given host:port.

    Returns a dict with TLS metadata if the handshake succeeds, or ``None``
    on failure.  Certificate verification is disabled so we observe all
    certificates, including self-signed and expired ones.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=timeout,
        )
    except (OSError, TimeoutError, asyncio.TimeoutError, ssl.SSLError):
        return None

    try:
        ssl_object = writer.transport.get_extra_info("ssl_object")
        if ssl_object is None:
            return None

        tls_info: dict[str, Any] = {
            "tls_version": ssl_object.version(),
        }

        # Extract certificate details from the DER-encoded certificate.
        der_bytes = ssl_object.getpeercert(binary_form=True)
        if der_bytes is not None:
            try:
                from cryptography import x509 as _x509  # noqa: PLC0415
                from cryptography.x509.oid import NameOID  # noqa: PLC0415

                cert = _x509.load_der_x509_certificate(der_bytes)

                # Subject CN
                cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attrs:
                    tls_info["cert_subject_cn"] = cn_attrs[0].value

                # Issuer CN
                issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                if issuer_cn:
                    tls_info["cert_issuer_cn"] = issuer_cn[0].value

                # Expiry (ISO 8601 UTC)
                if cert.not_valid_after_utc is not None:
                    tls_info["cert_not_after"] = (
                        cert.not_valid_after_utc.isoformat().replace("+00:00", "Z")
                    )
            except Exception:
                logger.debug(
                    "active-port-probe: failed to parse cert on %s:%d",
                    host, port, exc_info=True,
                )

        return tls_info
    finally:
        writer.close()
        await writer.wait_closed()


# === Collector ================================================================


@register_collector
class ActivePortProbeCollector(Collector):
    """Direct TCP connect scan on IP and domain entities.

    Tier-3 active collector.  Dispatch gating is the dispatcher's
    responsibility per SPEC section 6.3 -- this collector does not import
    or call ``assert_tier_3_dispatch_allowed``.

    Accepts DOMAIN and IP seeds.  For DOMAIN seeds, resolves to the first
    IP via ``socket.getaddrinfo``.  Probes a curated set of 30 common ports
    and attempts TLS handshakes on TLS-capable ports (443, 8443, 993, 995).
    """

    collector_id: str = "active-port-probe"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_3
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None
    technique_ids: ClassVar[list[str]] = ["T1046"]

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Probe ports on an IP or domain seed and yield observations.

        For DOMAIN seeds, resolves the domain to the first IP address.
        For each target IP, probes all ports in ``DEFAULT_PORTS`` with
        bounded concurrency.  On TLS-capable open ports, attempts a
        TLS handshake to extract certificate metadata.

        Yields one ``Observation`` per target IP with port scan results
        and optional TLS metadata.
        """
        if seed.seed_type == SeedType.IP:
            ip = seed.value.strip()
            subject_value = ip
            identifier_type = ExtendedIdentifierType.IP
        elif seed.seed_type == SeedType.DOMAIN:
            domain = seed.value.strip().lower()
            ip = _resolve_domain(domain)
            if ip is None:
                logger.warning(
                    "active-port-probe: could not resolve domain %r, skipping",
                    domain,
                )
                return
            subject_value = ip
            identifier_type = ExtendedIdentifierType.IP
        else:
            logger.warning(
                "active-port-probe: skipping unsupported seed type %s",
                seed.seed_type,
            )
            return

        # Allow per-seed port list override via seed properties.
        ports: list[int] = seed.properties.get("ports", DEFAULT_PORTS)

        timeout: float = self.config.extra.get(
            "probe_timeout_seconds", _DEFAULT_PROBE_TIMEOUT,
        )

        # Semaphore bounds concurrent probes.
        semaphore = asyncio.Semaphore(_PROBE_SEMAPHORE_LIMIT)

        # Probe all ports concurrently (bounded by semaphore).
        results = await asyncio.gather(
            *(
                _probe_port(ip, port, timeout, semaphore)
                for port in ports
            ),
            return_exceptions=True,
        )

        open_ports: list[int] = []
        for port, result in zip(ports, results, strict=True):
            if isinstance(result, BaseException):
                continue
            if result:
                open_ports.append(port)

        # Attempt TLS handshakes on TLS-capable open ports.
        tls_results: dict[int, dict[str, Any]] = {}
        tls_ports = [p for p in open_ports if p in _TLS_PROBE_PORTS]
        if tls_ports:
            tls_probes = await asyncio.gather(
                *(_probe_tls(ip, p, timeout) for p in tls_ports),
                return_exceptions=True,
            )
            for port, tls_result in zip(tls_ports, tls_probes, strict=True):
                if isinstance(tls_result, BaseException) or tls_result is None:
                    continue
                tls_results[port] = tls_result

        # Build the structured payload.
        payload: dict[str, Any] = {
            "open_ports": sorted(open_ports),
            "source": "active-probe",
            "_collector_id": "active-port-probe",
        }

        # Add TLS metadata from the first successful TLS probe (prefer 443).
        for preferred_port in [443, 8443, 993, 995]:
            if preferred_port in tls_results:
                tls_data = tls_results[preferred_port]
                if "tls_version" in tls_data:
                    payload["tls_version"] = tls_data["tls_version"]
                if "cert_subject_cn" in tls_data:
                    payload["cert_subject_cn"] = tls_data["cert_subject_cn"]
                if "cert_issuer_cn" in tls_data:
                    payload["cert_issuer_cn"] = tls_data["cert_issuer_cn"]
                if "cert_not_after" in tls_data:
                    payload["cert_not_after"] = tls_data["cert_not_after"]
                break

        # Include all per-port TLS details if multiple ports had TLS.
        if tls_results:
            payload["tls_details"] = {
                str(p): tls_results[p] for p in sorted(tls_results)
            }

        # Include domain context if seed was a domain.
        if seed.seed_type == SeedType.DOMAIN:
            payload["resolved_from_domain"] = seed.value.strip().lower()

        yield Observation(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            tenant_id=self.config.tenant_id,
            observation_type=ObservationType.PORT_SCAN_RESULT,
            subject=ObservationSubject(
                identifier_type=identifier_type,
                identifier_value=subject_value,
            ),
            observed_at=datetime.now(UTC),
            structured_payload=payload,
        )

    async def health_check(self) -> CollectorHealthCheck:
        """Probe a well-known host:port to verify TCP connectivity works.

        Attempts a TCP connect to 8.8.8.8:53 (Google public DNS).
        Returns a ``CollectorHealthCheck`` with SUCCESS or FAILURE status.
        Does not raise.
        """
        start = datetime.now(UTC)
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(_HEALTH_CHECK_HOST, _HEALTH_CHECK_PORT),
                timeout=self.config.request_timeout_seconds,
            )
            writer.close()
            await writer.wait_closed()
            elapsed_ms = (datetime.now(UTC) - start).total_seconds() * 1000
            return CollectorHealthCheck(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                status=CollectorStatus.SUCCESS,
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
    "ActivePortProbeCollector",
]
