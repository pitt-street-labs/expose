"""Active TLS handshake collector (Tier 3, per SPEC.md section 6.3).

This collector performs TLS handshakes against discovered IP:port pairs (or
domains) and extracts certificate chain details, negotiated protocol version,
cipher suite, and a JARM fingerprint stub.

This is a Tier-3 (active, attribution-gated) collector: the dispatcher is
responsible for ensuring that Tier-3 dispatch gating (SPEC section 6.3 /
ADR-008) is satisfied before calling ``expand()``. This collector does
NOT self-gate.

Certificate verification is intentionally disabled (``CERT_NONE``) because
the collector needs to observe *all* certificates, including self-signed and
expired ones, for attack-surface enumeration. The evidence blob carries the
leaf certificate PEM for downstream storage and fingerprinting.

Credential requirements: none. TLS handshakes do not require API keys.

Dependencies: Python stdlib ``ssl`` + ``asyncio``. The FIPS SHA-256
adapter (``expose.crypto``) is used for certificate fingerprint computation
per ADR-010.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, ClassVar

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
    CollectorSourceUnreachableError,
    Observation,
    ObservationSubject,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.registry import register_collector
from expose.collectors.tiers import CollectorTier
from expose.crypto import compute_cert_fingerprint
from expose.sanitization.text import SanitizationFieldKind, sanitize_field
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

logger = logging.getLogger(__name__)

# Default TLS port when not specified in seed properties.
_DEFAULT_TLS_PORT = 443

# Well-known host used for health checks. Google's front-end servers have
# valid TLS certificates and are highly available.
_HEALTH_CHECK_HOST = "google.com"
_HEALTH_CHECK_PORT = 443


def _compute_jarm(host: str, port: int) -> str | None:
    """Compute a JARM fingerprint for the given host:port.

    JARM works by sending 10 TLS Client Hello packets with different
    parameters and hashing the Server Hello responses. This is a v0.1.0
    stub that returns None. Full JARM implementation is a follow-up.
    """
    logger.debug(
        "JARM computation not yet implemented for %s:%d", host, port
    )
    return None


def _extract_cert_pem(ssl_object: ssl.SSLObject | ssl.SSLSocket) -> bytes | None:
    """Extract the leaf certificate as PEM bytes from an SSL object.

    Returns None if no certificate is available (should not happen for a
    successful TLS handshake, but defensive).
    """
    der_bytes = ssl_object.getpeercert(binary_form=True)
    if der_bytes is None:
        return None
    # Convert DER to PEM using ssl module's helper.
    pem = ssl.DER_cert_to_PEM_cert(der_bytes)
    return pem.encode("ascii")


def _extract_cert_details(
    ssl_object: ssl.SSLObject | ssl.SSLSocket,
) -> dict[str, Any]:
    """Extract certificate metadata from the SSL object.

    Uses ``getpeercert(binary_form=False)`` for parsed fields and
    ``getpeercert(binary_form=True)`` for raw DER (fingerprint computation).
    When verify_mode is CERT_NONE, the parsed dict form returns an empty
    dict, so we fall back to parsing the DER certificate via the
    ``cryptography`` library.
    """
    details: dict[str, Any] = {
        "cert_subject_cn": None,
        "cert_issuer_cn": None,
        "cert_issuer_org": None,
        "cert_serial": None,
        "cert_not_before": None,
        "cert_not_after": None,
        "cert_sans": [],
        "cert_fingerprint_sha256": None,
    }

    der_bytes = ssl_object.getpeercert(binary_form=True)
    if der_bytes is None:
        return details

    # Compute SHA-256 fingerprint via FIPS adapter.
    try:
        details["cert_fingerprint_sha256"] = compute_cert_fingerprint(der_bytes)
    except Exception:
        logger.debug("Failed to compute certificate fingerprint", exc_info=True)

    # Parse the certificate using the cryptography library for rich metadata.
    try:
        from cryptography import x509 as _x509  # noqa: PLC0415
        from cryptography.x509 import ExtensionNotFound  # noqa: PLC0415
        from cryptography.x509.oid import NameOID  # noqa: PLC0415

        cert = _x509.load_der_x509_certificate(der_bytes)

        # Subject CN
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attrs:
                details["cert_subject_cn"] = cn_attrs[0].value
        except Exception:
            logger.debug("Failed to extract subject CN", exc_info=True)

        # Issuer CN and Org
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            if issuer_cn:
                details["cert_issuer_cn"] = issuer_cn[0].value
        except Exception:
            logger.debug("Failed to extract issuer CN", exc_info=True)

        try:
            issuer_org = cert.issuer.get_attributes_for_oid(
                NameOID.ORGANIZATION_NAME
            )
            if issuer_org:
                details["cert_issuer_org"] = issuer_org[0].value
        except Exception:
            logger.debug("Failed to extract issuer org", exc_info=True)

        # Serial number (hex, lowercase)
        details["cert_serial"] = format(cert.serial_number, "x")

        # Validity dates (ISO 8601 UTC)
        if cert.not_valid_before_utc is not None:
            details["cert_not_before"] = (
                cert.not_valid_before_utc.isoformat().replace("+00:00", "Z")
            )
        if cert.not_valid_after_utc is not None:
            details["cert_not_after"] = (
                cert.not_valid_after_utc.isoformat().replace("+00:00", "Z")
            )

        # SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(
                _x509.SubjectAlternativeName
            )
            raw_sans = san_ext.value.get_values_for_type(_x509.DNSName)
            details["cert_sans"] = [
                sanitize_field(san, SanitizationFieldKind.CERT_SAN).value
                for san in raw_sans
            ]
        except ExtensionNotFound:
            details["cert_sans"] = []

    except Exception:
        logger.debug(
            "Failed to parse certificate details via cryptography library",
            exc_info=True,
        )

    return details


async def _tls_handshake(
    host: str, port: int, handshake_timeout: float
) -> tuple[ssl.SSLObject | ssl.SSLSocket, asyncio.StreamWriter]:
    """Perform a TLS handshake and return the SSL object + writer.

    The caller is responsible for closing the writer. Certificate
    verification is disabled so we observe all certificates, including
    self-signed and expired ones.

    Raises ``CollectorSourceUnreachableError`` on connection or handshake
    failure.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=handshake_timeout,
        )
    except TimeoutError as exc:
        msg = f"TLS handshake timed out for {host}:{port}"
        raise CollectorSourceUnreachableError(msg) from exc
    except ssl.SSLError as exc:
        # SSLError is a subclass of OSError, so this must come before the
        # OSError handler to produce the correct error message.
        msg = f"TLS handshake failed for {host}:{port}: {exc}"
        raise CollectorSourceUnreachableError(msg) from exc
    except (ConnectionRefusedError, OSError) as exc:
        msg = f"Connection refused for {host}:{port}: {exc}"
        raise CollectorSourceUnreachableError(msg) from exc

    ssl_object = writer.transport.get_extra_info("ssl_object")
    if ssl_object is None:
        writer.close()
        msg = f"No SSL object available after handshake to {host}:{port}"
        raise CollectorSourceUnreachableError(msg)

    return ssl_object, writer


@register_collector
class ActiveTlsCollector(Collector):
    """Perform TLS handshakes and extract certificate metadata.

    Tier-3 active collector. Dispatch gating is the dispatcher's
    responsibility per SPEC section 6.3 -- this collector does not import
    or call ``assert_tier_3_dispatch_allowed``.
    """

    collector_id: str = "active-tls-handshake"
    collector_version: str = "0.1.0"
    tier: CollectorTier = CollectorTier.TIER_3
    requires_credentials: bool = False
    rate_limit_per_minute: int | None = None
    technique_ids: ClassVar[list[str]] = ["T1596.003"]

    def __init__(self, config: CollectorConfig) -> None:
        super().__init__(config)

    async def expand(self, seed: Seed) -> AsyncIterator[Observation]:
        """Perform a TLS handshake for a DOMAIN or IP seed.

        Skips non-DOMAIN/IP seeds. On connection failure or TLS handshake
        error, raises ``CollectorSourceUnreachableError``.
        """
        if seed.seed_type == SeedType.IP:
            host = seed.value
            identifier_type = ExtendedIdentifierType.IP
            identifier_value = host
        elif seed.seed_type == SeedType.DOMAIN:
            host = seed.value
            identifier_type = ExtendedIdentifierType.DOMAIN
            identifier_value = host
        else:
            return

        port = int(seed.properties.get("port", _DEFAULT_TLS_PORT))

        ssl_object, writer = await _tls_handshake(
            host, port, self.config.request_timeout_seconds
        )

        try:
            # Extract TLS session metadata.
            tls_version = ssl_object.version()
            cipher_info = ssl_object.cipher()
            cipher_suite = cipher_info[0] if cipher_info else None

            # Extract certificate details.
            cert_details = _extract_cert_details(ssl_object)

            # Extract leaf certificate PEM for evidence blob.
            pem_bytes = _extract_cert_pem(ssl_object)

            # Compute JARM fingerprint (stub for v0.1.0).
            jarm = _compute_jarm(host, port)

            payload: dict[str, Any] = {
                "tls_version": tls_version,
                "cipher_suite": cipher_suite,
                "cert_subject_cn": cert_details["cert_subject_cn"],
                "cert_issuer_cn": cert_details["cert_issuer_cn"],
                "cert_issuer_org": cert_details["cert_issuer_org"],
                "cert_serial": cert_details["cert_serial"],
                "cert_not_before": cert_details["cert_not_before"],
                "cert_not_after": cert_details["cert_not_after"],
                "cert_sans": cert_details["cert_sans"],
                "cert_fingerprint_sha256": cert_details["cert_fingerprint_sha256"],
                "jarm_fingerprint": jarm,
            }

            yield Observation(
                collector_id=self.collector_id,
                collector_version=self.collector_version,
                tenant_id=self.config.tenant_id,
                observation_type=ObservationType.TLS_HANDSHAKE,
                subject=ObservationSubject(
                    identifier_type=identifier_type,
                    identifier_value=identifier_value,
                ),
                observed_at=datetime.now(UTC),
                structured_payload=payload,
                evidence_blob=pem_bytes,
                evidence_blob_content_type="application/x-pem-file" if pem_bytes else None,
            )
        finally:
            writer.close()

    async def health_check(self) -> CollectorHealthCheck:
        """Quick TLS handshake to a well-known host to verify connectivity.

        Returns a ``CollectorHealthCheck`` with SUCCESS or FAILURE status.
        Does not raise.
        """
        start = datetime.now(UTC)
        try:
            _ssl_object, writer = await _tls_handshake(
                _HEALTH_CHECK_HOST,
                _HEALTH_CHECK_PORT,
                handshake_timeout=10.0,
            )
            writer.close()
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
    "ActiveTlsCollector",
]
