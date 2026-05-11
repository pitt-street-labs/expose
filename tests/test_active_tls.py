"""Tests for the active-tls-handshake collector.

Exercises all code paths with fully mocked ssl/asyncio — no live network
connections are ever made. The mock strategy patches ``asyncio.open_connection``
and the ssl module so that ``_tls_handshake`` operates on mocks that simulate
TLS connections with configurable certificate metadata.

Coverage:
    1.  Happy path: domain seed, mock TLS handshake, observations yielded
    2.  IP seed with custom port — uses ``seed.properties["port"]``
    3.  Non-matching seed type skipped (ASN seed)
    4.  Connection refused — raises CollectorSourceUnreachableError
    5.  TLS handshake timeout — raises CollectorSourceUnreachableError
    6.  Self-signed cert — still yields observation (we don't verify)
    7.  Health check success
    8.  Health check failure
    9.  Evidence blob contains PEM bytes
    10. SANs are sanitized
    11. Cipher strength classification (all categories)
    12. Key size extraction and weakness detection
    13. Protocol version assessment
    14. _collector_id present in all observation payloads
    15. Chain depth and self-signed detection
"""

from __future__ import annotations

import asyncio
import ssl
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

from expose.collectors.base import (
    Collector,
    CollectorConfig,
    CollectorHealthCheck,
    CollectorSourceUnreachableError,
    Observation,
    ObservationType,
    Seed,
    SeedType,
)
from expose.collectors.builtin.active_tls import (
    ActiveTlsCollector,
    _assess_protocol_version,
    _classify_cipher_strength,
    _compute_jarm,
    _extract_cert_details,
    _extract_cert_pem,
)
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.collectors.tiers import CollectorTier
from expose.types.canonical import CollectorStatus, ExtendedIdentifierType

# Deterministic test IDs (project convention).
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000D001")
RUN_ID = UUID("018f1f00-0000-7000-8000-00000000D002")

# A self-signed test certificate (PEM) generated for testing purposes.
# This is a real, parseable X.509 certificate (self-signed, CN=test.com,
# O=Test Org, SAN=test.com,www.test.com). Generated via cryptography library.
_TEST_CERT_PEM = b"""\
-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUBqUVhNou9F+z6x47YTrW3jOChWIwDQYJKoZIhvcNAQEL
BQAwJjERMA8GA1UEAwwIdGVzdC5jb20xETAPBgNVBAoMCFRlc3QgT3JnMB4XDTI2
MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAwMFowJjERMA8GA1UEAwwIdGVzdC5jb20x
ETAPBgNVBAoMCFRlc3QgT3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEA48ftDDtC922BKqu0y1C2ks8p3EnW6vV1/AjPjdYf+4TP7NJ3bB+yaBPl+BnI
AY/y+7u/BuXZstKf9lxQ5kxaSRVisptPfwmcY3gKiwMLKj0PRWoRDdMVmzFDy8Hf
Zi9mPw0Qo6uevgowogEhGRpXN3QaLIfNjhE6ea6zu5Pz/HVbY5DGy8meY2QzO8Hi
nNLJ/6OS4X/cCGJxXo6XZzl9oEDBa6cj0gGDUqbxwzpaJetc/Oud4SNWiAS+G/R8
FtPZ+ghpPSnZEQlw+TsbIL7kyUJonuoohpD/AZusKrtnSt07hQFJ6nlA9bU1H1x5
IlhDCx3cySqyO/wFRRXzhQDi+QIDAQABoyUwIzAhBgNVHREEGjAYggh0ZXN0LmNv
bYIMd3d3LnRlc3QuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQApZFQ2D5tOYbmn+a2C
ytnp6e2/8YztPmJ3XdhjS9P5pkba1fxOPpxdL/uoiQ+LvdC70UhuydToAMyM4BF2
Yzbygb4mdUtxq3fIr8vYQbTkKCVItJY0x6qR78nR/f3yLfnGBXkOq2yp7fp7ka6K
I4uTDfipE9DDNQSxVHXyvax+GG/3ZITXUsegzmMMta2IJZDHXGmBTeG7+T5PHhfb
HZ3+GTPYnOLo+tFLzRaPqZ4VyyKe3Q02JMVTcyIZVOFIx6M/Q+sfebUPiC0pWvfF
OyFdQcs1ZImTeoencQsURr5sMVN5JGfmpwAftm7c2CLeQQRxH8KQSWIIzhiqti8A
8gCd
-----END CERTIFICATE-----
"""

# Corresponding DER bytes (decoded from the PEM above).
_TEST_CERT_DER = ssl.PEM_cert_to_DER_cert(_TEST_CERT_PEM.decode("ascii"))


def _config(**extra: object) -> CollectorConfig:
    """Build a minimal CollectorConfig for test use."""
    return CollectorConfig(
        tenant_id=TENANT_ID,
        run_id=RUN_ID,
        request_timeout_seconds=5.0,
        extra=dict(extra),  # type: ignore[arg-type]
    )


def _make_mock_ssl_object(
    *,
    der_bytes: bytes = _TEST_CERT_DER,
    version: str = "TLSv1.3",
    cipher: tuple[str, str, int] = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
) -> MagicMock:
    """Build a mock ssl.SSLObject with configurable certificate and TLS metadata."""
    ssl_obj = MagicMock(spec=ssl.SSLObject)
    ssl_obj.getpeercert.side_effect = lambda binary_form=False: (
        der_bytes if binary_form else {}
    )
    ssl_obj.version.return_value = version
    ssl_obj.cipher.return_value = cipher
    return ssl_obj


def _make_mock_writer(ssl_object: MagicMock) -> MagicMock:
    """Build a mock asyncio.StreamWriter with transport -> ssl_object."""
    transport = MagicMock()
    transport.get_extra_info.side_effect = lambda key: (
        ssl_object if key == "ssl_object" else None
    )
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.transport = transport
    writer.close = MagicMock()
    return writer


async def _collect(
    seed: Seed, config: CollectorConfig | None = None
) -> list[Observation]:
    """Run expand() and collect all observations into a list."""
    cfg = config or _config()
    collector = ActiveTlsCollector(cfg)
    results: list[Observation] = []
    async for obs in collector.expand(seed):
        results.append(obs)
    return results


# ======================================================================
# 1. Happy path — domain seed yields TLS_HANDSHAKE observation
# ======================================================================
class TestHappyPathDomainSeed:
    """Test 1: Domain seed produces a TLS_HANDSHAKE observation with cert details."""

    async def test_domain_seed_yields_tls_observation(self) -> None:
        ssl_obj = _make_mock_ssl_object()
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="test.com")
            observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.collector_id == "active-tls-handshake"
        assert obs.collector_version == "0.1.0"
        assert obs.observation_type == ObservationType.TLS_HANDSHAKE
        assert obs.subject.identifier_type == ExtendedIdentifierType.DOMAIN
        assert obs.subject.identifier_value == "test.com"
        assert obs.tenant_id == TENANT_ID
        assert obs.structured_payload["tls_version"] == "TLSv1.3"
        assert obs.structured_payload["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
        assert obs.structured_payload["cert_serial"] is not None
        assert obs.structured_payload["cert_fingerprint_sha256"] is not None
        # JARM is stubbed to None in v0.1.0.
        assert obs.structured_payload["jarm_fingerprint"] is None
        # New fields from enhanced analysis.
        assert obs.structured_payload["_collector_id"] == "active-tls-handshake"
        assert obs.structured_payload["cipher_strength"] == "strong"
        assert obs.structured_payload["protocol_assessment"] == "preferred"
        assert obs.structured_payload["key_algorithm"] == "RSA"
        assert obs.structured_payload["key_size_bits"] == 2048
        assert obs.structured_payload["key_weak"] is False
        # Test cert is self-signed (subject == issuer).
        assert obs.structured_payload["self_signed"] is True
        assert obs.structured_payload["chain_depth"] == 1
        # Writer should be closed after extraction.
        writer.close.assert_called_once()


# ======================================================================
# 2. IP seed with custom port
# ======================================================================
class TestIpSeedCustomPort:
    """Test 2: IP seed uses seed.properties['port'] for custom port."""

    async def test_ip_seed_with_custom_port(self) -> None:
        ssl_obj = _make_mock_ssl_object()
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(
                seed_type=SeedType.IP,
                value="192.0.2.1",
                properties={"port": 8443},
            )
            observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.subject.identifier_type == ExtendedIdentifierType.IP
        assert obs.subject.identifier_value == "192.0.2.1"

        # Verify the connection was made to the custom port.
        call_args = mock_open.call_args
        assert call_args[0][0] == "192.0.2.1"
        assert call_args[0][1] == 8443


# ======================================================================
# 3. Non-matching seed type skipped
# ======================================================================
class TestNonMatchingSeedType:
    """Test 3: ASN seed produces no observations."""

    async def test_asn_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ASN, value="AS13335")
        observations = await _collect(seed)
        assert observations == []

    async def test_organization_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.ORGANIZATION, value="ACME Corp")
        observations = await _collect(seed)
        assert observations == []

    async def test_cidr_seed_skipped(self) -> None:
        seed = Seed(seed_type=SeedType.CIDR, value="192.0.2.0/24")
        observations = await _collect(seed)
        assert observations == []


# ======================================================================
# 4. Connection refused raises CollectorSourceUnreachableError
# ======================================================================
class TestConnectionRefused:
    """Test 4: Connection refused raises CollectorSourceUnreachableError."""

    async def test_connection_refused_raises_source_unreachable(self) -> None:
        mock_open = AsyncMock(
            side_effect=ConnectionRefusedError("Connection refused")
        )

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="closed.example.com")
            with pytest.raises(CollectorSourceUnreachableError, match="Connection refused"):
                await _collect(seed)

    async def test_os_error_raises_source_unreachable(self) -> None:
        mock_open = AsyncMock(
            side_effect=OSError("Network is unreachable")
        )

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="unreachable.example.com")
            with pytest.raises(CollectorSourceUnreachableError):
                await _collect(seed)


# ======================================================================
# 5. TLS handshake timeout raises CollectorSourceUnreachableError
# ======================================================================
class TestTlsTimeout:
    """Test 5: Timeout raises CollectorSourceUnreachableError."""

    async def test_timeout_raises_source_unreachable(self) -> None:
        mock_open = AsyncMock(side_effect=TimeoutError())

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="slow.example.com")
            with pytest.raises(
                CollectorSourceUnreachableError, match="timed out"
            ):
                await _collect(seed)


# ======================================================================
# 6. Self-signed cert still yields observation
# ======================================================================
class TestSelfSignedCert:
    """Test 6: Self-signed certificates are still observed (CERT_NONE mode)."""

    async def test_self_signed_cert_yields_observation(self) -> None:
        # The test cert IS self-signed. Verify we still get an observation.
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="selfsigned.example.com")
            observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        # Should still have cert details even though it's self-signed.
        assert obs.structured_payload["cert_serial"] is not None
        assert obs.structured_payload["cert_fingerprint_sha256"] is not None
        assert obs.observation_type == ObservationType.TLS_HANDSHAKE


# ======================================================================
# 7. Health check success
# ======================================================================
class TestHealthCheckSuccess:
    """Test 7: Health check returns SUCCESS on successful TLS handshake."""

    async def test_health_check_success(self) -> None:
        ssl_obj = _make_mock_ssl_object()
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            collector = ActiveTlsCollector(_config())
            result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.SUCCESS
        assert result.collector_id == "active-tls-handshake"
        assert result.latency_ms is not None
        assert result.latency_ms >= 0.0
        assert result.error_message is None


# ======================================================================
# 8. Health check failure
# ======================================================================
class TestHealthCheckFailure:
    """Test 8: Health check returns FAILURE on connection error."""

    async def test_health_check_failure_on_connection_error(self) -> None:
        mock_open = AsyncMock(
            side_effect=ConnectionRefusedError("Connection refused")
        )

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            collector = ActiveTlsCollector(_config())
            result = await collector.health_check()

        assert isinstance(result, CollectorHealthCheck)
        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None
        assert "Connection refused" in result.error_message

    async def test_health_check_failure_on_timeout(self) -> None:
        mock_open = AsyncMock(side_effect=TimeoutError())

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            collector = ActiveTlsCollector(_config())
            result = await collector.health_check()

        assert result.status == CollectorStatus.FAILURE
        assert result.error_message is not None


# ======================================================================
# 9. Evidence blob contains PEM bytes
# ======================================================================
class TestEvidenceBlob:
    """Test 9: Evidence blob contains the leaf certificate PEM."""

    async def test_evidence_blob_is_pem(self) -> None:
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.evidence_blob is not None
        assert obs.evidence_blob.startswith(b"-----BEGIN CERTIFICATE-----")
        assert obs.evidence_blob.endswith(b"-----END CERTIFICATE-----\n")
        assert obs.evidence_blob_content_type == "application/x-pem-file"

    async def test_no_cert_means_no_evidence_blob(self) -> None:
        """When no certificate is available, evidence blob is None."""
        ssl_obj = MagicMock(spec=ssl.SSLObject)
        ssl_obj.getpeercert.return_value = None
        ssl_obj.version.return_value = "TLSv1.3"
        ssl_obj.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="nocert.example.com")
            observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        assert obs.evidence_blob is None
        assert obs.evidence_blob_content_type is None


# ======================================================================
# 10. SANs are sanitized
# ======================================================================
class TestSanSanitization:
    """Test 10: Certificate SANs are sanitized via sanitize_field."""

    async def test_sans_are_sanitized(self) -> None:
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="test.com")
            observations = await _collect(seed)

        assert len(observations) == 1
        obs = observations[0]
        # SANs should be strings (sanitized), not raw bytes or unsanitized.
        sans = obs.structured_payload["cert_sans"]
        assert isinstance(sans, list)
        for san in sans:
            assert isinstance(san, str)
            # Sanitized SANs should not contain control characters.
            assert "\x00" not in san


# ======================================================================
# Collector metadata and registration
# ======================================================================
class TestCollectorMetadata:
    """Verify class-level metadata and registry registration."""

    def test_collector_class_attributes(self) -> None:
        assert ActiveTlsCollector.collector_id == "active-tls-handshake"
        assert ActiveTlsCollector.collector_version == "0.1.0"
        assert ActiveTlsCollector.tier == CollectorTier.TIER_3
        assert ActiveTlsCollector.requires_credentials is False

    def test_collector_is_subclass_of_collector_abc(self) -> None:
        assert issubclass(ActiveTlsCollector, Collector)

    def test_registered_in_default_registry(self) -> None:
        assert DEFAULT_REGISTRY.is_registered("active-tls-handshake")
        cls = DEFAULT_REGISTRY.get("active-tls-handshake")
        assert cls is ActiveTlsCollector


# ======================================================================
# JARM stub
# ======================================================================
class TestJarmStub:
    """Verify the JARM computation stub behaves correctly."""

    def test_jarm_returns_none(self) -> None:
        result = _compute_jarm("example.com", 443)
        assert result is None


# ======================================================================
# Helper function unit tests
# ======================================================================
class TestExtractCertPem:
    """Unit tests for _extract_cert_pem."""

    def test_returns_pem_bytes(self) -> None:
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        pem = _extract_cert_pem(ssl_obj)
        assert pem is not None
        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")

    def test_returns_none_when_no_cert(self) -> None:
        ssl_obj = MagicMock(spec=ssl.SSLObject)
        ssl_obj.getpeercert.return_value = None
        pem = _extract_cert_pem(ssl_obj)
        assert pem is None


class TestExtractCertDetails:
    """Unit tests for _extract_cert_details."""

    def test_extracts_subject_cn(self) -> None:
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        details = _extract_cert_details(ssl_obj)
        assert details["cert_subject_cn"] == "test.com"

    def test_extracts_serial(self) -> None:
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        details = _extract_cert_details(ssl_obj)
        assert details["cert_serial"] is not None
        # Serial should be lowercase hex.
        assert all(c in "0123456789abcdef" for c in details["cert_serial"])

    def test_extracts_fingerprint(self) -> None:
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        details = _extract_cert_details(ssl_obj)
        fp = details["cert_fingerprint_sha256"]
        assert fp is not None
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_handles_no_cert(self) -> None:
        ssl_obj = MagicMock(spec=ssl.SSLObject)
        ssl_obj.getpeercert.return_value = None
        details = _extract_cert_details(ssl_obj)
        assert details["cert_subject_cn"] is None
        assert details["cert_serial"] is None
        assert details["cert_fingerprint_sha256"] is None
        assert details["cert_sans"] == []
        assert details["key_algorithm"] is None
        assert details["key_size_bits"] is None
        assert details["key_weak"] is None
        assert details["chain_depth"] is None
        assert details["self_signed"] is None

    def test_extracts_key_algorithm_and_size(self) -> None:
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        details = _extract_cert_details(ssl_obj)
        assert details["key_algorithm"] == "RSA"
        assert details["key_size_bits"] == 2048
        assert details["key_weak"] is False

    def test_self_signed_detection(self) -> None:
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        details = _extract_cert_details(ssl_obj)
        # Test cert has subject == issuer (self-signed).
        assert details["self_signed"] is True
        assert details["chain_depth"] == 1

    def test_validity_dates_present(self) -> None:
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        details = _extract_cert_details(ssl_obj)
        assert details["cert_not_before"] is not None
        assert details["cert_not_after"] is not None
        # Should be ISO 8601 with Z suffix.
        assert details["cert_not_before"].endswith("Z")
        assert details["cert_not_after"].endswith("Z")


# ======================================================================
# Default port behavior
# ======================================================================
class TestDefaultPort:
    """Verify default port 443 is used when not specified in seed properties."""

    async def test_default_port_443(self) -> None:
        ssl_obj = _make_mock_ssl_object()
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            await _collect(seed)

        call_args = mock_open.call_args
        assert call_args[0][1] == 443


# ======================================================================
# SSL error handling
# ======================================================================
class TestSslError:
    """SSL-level errors during handshake are surfaced as CollectorSourceUnreachableError."""

    async def test_ssl_error_raises_source_unreachable(self) -> None:
        mock_open = AsyncMock(
            side_effect=ssl.SSLError("SSL handshake error")
        )

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="badsslserver.example.com")
            with pytest.raises(CollectorSourceUnreachableError, match="TLS handshake failed"):
                await _collect(seed)


# ======================================================================
# 11. Cipher strength classification
# ======================================================================
class TestCipherStrengthClassification:
    """Test 11: Cipher suite strength classification for all categories."""

    # -- Strong ciphers (modern, secure) --
    def test_aes_256_gcm_is_strong(self) -> None:
        assert _classify_cipher_strength("TLS_AES_256_GCM_SHA384") == "strong"

    def test_aes_128_gcm_is_strong(self) -> None:
        assert _classify_cipher_strength("TLS_AES_128_GCM_SHA256") == "strong"

    def test_chacha20_is_strong(self) -> None:
        assert _classify_cipher_strength("TLS_CHACHA20_POLY1305_SHA256") == "strong"

    def test_ecdhe_aes_is_strong(self) -> None:
        assert _classify_cipher_strength("ECDHE-RSA-AES256-GCM-SHA384") == "strong"

    # -- Acceptable ciphers (3DES, deprecated but not broken) --
    def test_3des_is_acceptable(self) -> None:
        assert _classify_cipher_strength("ECDHE-RSA-DES-CBC3-SHA") == "acceptable"

    def test_triple_des_variant_is_acceptable(self) -> None:
        assert _classify_cipher_strength("DES-CBC3-SHA") == "acceptable"

    def test_3des_ede_is_acceptable(self) -> None:
        assert _classify_cipher_strength("TLS_RSA_WITH_3DES_EDE_CBC_SHA") == "acceptable"

    # -- Weak ciphers (known vulnerabilities) --
    def test_rc4_is_weak(self) -> None:
        assert _classify_cipher_strength("RC4-SHA") == "weak"

    def test_rc4_md5_is_weak(self) -> None:
        assert _classify_cipher_strength("RC4-MD5") == "weak"

    def test_des_cbc_is_weak(self) -> None:
        assert _classify_cipher_strength("DES-CBC-SHA") == "weak"

    def test_rc2_is_weak(self) -> None:
        assert _classify_cipher_strength("RC2-CBC-MD5") == "weak"

    def test_exp_rc2_is_insecure_not_weak(self) -> None:
        # EXP- prefix contains EXPORT -> insecure wins first.
        assert _classify_cipher_strength("EXP-RC2-CBC-MD5") == "insecure"

    def test_idea_is_weak(self) -> None:
        assert _classify_cipher_strength("IDEA-CBC-SHA") == "weak"

    def test_seed_is_weak(self) -> None:
        assert _classify_cipher_strength("SEED-SHA") == "weak"

    # -- Insecure ciphers (no confidentiality or authentication) --
    def test_null_is_insecure(self) -> None:
        assert _classify_cipher_strength("NULL-SHA") == "insecure"

    def test_null_md5_is_insecure(self) -> None:
        assert _classify_cipher_strength("NULL-MD5") == "insecure"

    def test_export_is_insecure(self) -> None:
        assert _classify_cipher_strength("EXP-DES-CBC-SHA") == "insecure"

    def test_export_rc4_is_insecure(self) -> None:
        assert _classify_cipher_strength("EXP-RC4-MD5") == "insecure"

    def test_anon_is_insecure(self) -> None:
        assert _classify_cipher_strength("ADH-AES256-SHA") == "insecure"
        # "anon" substring check — anonymous DH
        assert _classify_cipher_strength("AECDH-AES128-SHA") == "insecure"

    def test_anon_dh_is_insecure(self) -> None:
        assert _classify_cipher_strength("aNULL") == "insecure"

    # -- Edge cases --
    def test_none_cipher_is_unknown(self) -> None:
        assert _classify_cipher_strength(None) == "unknown"

    def test_case_insensitive(self) -> None:
        assert _classify_cipher_strength("tls_aes_256_gcm_sha384") == "strong"
        assert _classify_cipher_strength("null-sha") == "insecure"
        assert _classify_cipher_strength("rc4-sha") == "weak"

    async def test_cipher_strength_in_observation_payload(self) -> None:
        """Verify cipher_strength appears in the observation from expand()."""
        ssl_obj = _make_mock_ssl_object(
            cipher=("RC4-SHA", "TLSv1.2", 128),
        )
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="weak-cipher.example.com")
            observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["cipher_strength"] == "weak"


# ======================================================================
# 12. Key size extraction and weakness detection
# ======================================================================
class TestKeyExtraction:
    """Test 12: Key algorithm/size extraction and weakness flagging."""

    def test_rsa_2048_not_weak(self) -> None:
        # The test cert has RSA-2048.
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        details = _extract_cert_details(ssl_obj)
        assert details["key_algorithm"] == "RSA"
        assert details["key_size_bits"] == 2048
        assert details["key_weak"] is False

    async def test_key_fields_in_observation(self) -> None:
        """Key algorithm and size appear in structured_payload."""
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="test.com")
            observations = await _collect(seed)

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert payload["key_algorithm"] == "RSA"
        assert payload["key_size_bits"] == 2048
        assert payload["key_weak"] is False

    def test_key_fields_none_when_no_cert(self) -> None:
        """When no certificate is available, key fields are None."""
        ssl_obj = MagicMock(spec=ssl.SSLObject)
        ssl_obj.getpeercert.return_value = None
        details = _extract_cert_details(ssl_obj)
        assert details["key_algorithm"] is None
        assert details["key_size_bits"] is None
        assert details["key_weak"] is None


# ======================================================================
# 13. Protocol version assessment
# ======================================================================
class TestProtocolAssessment:
    """Test 13: Protocol version assessment for all TLS versions."""

    def test_tlsv13_preferred(self) -> None:
        assert _assess_protocol_version("TLSv1.3") == "preferred"

    def test_tlsv12_acceptable(self) -> None:
        assert _assess_protocol_version("TLSv1.2") == "acceptable"

    def test_tlsv11_deprecated(self) -> None:
        assert _assess_protocol_version("TLSv1.1") == "deprecated"

    def test_tlsv10_deprecated(self) -> None:
        assert _assess_protocol_version("TLSv1.0") == "deprecated"

    def test_tlsv1_deprecated(self) -> None:
        # Some implementations report "TLSv1" without the ".0".
        assert _assess_protocol_version("TLSv1") == "deprecated"

    def test_sslv3_insecure(self) -> None:
        assert _assess_protocol_version("SSLv3") == "insecure"

    def test_sslv2_insecure(self) -> None:
        assert _assess_protocol_version("SSLv2") == "insecure"

    def test_none_version_unknown(self) -> None:
        assert _assess_protocol_version(None) == "unknown"

    def test_unrecognized_version_unknown(self) -> None:
        assert _assess_protocol_version("TLSv1.4") == "unknown"

    async def test_protocol_assessment_in_observation(self) -> None:
        """Protocol assessment appears in structured_payload."""
        ssl_obj = _make_mock_ssl_object(
            version="TLSv1.1",
            cipher=("ECDHE-RSA-AES256-SHA384", "TLSv1.1", 256),
        )
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="oldtls.example.com")
            observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["protocol_assessment"] == "deprecated"
        assert observations[0].structured_payload["tls_version"] == "TLSv1.1"

    async def test_tlsv12_assessment_in_observation(self) -> None:
        ssl_obj = _make_mock_ssl_object(
            version="TLSv1.2",
            cipher=("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256),
        )
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="tls12.example.com")
            observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["protocol_assessment"] == "acceptable"


# ======================================================================
# 14. _collector_id present in all observation payloads
# ======================================================================
class TestCollectorIdInPayload:
    """Test 14: _collector_id is always present in structured_payload for lead scoring."""

    async def test_collector_id_in_domain_seed_payload(self) -> None:
        ssl_obj = _make_mock_ssl_object()
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["_collector_id"] == "active-tls-handshake"

    async def test_collector_id_in_ip_seed_payload(self) -> None:
        ssl_obj = _make_mock_ssl_object()
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.IP, value="10.0.0.1")
            observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["_collector_id"] == "active-tls-handshake"

    async def test_collector_id_matches_class_attribute(self) -> None:
        """_collector_id in payload matches the class-level collector_id."""
        ssl_obj = _make_mock_ssl_object()
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="example.com")
            observations = await _collect(seed)

        assert len(observations) == 1
        assert observations[0].structured_payload["_collector_id"] == observations[0].collector_id


# ======================================================================
# 15. Chain depth and self-signed detection
# ======================================================================
class TestChainDepthAndSelfSigned:
    """Test 15: Certificate chain depth and self-signed detection."""

    async def test_self_signed_cert_chain_depth_1(self) -> None:
        """Self-signed certs (subject == issuer) report chain_depth=1."""
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        writer = _make_mock_writer(ssl_obj)
        mock_open = AsyncMock(return_value=(MagicMock(), writer))

        with patch("expose.collectors.builtin.active_tls.asyncio.open_connection", mock_open):
            seed = Seed(seed_type=SeedType.DOMAIN, value="selfsigned.example.com")
            observations = await _collect(seed)

        assert len(observations) == 1
        payload = observations[0].structured_payload
        assert payload["self_signed"] is True
        assert payload["chain_depth"] == 1

    def test_self_signed_details_extraction(self) -> None:
        """Direct test of _extract_cert_details for self-signed cert."""
        ssl_obj = _make_mock_ssl_object(der_bytes=_TEST_CERT_DER)
        details = _extract_cert_details(ssl_obj)
        assert details["self_signed"] is True
        assert details["chain_depth"] == 1

    def test_chain_depth_none_when_no_cert(self) -> None:
        """When no certificate is available, chain_depth is None."""
        ssl_obj = MagicMock(spec=ssl.SSLObject)
        ssl_obj.getpeercert.return_value = None
        details = _extract_cert_details(ssl_obj)
        assert details["chain_depth"] is None
        assert details["self_signed"] is None
