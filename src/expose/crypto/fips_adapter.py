"""FIPS-validated SHA-256 / certificate fingerprint adapter (per ADR-010).

ADR-010 §Commitment 1 mandates "FIPS 140-3 validated cryptography everywhere
— TLS, signing, hashing, key management, password storage, all use FIPS-
validated implementations from day one. Specific stack choices: the
``cryptography`` Python library in FIPS mode, AWS-LC bindings, or BoringSSL
bindings — never the default Python ``hashlib`` or ``secrets`` modules in
non-FIPS mode."

This module is the **sole legal SHA-256 path inside ``src/expose/``**. Every
SHA-256 digest computed by EXPOSE engine code MUST route through these
helpers. The ``tests/test_fips_crypto_gate.py`` banned-import scanner
enforces this by rejecting any ``import hashlib`` / ``import secrets`` /
``from Crypto`` use elsewhere in the engine source tree.

The implementation routes through
``cryptography.hazmat.primitives.hashes.Hash(hashes.SHA256())`` and
``cryptography.x509.load_{pem,der}_x509_certificate``. The ``cryptography``
library transparently delegates to the underlying OpenSSL build's digest
implementation; when EXPOSE runs against a FIPS-mode OpenSSL (the federal
deployment configuration per ADR-010), these calls are FIPS-validated. When
EXPOSE runs against a stock OpenSSL build (lab/dev), the same call path is
exercised so behavioral parity is preserved between FIPS and non-FIPS
operation. This is the same posture the ``cryptography`` upstream
documents.

Relationship to ``expose.sanitization.canonicalize.normalize_cert_fingerprint``
=============================================================================

These two functions are complementary, not duplicative:

- ``normalize_cert_fingerprint(fingerprint: str) -> str`` *normalizes* an
  already-computed fingerprint string into the canonical lowercase 64-char
  hex form (handles colon/space/hyphen separators, ``sha256:`` prefix,
  mixed case). It does **not** compute anything from a certificate.
- ``compute_cert_fingerprint(pem_or_der: bytes) -> str`` (this module)
  *computes* the SHA-256 fingerprint from the raw certificate bytes (PEM
  or DER), returning the same canonical 64-char lowercase hex form that
  ``normalize_cert_fingerprint`` produces.

Pipeline ordering: collectors call ``compute_cert_fingerprint`` to derive
the fingerprint from observed cert bytes. If a collector receives a
fingerprint as a *string* from an upstream API (Censys, etc.) it calls
``normalize_cert_fingerprint``. Both produce identical canonical output, so
downstream consumers (graph storage, attribution, the canonical artifact
serializer) handle a single representation.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes

# Sentinel for the PEM armor header. ``cryptography`` will accept any PEM
# block whose label matches the expected type; we only need to detect that
# the input *is* PEM rather than DER, so a substring check on the standard
# certificate armor opening is sufficient.
_PEM_OPENING = b"-----BEGIN"

# SHA-256 digest size in bytes (per FIPS 180-4). Hoisted to a constant to
# document the compute_sha256 return-length contract without a magic number.
_SHA256_DIGEST_SIZE_BYTES = 32


def compute_sha256(data: bytes) -> bytes:
    """Return the FIPS-validated SHA-256 digest of ``data`` as 32 raw bytes.

    Uses ``cryptography.hazmat.primitives.hashes.Hash(hashes.SHA256())`` so
    the call delegates to the underlying OpenSSL digest implementation —
    FIPS-validated when EXPOSE runs against a FIPS-mode OpenSSL build.

    The contract is byte-in / bytes-out (always 32 bytes per FIPS 180-4).
    Callers needing hex output should use :func:`compute_sha256_hex`.
    """

    digester = hashes.Hash(hashes.SHA256())
    digester.update(data)
    digest = digester.finalize()
    # Defensive post-condition. SHA-256 is contractually 32 bytes; if a
    # crypto-backend bug ever returned something else we want to fail loud
    # rather than silently corrupt downstream fingerprint comparisons.
    if len(digest) != _SHA256_DIGEST_SIZE_BYTES:  # pragma: no cover - defensive
        msg = (
            f"FIPS adapter SHA-256 returned {len(digest)} bytes; expected "
            f"{_SHA256_DIGEST_SIZE_BYTES}. Crypto backend is misconfigured."
        )
        raise RuntimeError(msg)
    return digest


def compute_sha256_hex(data: bytes) -> str:
    """Return the FIPS-validated SHA-256 digest of ``data`` as 64-char lowercase hex.

    Output matches the canonical artifact schema's
    ``CertFingerprintSha256`` regex (``^[a-f0-9]{64}$``). No ``sha256:``
    prefix — bare hex.
    """

    return compute_sha256(data).hex()


def compute_cert_fingerprint(pem_or_der: bytes) -> str:
    """Compute the SHA-256 fingerprint of an X.509 certificate.

    Accepts the certificate as either:

    - **PEM**: ASCII armor, recognized by the ``-----BEGIN`` header. Any
      label is accepted (typically ``-----BEGIN CERTIFICATE-----``); the
      ``cryptography`` loader validates the label.
    - **DER**: raw binary. Anything not starting with ``-----BEGIN`` is
      treated as DER.

    Returns the canonical 64-character lowercase hex SHA-256 fingerprint
    (matching ``^[a-f0-9]{64}$``), the same form
    :func:`expose.sanitization.canonicalize.normalize_cert_fingerprint`
    produces. The fingerprint is computed via the certificate's parsed-
    object ``.fingerprint(hashes.SHA256())`` method, which routes through
    the same FIPS-validated digest path as :func:`compute_sha256`.

    Raises :class:`ValueError` (via ``cryptography``) if the input is not
    a parseable certificate.
    """

    if pem_or_der.lstrip().startswith(_PEM_OPENING):
        cert = x509.load_pem_x509_certificate(pem_or_der)
    else:
        cert = x509.load_der_x509_certificate(pem_or_der)
    # ``.fingerprint()`` returns raw bytes; ``.hex()`` is lowercase per
    # CPython contract — matches the canonical artifact schema regex.
    return cert.fingerprint(hashes.SHA256()).hex()


__all__ = [
    "compute_cert_fingerprint",
    "compute_sha256",
    "compute_sha256_hex",
]
