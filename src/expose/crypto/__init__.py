"""FIPS-validated cryptography adapter for EXPOSE engine code.

This package is the sole legal path for SHA-256 / certificate fingerprint
computation inside ``src/expose/``. Per ADR-010 (FedRAMP-ready posture)
the engine MUST NOT use Python's stdlib ``hashlib`` or ``secrets``
modules; ``tests/test_fips_crypto_gate.py`` enforces that ban via static
import scanning. Routing through this package keeps every digest call on
the FIPS-validated ``cryptography`` library code path, which delegates to
the underlying OpenSSL build (FIPS-mode in federal deployments).

See :mod:`expose.crypto.fips_adapter` for the implementation and the
detailed relationship to
``expose.sanitization.canonicalize.normalize_cert_fingerprint``.
"""

from __future__ import annotations

from expose.crypto.fips_adapter import (
    compute_cert_fingerprint,
    compute_sha256,
    compute_sha256_hex,
)

__all__ = [
    "compute_cert_fingerprint",
    "compute_sha256",
    "compute_sha256_hex",
]
