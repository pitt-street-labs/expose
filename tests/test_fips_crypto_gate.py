"""FIPS-mode crypto gate + adapter positive tests (per ADR-010).

ADR-010 requires "FIPS 140-3 validated cryptography everywhere — TLS, signing,
hashing, key management, password storage, all use FIPS-validated implementations
from day one. Specific stack choices: the `cryptography` Python library in FIPS
mode, AWS-LC bindings, or BoringSSL bindings — never the default Python
`hashlib` or `secrets` modules in non-FIPS mode."

Two responsibilities live in this file:

1. **Banned-import scanner** (``test_no_banned_crypto_imports``) — scans the
   EXPOSE source tree for direct imports of banned modules. The check is
   allowlist-based; the FIPS adapter at ``src/expose/crypto/fips_adapter.py``
   uses only ``cryptography`` (which is allowed), so it currently needs no
   entry in ``ALLOWED_FILES``.
2. **Positive-case tests** (``test_compute_sha256_*`` /
   ``test_compute_cert_fingerprint_*``) — verify the FIPS adapter actually
   produces correct output for known SHA-256 vectors and certificate
   fingerprints. Without these, the gate would only prove that nothing uses
   the banned modules; it would not prove that the legitimate adapter works.

Banned in `src/expose/`:
  - `import hashlib` / `from hashlib ...`
  - `import secrets` / `from secrets ...`
  - `from Crypto ...` (pycryptodome — not FIPS-validated by default)

Allowed:
  - `from cryptography ...` (the FIPS-capable library)
  - Anything inside `src/expose/crypto/fips_adapter.py` (when it lands;
    encapsulates any necessary low-level use behind a FIPS-mode-checked wrapper)
"""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from expose.crypto.fips_adapter import (
    compute_cert_fingerprint,
    compute_sha256,
    compute_sha256_hex,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "expose"

# Canonical fingerprint regex from canonical-artifact-v1 schema
# (CertFingerprintSha256). Bare 64-char lowercase hex, no ``sha256:`` prefix.
_CERT_FINGERPRINT_RE = re.compile(r"^[a-f0-9]{64}$")

# FIPS 180-4 SHA-256("") test vector. This is the most-cited known-answer
# test for the algorithm; if our adapter returns anything else the crypto
# backend is fundamentally broken.
_SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

BANNED_PATTERNS = [
    re.compile(r"^\s*import\s+hashlib\b", re.MULTILINE),
    re.compile(r"^\s*from\s+hashlib\b", re.MULTILINE),
    re.compile(r"^\s*import\s+secrets\b", re.MULTILINE),
    re.compile(r"^\s*from\s+secrets\b", re.MULTILINE),
    re.compile(r"^\s*from\s+Crypto\b", re.MULTILINE),  # pycryptodome
    re.compile(r"^\s*import\s+Crypto\b", re.MULTILINE),
]

ALLOWED_FILES = {
    # When a FIPS adapter lands, list it here. The adapter must use the
    # `cryptography` library in FIPS-mode; the allowlist exists to keep the
    # exception explicit and reviewable.
    # SRC_ROOT / "crypto" / "fips_adapter.py",
}


def _python_files() -> list[Path]:
    return [
        p
        for p in SRC_ROOT.rglob("*.py")
        if p not in ALLOWED_FILES
    ]


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: str(p.relative_to(SRC_ROOT)))
def test_no_banned_crypto_imports(path: Path) -> None:
    """No EXPOSE source file may import non-FIPS-validated crypto primitives."""
    text = path.read_text(encoding="utf-8")
    violations = []
    for pattern in BANNED_PATTERNS:
        for match in pattern.finditer(text):
            line_no = text[: match.start()].count("\n") + 1
            violations.append(f"  {path.relative_to(REPO_ROOT)}:{line_no}: {match.group(0).strip()}")
    if violations:
        pytest.fail(
            "Non-FIPS crypto import found (violates ADR-010):\n"
            + "\n".join(violations)
            + "\n\nUse the `cryptography` library in FIPS mode, or land a FIPS"
            " adapter in src/expose/crypto/fips_adapter.py and add to the"
            " ALLOWED_FILES set in this test."
        )


def test_fips_gate_finds_files() -> None:
    """Sanity: the gate is actually scanning files (catches a gate that turned
    into a no-op via path mistakes)."""
    files = _python_files()
    assert len(files) >= 3, (
        f"FIPS gate found only {len(files)} files to scan; expected ≥3. "
        "Check src/expose/ exists and contains Python sources."
    )


# === Positive-case tests for the FIPS adapter ================================
# The banned-import scanner above proves nothing forbidden is used; these
# tests prove the legitimate adapter actually works.


def _build_test_certificate() -> x509.Certificate:
    """Generate a self-signed ECDSA P-256 cert for fingerprint round-trips.

    Inline rather than fixture-based: each call gets a fresh certificate so
    tests cannot accidentally cross-contaminate via shared key material, and
    the test file stays self-contained (no conftest changes per W1.B scope).
    P-256 keeps generation fast (<10ms) so the per-test cost is negligible.
    """

    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "expose-fips-adapter-test")],
    )
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )


def test_compute_sha256_known_vector() -> None:
    """FIPS 180-4 known-answer test: SHA-256("") matches the canonical digest."""
    digest = compute_sha256(b"")
    assert digest.hex() == _SHA256_EMPTY
    # Contract: 32 raw bytes (256 bits) per FIPS 180-4.
    assert len(digest) == 32


def test_compute_sha256_hex_lowercase() -> None:
    """compute_sha256_hex always returns lowercase hex.

    Output feeds the canonical artifact schema's CertFingerprintSha256
    regex (``^[a-f0-9]{64}$``), which is lowercase-only. Any uppercase
    character would silently fail downstream schema validation.
    """
    # Mix of inputs: empty (all-hex-letters digest), short, and longer text
    # that's likely to produce hex digits A-F somewhere in the output.
    for sample in [b"", b"a", b"The quick brown fox jumps over the lazy dog"]:
        out = compute_sha256_hex(sample)
        assert out == out.lower(), f"non-lowercase output for {sample!r}: {out}"
        assert _CERT_FINGERPRINT_RE.match(out), (
            f"output {out!r} does not match canonical fingerprint regex"
        )


def test_compute_cert_fingerprint_pem_and_der() -> None:
    """PEM and DER encodings of the same cert must produce identical fingerprints.

    The fingerprint is defined as SHA-256 of the DER-encoded cert; PEM is
    just base64-armored DER. Auto-detect must route both paths to the same
    digest.
    """
    cert = _build_test_certificate()
    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
    der_bytes = cert.public_bytes(serialization.Encoding.DER)

    pem_fp = compute_cert_fingerprint(pem_bytes)
    der_fp = compute_cert_fingerprint(der_bytes)

    assert pem_fp == der_fp, (
        f"PEM/DER fingerprint mismatch: PEM={pem_fp!r} DER={der_fp!r}"
    )
    # Cross-check against the cert object's own .fingerprint() method —
    # if these disagree the adapter is computing the wrong thing.
    expected = cert.fingerprint(hashes.SHA256()).hex()
    assert pem_fp == expected


def test_fingerprint_matches_canonical_regex() -> None:
    """Adapter output must match canonical-artifact-v1 CertFingerprintSha256 regex.

    Schema regex is ``^[a-f0-9]{64}$`` — bare 64-char lowercase hex, no
    ``sha256:`` prefix, no separators. The pipeline depends on this exact
    form for fingerprint equality comparisons.
    """
    cert = _build_test_certificate()
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    fp = compute_cert_fingerprint(der_bytes)
    assert _CERT_FINGERPRINT_RE.match(fp), (
        f"fingerprint {fp!r} does not match canonical regex ^[a-f0-9]{{64}}$"
    )

    # Same invariant for compute_sha256_hex on arbitrary bytes.
    digest_hex = compute_sha256_hex(b"observation payload")
    assert _CERT_FINGERPRINT_RE.match(digest_hex)
