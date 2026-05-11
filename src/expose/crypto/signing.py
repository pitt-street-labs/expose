"""Artifact signing and SLSA provenance generation (per ADR-004 / ADR-010).

This module provides in-process cryptographic signing of canonical artifacts
using Ed25519 or ECDSA P-256 keys, plus structured SLSA Level 2+ provenance
envelope generation.  It complements the *container-image* signing performed
by ``cosign`` (see ``deploy/cosign-keypair-setup.md``) by covering the JSON
artifacts themselves — the canonical scan results that EXPOSE produces.

All cryptographic operations route through the ``cryptography`` library,
consistent with ADR-010's FIPS-validated crypto mandate.  SHA-256 hashing is
delegated to :func:`expose.crypto.fips_adapter.compute_sha256_hex` so the
FIPS gate (``tests/test_fips_crypto_gate.py``) remains satisfied.

Key algorithms
--------------
- **Ed25519** — default.  Fast, small signatures, no parameter choices.
  Uses ``cryptography.hazmat.primitives.asymmetric.ed25519``.
- **ECDSA P-256** — alternative for environments that require NIST curves.
  Uses ``cryptography.hazmat.primitives.asymmetric.ec`` with ``SECP256R1``
  and ``ECDSA(hashes.SHA256())``.

Neither algorithm requires ``hashlib`` or ``secrets``; key generation uses
``cryptography``'s own CSPRNG path.

Key material lifecycle — accepted risk
---------------------------------------
Python's CPython runtime does not support deterministic zeroing of heap-
allocated ``bytes`` / ``str`` objects.  The :class:`SecureBytes` wrapper in
this module provides **best-effort** zeroization by storing key material in
a mutable ``bytearray`` and overwriting it on ``__del__`` / context-manager
exit.  This mitigates casual memory inspection but does NOT eliminate all
copies:

- The ``cryptography`` library's own internal OpenSSL buffers are outside
  our control and may retain key material until the process exits.
- CPython's memory allocator may leave freed pages mapped and un-zeroed.
- The GC does not guarantee prompt ``__del__`` invocation.

This is an **accepted risk** for the current threat model (server-side
process, not a shared-memory environment).  For higher-assurance key
protection, use an HSM / KMS backend (SPEC §10.1 Secrets Management).
"""

from __future__ import annotations

import base64
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pydantic import BaseModel, ConfigDict, Field

from expose.crypto.fips_adapter import compute_sha256_hex

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

logger = logging.getLogger(__name__)

_SUPPORTED_ALGORITHMS = frozenset({"ed25519", "ecdsa-p256"})


# ---------------------------------------------------------------------------
# SecureBytes — best-effort key material zeroization
# ---------------------------------------------------------------------------


class SecureBytes:
    """Best-effort secure wrapper for sensitive key material.

    Stores data in a mutable ``bytearray`` so it can be explicitly zeroed,
    unlike immutable ``bytes`` objects.  Provides both ``__del__`` (GC
    cleanup) and context-manager (``with`` block) interfaces for
    zeroization.

    **Limitations (accepted risk):**

    - CPython does not guarantee prompt ``__del__`` invocation.
    - The ``cryptography`` library's internal OpenSSL buffers may retain
      copies of key material beyond our control.
    - The CPython allocator may leave freed memory pages un-zeroed.

    For higher-assurance key protection, use an HSM / KMS backend.
    """

    def __init__(self, data: bytes | bytearray) -> None:
        self._buf = bytearray(data)
        self._zeroed = False

    # -- Context manager ----------------------------------------------------

    def __enter__(self) -> SecureBytes:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.zero()

    # -- Access -------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Return an immutable snapshot of the key material.

        Logs a warning if accessed after zeroization.
        """
        if self._zeroed:
            logger.warning(
                "SecureBytes.to_bytes() called after zeroization — "
                "returned data is all-zeros and not valid key material"
            )
        return bytes(self._buf)

    # -- Zeroization --------------------------------------------------------

    def zero(self) -> None:
        """Overwrite the internal buffer with zeros."""
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._zeroed = True

    @property
    def is_zeroed(self) -> bool:
        """Whether :meth:`zero` has been called."""
        return self._zeroed

    def __del__(self) -> None:
        """Best-effort zeroization on garbage collection."""
        if not self._zeroed:
            self.zero()

    def __len__(self) -> int:
        return len(self._buf)

    def __repr__(self) -> str:
        state = "zeroed" if self._zeroed else "live"
        return f"<SecureBytes len={len(self._buf)} {state}>"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SigningKeyPair(BaseModel):
    """Represents the public half of a signing key pair plus metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str = Field(min_length=1)
    algorithm: str  # "ed25519" or "ecdsa-p256"
    public_key_pem: str
    created_at: datetime


class ArtifactSignature(BaseModel):
    """Cryptographic signature for a canonical artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_hash: str = Field(min_length=1)  # SHA-256 hex of artifact content
    signature_b64: str = Field(min_length=1)  # base64-encoded raw signature bytes
    key_id: str = Field(min_length=1)
    algorithm: str
    signed_at: datetime


class SLSAProvenance(BaseModel):
    """SLSA Level 2+ provenance attestation for an EXPOSE artifact.

    Follows the `SLSA Provenance v1 <https://slsa.dev/provenance/v1>`_
    envelope structure, adapted for EXPOSE's artifact-centric (non-container)
    use case.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    build_type: str = "https://expose.dev/slsa/artifact/v1"
    builder_id: str = Field(min_length=1)  # e.g. "expose-pipeline/v0.1.0"
    invocation_id: str = Field(min_length=1)  # run_id
    started_at: datetime
    finished_at: datetime
    materials: list[dict[str, str]] = Field(default_factory=list)
    subject_hash: str = Field(min_length=1)  # SHA-256 hex of artifact content
    subject_name: str = Field(min_length=1)  # artifact filename or identifier


# ---------------------------------------------------------------------------
# Signer implementation
# ---------------------------------------------------------------------------


class ArtifactSigner:
    """Signs canonical artifacts using Ed25519 or ECDSA-P256.

    Instantiate with PEM-encoded private key bytes and an algorithm
    identifier.  Use the :meth:`generate_key_pair` class method to create a
    fresh key pair for testing or key-rotation ceremonies.
    """

    def __init__(self, private_key_pem: bytes, algorithm: str = "ed25519") -> None:
        if algorithm not in _SUPPORTED_ALGORITHMS:
            msg = (
                f"Unsupported signing algorithm {algorithm!r}; "
                f"expected one of {sorted(_SUPPORTED_ALGORITHMS)}"
            )
            raise ValueError(msg)

        self._algorithm = algorithm

        # Wrap the PEM bytes in SecureBytes for best-effort zeroization.
        # The PEM material is consumed during load and zeroed immediately
        # afterward — only the parsed key object is retained.
        secure_pem = SecureBytes(private_key_pem)
        try:
            self._private_key: PrivateKeyTypes = serialization.load_pem_private_key(
                secure_pem.to_bytes(), password=None,
            )
        finally:
            secure_pem.zero()

        # Validate that the loaded key matches the declared algorithm.
        if algorithm == "ed25519" and not isinstance(
            self._private_key, ed25519.Ed25519PrivateKey,
        ):
            msg = "Private key is not an Ed25519 key but algorithm='ed25519' was specified"
            raise ValueError(msg)
        if algorithm == "ecdsa-p256" and not isinstance(
            self._private_key, ec.EllipticCurvePrivateKey,
        ):
            msg = "Private key is not an EC key but algorithm='ecdsa-p256' was specified"
            raise ValueError(msg)

        # Derive the key ID from the SHA-256 fingerprint of the public key DER.
        # Truncated to 32 hex chars (128 bits) per NIST identifier-uniqueness
        # minimum (see security finding #158).
        pub_der = self._private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._key_id = compute_sha256_hex(pub_der)[:32]

    # -- Key generation -----------------------------------------------------

    @classmethod
    def generate_key_pair(
        cls,
        algorithm: str = "ed25519",
    ) -> tuple[ArtifactSigner, SigningKeyPair]:
        """Generate a new key pair.

        Returns ``(signer, public_key_info)`` where *signer* is ready to
        sign artifacts and *public_key_info* carries the PEM-encoded public
        key and metadata for distribution / storage.
        """
        if algorithm not in _SUPPORTED_ALGORITHMS:
            msg = (
                f"Unsupported signing algorithm {algorithm!r}; "
                f"expected one of {sorted(_SUPPORTED_ALGORITHMS)}"
            )
            raise ValueError(msg)

        if algorithm == "ed25519":
            private_key: PrivateKeyTypes = ed25519.Ed25519PrivateKey.generate()
        else:  # ecdsa-p256
            private_key = ec.generate_private_key(ec.SECP256R1())

        # Wrap private PEM in SecureBytes and zero after the signer has
        # consumed it (the signer's __init__ also wraps + zeros its copy).
        secure_private_pem = SecureBytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        try:
            signer = cls(secure_private_pem.to_bytes(), algorithm=algorithm)
        finally:
            secure_private_pem.zero()

        key_info = SigningKeyPair(
            key_id=signer._key_id,
            algorithm=algorithm,
            public_key_pem=public_pem.decode("ascii"),
            created_at=datetime.now(UTC),
        )
        return signer, key_info

    # -- Signing ------------------------------------------------------------

    def sign(self, artifact_bytes: bytes) -> ArtifactSignature:
        """Sign artifact content and return an :class:`ArtifactSignature`.

        The artifact is first hashed with SHA-256 via
        :func:`~expose.crypto.fips_adapter.compute_sha256_hex`.  The hash
        digest bytes are then signed with the private key.

        For Ed25519, the ``cryptography`` library performs its own internal
        hashing (Ed25519 signs the message directly, not a pre-hash).  We
        sign the full artifact bytes to honour the Ed25519 specification.
        The ``artifact_hash`` field in the returned signature is recorded for
        verification convenience but the actual signed payload is
        ``artifact_bytes``.
        """
        artifact_hash = compute_sha256_hex(artifact_bytes)

        if self._algorithm == "ed25519":
            raw_sig = self._private_key.sign(artifact_bytes)  # type: ignore[union-attr]
        else:  # ecdsa-p256
            raw_sig = self._private_key.sign(  # type: ignore[union-attr]
                artifact_bytes,
                ec.ECDSA(hashes.SHA256()),
            )

        return ArtifactSignature(
            artifact_hash=artifact_hash,
            signature_b64=base64.b64encode(raw_sig).decode("ascii"),
            key_id=self._key_id,
            algorithm=self._algorithm,
            signed_at=datetime.now(UTC),
        )

    # -- Verification -------------------------------------------------------

    @staticmethod
    def verify(
        artifact_bytes: bytes,
        signature: ArtifactSignature,
        public_key_pem: str,
    ) -> bool:
        """Verify an artifact signature against a public key.

        Returns ``True`` if the signature is valid, ``False`` otherwise.
        Never raises on invalid/malformed signatures — all failure modes
        map to ``False``.
        """
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
            raw_sig = base64.b64decode(signature.signature_b64)

            if signature.algorithm == "ed25519":
                if not isinstance(pub_key, ed25519.Ed25519PublicKey):
                    return False
                pub_key.verify(raw_sig, artifact_bytes)
            elif signature.algorithm == "ecdsa-p256":
                if not isinstance(pub_key, ec.EllipticCurvePublicKey):
                    return False
                pub_key.verify(raw_sig, artifact_bytes, ec.ECDSA(hashes.SHA256()))
            else:
                return False

        except (InvalidSignature, ValueError, TypeError, Exception):
            return False
        else:
            return True

    # -- SLSA provenance ----------------------------------------------------

    def create_provenance(
        self,
        *,
        artifact_bytes: bytes,
        artifact_name: str,
        run_id: str,
        started_at: datetime,
        finished_at: datetime,
        builder_version: str = "0.1.0",
    ) -> SLSAProvenance:
        """Generate SLSA Level 2+ provenance for an artifact.

        The provenance envelope records *who* built the artifact, *when*,
        and the SHA-256 digest of the artifact content as the subject hash.
        Callers can extend ``materials`` on the returned (frozen) model via
        ``model_copy(update=...)`` if additional build inputs need recording.
        """
        subject_hash = compute_sha256_hex(artifact_bytes)

        return SLSAProvenance(
            builder_id=f"expose-pipeline/v{builder_version}",
            invocation_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            subject_hash=subject_hash,
            subject_name=artifact_name,
        )


class SignatureResult(BaseModel):
    """High-level result from :func:`sign_artifact`.

    Bundles the algorithm, key identifier, base64 signature, ISO-8601
    timestamp, and SHA-256 content hash into a single record suitable for
    embedding in a manifest's ``signature`` block.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: str
    key_id: str = Field(min_length=1)
    signature_b64: str = Field(min_length=1)
    signed_at: datetime
    content_hash: str = Field(min_length=1)  # SHA-256 hex via FIPS adapter


def sign_artifact(
    artifact_bytes: bytes,
    private_key: ArtifactSigner,
) -> SignatureResult:
    """Sign arbitrary artifact bytes and return a :class:`SignatureResult`.

    This is the preferred high-level entry point.  It delegates to
    :meth:`ArtifactSigner.sign` and re-packages the result into the
    manifest-oriented :class:`SignatureResult` schema.

    All hashing is performed via
    :func:`~expose.crypto.fips_adapter.compute_sha256_hex`.
    """
    sig = private_key.sign(artifact_bytes)
    return SignatureResult(
        algorithm=sig.algorithm,
        key_id=sig.key_id,
        signature_b64=sig.signature_b64,
        signed_at=sig.signed_at,
        content_hash=sig.artifact_hash,
    )


def verify_artifact(
    artifact_bytes: bytes,
    signature_b64: str,
    public_key: str,
    *,
    algorithm: str = "ed25519",
) -> bool:
    """Verify an artifact signature given raw base64 and a PEM public key.

    This is the convenience counterpart to :func:`sign_artifact`.  It
    constructs an ephemeral :class:`ArtifactSignature` and delegates to
    :meth:`ArtifactSigner.verify`.  Returns ``True`` on success,
    ``False`` on any failure (never raises).
    """
    # Build a minimal ArtifactSignature for the static verify path.
    ephemeral = ArtifactSignature(
        artifact_hash=compute_sha256_hex(artifact_bytes),
        signature_b64=signature_b64,
        key_id="verify-only",
        algorithm=algorithm,
        signed_at=datetime.now(UTC),
    )
    return ArtifactSigner.verify(artifact_bytes, ephemeral, public_key)


__all__ = [
    "ArtifactSignature",
    "ArtifactSigner",
    "SLSAProvenance",
    "SecureBytes",
    "SignatureResult",
    "SigningKeyPair",
    "sign_artifact",
    "verify_artifact",
]
