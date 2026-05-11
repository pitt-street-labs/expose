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
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pydantic import BaseModel, ConfigDict, Field

from expose.crypto.fips_adapter import compute_sha256_hex

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

_SUPPORTED_ALGORITHMS = frozenset({"ed25519", "ecdsa-p256"})


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
        self._private_key: PrivateKeyTypes = serialization.load_pem_private_key(
            private_key_pem, password=None,
        )

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
        pub_der = self._private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._key_id = compute_sha256_hex(pub_der)[:16]

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

        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        signer = cls(private_pem, algorithm=algorithm)
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


__all__ = [
    "ArtifactSignature",
    "ArtifactSigner",
    "SLSAProvenance",
    "SigningKeyPair",
]
