"""Tests for artifact signing and SLSA provenance generation.

Covers Ed25519 and ECDSA-P256 key generation, sign/verify round-trips,
tamper detection, model validation, and provenance envelope correctness.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519 as ed_mod
from pydantic import ValidationError

from expose.crypto.fips_adapter import compute_sha256_hex
from expose.crypto.signing import (
    ArtifactSignature,
    ArtifactSigner,
    SecureBytes,
    SignatureResult,
    SigningKeyPair,
    SLSAProvenance,
    sign_artifact,
    verify_artifact,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Ed25519 — key generation
# ---------------------------------------------------------------------------


class TestEd25519KeyGeneration:
    def test_generate_ed25519_key_pair(self) -> None:
        signer, key_info = ArtifactSigner.generate_key_pair(algorithm="ed25519")
        assert key_info.algorithm == "ed25519"
        assert len(key_info.key_id) == 32  # 128-bit NIST minimum (#158)
        assert "BEGIN PUBLIC KEY" in key_info.public_key_pem
        assert key_info.created_at is not None
        assert signer is not None

    def test_generate_ed25519_key_pair_default_algorithm(self) -> None:
        """Default algorithm should be ed25519."""
        signer, key_info = ArtifactSigner.generate_key_pair()
        assert key_info.algorithm == "ed25519"
        assert signer is not None


# ---------------------------------------------------------------------------
# Ed25519 — sign / verify round-trip
# ---------------------------------------------------------------------------


class TestEd25519SignVerify:
    def test_sign_and_verify_roundtrip(self) -> None:
        signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
        artifact = b'{"targets": [], "schema_version": "expose/v1"}'

        sig = signer.sign(artifact)
        assert ArtifactSigner.verify(artifact, sig, key_info.public_key_pem)
        assert sig.algorithm == "ed25519"
        assert sig.key_id == key_info.key_id
        assert len(sig.artifact_hash) == 64  # SHA-256 hex
        assert sig.signed_at is not None

    def test_verify_wrong_key_fails(self) -> None:
        signer1, _key1 = ArtifactSigner.generate_key_pair("ed25519")
        _signer2, key2 = ArtifactSigner.generate_key_pair("ed25519")
        artifact = b"some artifact content"

        sig = signer1.sign(artifact)
        assert not ArtifactSigner.verify(artifact, sig, key2.public_key_pem)

    def test_verify_tampered_artifact_fails(self) -> None:
        signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
        artifact = b"original content"
        tampered = b"tampered content"

        sig = signer.sign(artifact)
        assert not ArtifactSigner.verify(tampered, sig, key_info.public_key_pem)

    def test_sign_empty_artifact(self) -> None:
        """Empty artifact bytes can be signed and verified."""
        signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
        artifact = b""

        sig = signer.sign(artifact)
        assert ArtifactSigner.verify(artifact, sig, key_info.public_key_pem)

    def test_sign_same_artifact_twice_deterministic(self) -> None:
        """Ed25519 is deterministic — same artifact produces the same signature bytes."""
        signer, _key_info = ArtifactSigner.generate_key_pair("ed25519")
        artifact = b"deterministic test payload"

        sig1 = signer.sign(artifact)
        sig2 = signer.sign(artifact)

        # Same hash
        assert sig1.artifact_hash == sig2.artifact_hash
        # Ed25519 is deterministic: same key + same message = same signature
        assert sig1.signature_b64 == sig2.signature_b64


# ---------------------------------------------------------------------------
# ECDSA P-256 — key generation and sign/verify
# ---------------------------------------------------------------------------


class TestEcdsaP256:
    def test_generate_ecdsa_p256_key_pair(self) -> None:
        signer, key_info = ArtifactSigner.generate_key_pair(algorithm="ecdsa-p256")
        assert key_info.algorithm == "ecdsa-p256"
        assert len(key_info.key_id) == 32  # 128-bit NIST minimum (#158)
        assert "BEGIN PUBLIC KEY" in key_info.public_key_pem
        assert signer is not None

    def test_sign_and_verify_ecdsa_roundtrip(self) -> None:
        signer, key_info = ArtifactSigner.generate_key_pair("ecdsa-p256")
        artifact = b'{"schema_version": "expose/v1", "targets": []}'

        sig = signer.sign(artifact)
        assert ArtifactSigner.verify(artifact, sig, key_info.public_key_pem)
        assert sig.algorithm == "ecdsa-p256"

    def test_ecdsa_verify_wrong_key_fails(self) -> None:
        signer1, _key1 = ArtifactSigner.generate_key_pair("ecdsa-p256")
        _signer2, key2 = ArtifactSigner.generate_key_pair("ecdsa-p256")
        artifact = b"ecdsa test content"

        sig = signer1.sign(artifact)
        assert not ArtifactSigner.verify(artifact, sig, key2.public_key_pem)

    def test_ecdsa_verify_tampered_artifact_fails(self) -> None:
        signer, key_info = ArtifactSigner.generate_key_pair("ecdsa-p256")
        artifact = b"original ecdsa content"
        tampered = b"tampered ecdsa content"

        sig = signer.sign(artifact)
        assert not ArtifactSigner.verify(tampered, sig, key_info.public_key_pem)


# ---------------------------------------------------------------------------
# Invalid algorithm
# ---------------------------------------------------------------------------


class TestInvalidAlgorithm:
    def test_invalid_algorithm_in_constructor(self) -> None:
        """Passing an unsupported algorithm to the constructor raises ValueError."""
        priv = ed_mod.Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with pytest.raises(ValueError, match="Unsupported signing algorithm"):
            ArtifactSigner(pem, algorithm="rsa-4096")

    def test_invalid_algorithm_in_generate(self) -> None:
        with pytest.raises(ValueError, match="Unsupported signing algorithm"):
            ArtifactSigner.generate_key_pair(algorithm="dsa-1024")


# ---------------------------------------------------------------------------
# Malformed signature verification
# ---------------------------------------------------------------------------


class TestMalformedSignature:
    def test_verify_malformed_signature_returns_false(self) -> None:
        """A corrupted/malformed base64 signature must return False, not raise."""
        _signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
        artifact = b"test content"

        bad_sig = ArtifactSignature(
            artifact_hash="a" * 64,
            signature_b64=base64.b64encode(b"not a real signature").decode("ascii"),
            key_id="fake-key-id",
            algorithm="ed25519",
            signed_at=_now(),
        )
        assert not ArtifactSigner.verify(artifact, bad_sig, key_info.public_key_pem)

    def test_verify_invalid_base64_returns_false(self) -> None:
        """Completely invalid base64 in signature_b64 must return False."""
        _signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
        artifact = b"test content"

        bad_sig = ArtifactSignature(
            artifact_hash="b" * 64,
            signature_b64="!!!not-valid-base64!!!",
            key_id="fake",
            algorithm="ed25519",
            signed_at=_now(),
        )
        assert not ArtifactSigner.verify(artifact, bad_sig, key_info.public_key_pem)

    def test_verify_wrong_algorithm_label_returns_false(self) -> None:
        """Signature claiming unsupported algorithm returns False."""
        _signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
        artifact = b"test content"

        bad_sig = ArtifactSignature(
            artifact_hash="c" * 64,
            signature_b64=base64.b64encode(b"whatever").decode("ascii"),
            key_id="fake",
            algorithm="rsa-2048",
            signed_at=_now(),
        )
        assert not ArtifactSigner.verify(artifact, bad_sig, key_info.public_key_pem)


# ---------------------------------------------------------------------------
# Model validation
# ---------------------------------------------------------------------------


class TestModelValidation:
    def test_artifact_signature_frozen(self) -> None:
        sig = ArtifactSignature(
            artifact_hash="a" * 64,
            signature_b64=base64.b64encode(b"sig").decode("ascii"),
            key_id="k1",
            algorithm="ed25519",
            signed_at=_now(),
        )
        with pytest.raises(ValidationError):
            sig.artifact_hash = "b" * 64  # type: ignore[misc]

    def test_artifact_signature_min_length(self) -> None:
        with pytest.raises(ValidationError):
            ArtifactSignature(
                artifact_hash="",  # min_length=1 violated
                signature_b64="dGVzdA==",
                key_id="k1",
                algorithm="ed25519",
                signed_at=_now(),
            )

    def test_artifact_signature_forbids_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            ArtifactSignature(
                artifact_hash="a" * 64,
                signature_b64="dGVzdA==",
                key_id="k1",
                algorithm="ed25519",
                signed_at=_now(),
                extra_field="nope",  # type: ignore[call-arg]
            )

    def test_signing_key_pair_frozen(self) -> None:
        kp = SigningKeyPair(
            key_id="abc",
            algorithm="ed25519",
            public_key_pem="-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n",
            created_at=_now(),
        )
        with pytest.raises(ValidationError):
            kp.key_id = "xyz"  # type: ignore[misc]

    def test_signing_key_pair_min_length(self) -> None:
        with pytest.raises(ValidationError):
            SigningKeyPair(
                key_id="",  # min_length=1 violated
                algorithm="ed25519",
                public_key_pem="pem-data",
                created_at=_now(),
            )

    def test_slsa_provenance_frozen(self) -> None:
        now = _now()
        prov = SLSAProvenance(
            builder_id="expose-pipeline/v0.1.0",
            invocation_id="run-001",
            started_at=now,
            finished_at=now + timedelta(seconds=30),
            subject_hash="a" * 64,
            subject_name="artifact.json.gz",
        )
        with pytest.raises(ValidationError):
            prov.builder_id = "changed"  # type: ignore[misc]

    def test_slsa_provenance_min_length(self) -> None:
        now = _now()
        with pytest.raises(ValidationError):
            SLSAProvenance(
                builder_id="",  # min_length=1 violated
                invocation_id="run-001",
                started_at=now,
                finished_at=now + timedelta(seconds=1),
                subject_hash="a" * 64,
                subject_name="artifact.json.gz",
            )

    def test_slsa_provenance_forbids_extra_fields(self) -> None:
        now = _now()
        with pytest.raises(ValidationError):
            SLSAProvenance(
                builder_id="expose-pipeline/v0.1.0",
                invocation_id="run-001",
                started_at=now,
                finished_at=now + timedelta(seconds=1),
                subject_hash="a" * 64,
                subject_name="artifact.json.gz",
                bogus="nope",  # type: ignore[call-arg]
            )


# ---------------------------------------------------------------------------
# SLSA Provenance generation
# ---------------------------------------------------------------------------


class TestSLSAProvenance:
    def test_provenance_builder_id_and_invocation_id(self) -> None:
        signer, _key_info = ArtifactSigner.generate_key_pair("ed25519")
        artifact = b'{"data": "test"}'
        started = _now()
        finished = started + timedelta(seconds=10)

        prov = signer.create_provenance(
            artifact_bytes=artifact,
            artifact_name="scan-result.json.gz",
            run_id="run-abc-123",
            started_at=started,
            finished_at=finished,
            builder_version="0.2.0",
        )

        assert prov.builder_id == "expose-pipeline/v0.2.0"
        assert prov.invocation_id == "run-abc-123"

    def test_provenance_subject_hash_matches_artifact(self) -> None:
        signer, _key_info = ArtifactSigner.generate_key_pair("ed25519")
        artifact = b"provenance hash test"
        started = _now()
        finished = started + timedelta(seconds=5)

        prov = signer.create_provenance(
            artifact_bytes=artifact,
            artifact_name="test-artifact.json.gz",
            run_id="run-hash-check",
            started_at=started,
            finished_at=finished,
        )

        expected_hash = compute_sha256_hex(artifact)
        assert prov.subject_hash == expected_hash

    def test_provenance_default_build_type(self) -> None:
        signer, _key_info = ArtifactSigner.generate_key_pair("ed25519")
        started = _now()
        prov = signer.create_provenance(
            artifact_bytes=b"x",
            artifact_name="a.json.gz",
            run_id="run-1",
            started_at=started,
            finished_at=started + timedelta(seconds=1),
        )
        assert prov.build_type == "https://expose.dev/slsa/artifact/v1"

    def test_provenance_default_builder_version(self) -> None:
        signer, _key_info = ArtifactSigner.generate_key_pair("ed25519")
        started = _now()
        prov = signer.create_provenance(
            artifact_bytes=b"y",
            artifact_name="b.json.gz",
            run_id="run-2",
            started_at=started,
            finished_at=started + timedelta(seconds=1),
        )
        assert prov.builder_id == "expose-pipeline/v0.1.0"

    def test_provenance_timing(self) -> None:
        signer, _key_info = ArtifactSigner.generate_key_pair("ed25519")
        started = _now()
        finished = started + timedelta(minutes=3)
        prov = signer.create_provenance(
            artifact_bytes=b"timing test",
            artifact_name="c.json.gz",
            run_id="run-3",
            started_at=started,
            finished_at=finished,
        )
        assert prov.started_at == started
        assert prov.finished_at == finished

    def test_provenance_subject_name(self) -> None:
        signer, _key_info = ArtifactSigner.generate_key_pair("ed25519")
        started = _now()
        prov = signer.create_provenance(
            artifact_bytes=b"name test",
            artifact_name="my-scan.json.gz",
            run_id="run-4",
            started_at=started,
            finished_at=started + timedelta(seconds=1),
        )
        assert prov.subject_name == "my-scan.json.gz"

    def test_provenance_empty_materials_by_default(self) -> None:
        signer, _key_info = ArtifactSigner.generate_key_pair("ed25519")
        started = _now()
        prov = signer.create_provenance(
            artifact_bytes=b"materials test",
            artifact_name="d.json.gz",
            run_id="run-5",
            started_at=started,
            finished_at=started + timedelta(seconds=1),
        )
        assert prov.materials == []


# ---------------------------------------------------------------------------
# sign_artifact / verify_artifact convenience functions
# ---------------------------------------------------------------------------


class TestSignArtifactConvenience:
    """Tests for the high-level :func:`sign_artifact` convenience function."""

    def test_sign_artifact_returns_signature_result(self) -> None:
        signer, _key_info = ArtifactSigner.generate_key_pair("ed25519")
        payload = b'{"schema_version": "expose/v1"}'

        result = sign_artifact(payload, signer)

        assert isinstance(result, SignatureResult)
        assert result.algorithm == "ed25519"
        assert len(result.key_id) == 32  # 128-bit NIST minimum (#158)
        assert len(result.signature_b64) > 0
        assert result.signed_at is not None
        assert len(result.content_hash) == 64  # SHA-256 hex

    def test_sign_artifact_content_hash_matches_fips(self) -> None:
        """content_hash in SignatureResult must match FIPS adapter output."""
        signer, _key_info = ArtifactSigner.generate_key_pair("ed25519")
        payload = b"fips hash verification payload"

        result = sign_artifact(payload, signer)
        expected = compute_sha256_hex(payload)

        assert result.content_hash == expected

    def test_sign_artifact_ecdsa(self) -> None:
        signer, _key_info = ArtifactSigner.generate_key_pair("ecdsa-p256")
        payload = b"ecdsa convenience test"

        result = sign_artifact(payload, signer)

        assert result.algorithm == "ecdsa-p256"
        assert isinstance(result, SignatureResult)


class TestVerifyArtifactConvenience:
    """Tests for the high-level :func:`verify_artifact` convenience function."""

    def test_sign_then_verify_roundtrip(self) -> None:
        signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
        payload = b"roundtrip via convenience functions"

        sig_result = sign_artifact(payload, signer)
        assert verify_artifact(
            payload,
            sig_result.signature_b64,
            key_info.public_key_pem,
            algorithm="ed25519",
        )

    def test_verify_wrong_key_returns_false(self) -> None:
        signer, _key_info = ArtifactSigner.generate_key_pair("ed25519")
        _other_signer, other_key = ArtifactSigner.generate_key_pair("ed25519")
        payload = b"wrong key test"

        sig_result = sign_artifact(payload, signer)
        assert not verify_artifact(
            payload,
            sig_result.signature_b64,
            other_key.public_key_pem,
            algorithm="ed25519",
        )

    def test_verify_tampered_payload_returns_false(self) -> None:
        signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
        payload = b"original payload"

        sig_result = sign_artifact(payload, signer)
        assert not verify_artifact(
            b"tampered payload",
            sig_result.signature_b64,
            key_info.public_key_pem,
            algorithm="ed25519",
        )

    def test_verify_bogus_signature_returns_false(self) -> None:
        _signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
        payload = b"bogus sig test"

        assert not verify_artifact(
            payload,
            base64.b64encode(b"not-a-real-sig").decode("ascii"),
            key_info.public_key_pem,
            algorithm="ed25519",
        )

    def test_sign_verify_ecdsa_roundtrip(self) -> None:
        signer, key_info = ArtifactSigner.generate_key_pair("ecdsa-p256")
        payload = b"ecdsa convenience roundtrip"

        sig_result = sign_artifact(payload, signer)
        assert verify_artifact(
            payload,
            sig_result.signature_b64,
            key_info.public_key_pem,
            algorithm="ecdsa-p256",
        )


class TestSignatureResultModel:
    """Validate the SignatureResult Pydantic model."""

    def test_frozen(self) -> None:
        sr = SignatureResult(
            algorithm="ed25519",
            key_id="k1",
            signature_b64="dGVzdA==",
            signed_at=_now(),
            content_hash="a" * 64,
        )
        with pytest.raises(ValidationError):
            sr.algorithm = "changed"  # type: ignore[misc]

    def test_forbids_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            SignatureResult(
                algorithm="ed25519",
                key_id="k1",
                signature_b64="dGVzdA==",
                signed_at=_now(),
                content_hash="a" * 64,
                bogus="nope",  # type: ignore[call-arg]
            )

    def test_min_length_key_id(self) -> None:
        with pytest.raises(ValidationError):
            SignatureResult(
                algorithm="ed25519",
                key_id="",  # min_length=1 violated
                signature_b64="dGVzdA==",
                signed_at=_now(),
                content_hash="a" * 64,
            )


# ---------------------------------------------------------------------------
# Key ID length — 128-bit NIST minimum (Issue #158)
# ---------------------------------------------------------------------------


class TestKeyIdLength:
    """Verify key IDs are 32 hex chars (128 bits) per NIST guidance."""

    def test_ed25519_key_id_is_32_hex_chars(self) -> None:
        _signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
        assert len(key_info.key_id) == 32
        # Must be valid lowercase hex
        int(key_info.key_id, 16)

    def test_ecdsa_key_id_is_32_hex_chars(self) -> None:
        _signer, key_info = ArtifactSigner.generate_key_pair("ecdsa-p256")
        assert len(key_info.key_id) == 32
        int(key_info.key_id, 16)

    def test_key_id_is_lowercase_hex(self) -> None:
        """Key IDs must be lowercase hex to match SHA-256 hex convention."""
        _signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
        assert key_info.key_id == key_info.key_id.lower()

    def test_key_id_matches_between_signer_and_key_info(self) -> None:
        """The signer's internal key ID must match the published key_info."""
        signer, key_info = ArtifactSigner.generate_key_pair("ed25519")
        artifact = b"key-id-match-test"
        sig = signer.sign(artifact)
        assert sig.key_id == key_info.key_id
        assert len(sig.key_id) == 32

    def test_sign_artifact_convenience_key_id_length(self) -> None:
        """sign_artifact() convenience function also produces 32-char key IDs."""
        signer, _key_info = ArtifactSigner.generate_key_pair("ed25519")
        result = sign_artifact(b"convenience key id test", signer)
        assert len(result.key_id) == 32


# ---------------------------------------------------------------------------
# SecureBytes — zeroization and lifecycle (Issue #159)
# ---------------------------------------------------------------------------


class TestSecureBytes:
    """Verify SecureBytes provides best-effort key material zeroization."""

    def test_stores_data_correctly(self) -> None:
        data = b"sensitive key material"
        sb = SecureBytes(data)
        assert sb.to_bytes() == data
        assert not sb.is_zeroed

    def test_zero_overwrites_buffer(self) -> None:
        data = b"secret-key-bytes-1234567890abcdef"
        sb = SecureBytes(data)
        sb.zero()
        assert sb.is_zeroed
        assert sb.to_bytes() == b"\x00" * len(data)

    def test_zero_is_idempotent(self) -> None:
        sb = SecureBytes(b"idempotent test")
        sb.zero()
        sb.zero()  # should not raise
        assert sb.is_zeroed

    def test_context_manager_zeros_on_exit(self) -> None:
        data = b"context-manager-key-material"
        with SecureBytes(data) as sb:
            assert sb.to_bytes() == data
            assert not sb.is_zeroed
        assert sb.is_zeroed
        assert sb.to_bytes() == b"\x00" * len(data)

    def test_context_manager_zeros_on_exception(self) -> None:
        """Buffer is zeroed even if an exception occurs inside the with block."""
        data = b"exception-path-key"
        sb_ref = None
        with pytest.raises(RuntimeError, match="deliberate"):
            with SecureBytes(data) as sb:
                sb_ref = sb
                raise RuntimeError("deliberate")
        assert sb_ref is not None
        assert sb_ref.is_zeroed
        assert sb_ref.to_bytes() == b"\x00" * len(data)

    def test_del_zeros_buffer(self) -> None:
        """__del__ should zero the buffer if not already zeroed."""
        data = b"del-test-key-material"
        sb = SecureBytes(data)
        assert not sb.is_zeroed
        sb.__del__()  # Explicit call to simulate GC
        assert sb.is_zeroed
        assert sb.to_bytes() == b"\x00" * len(data)

    def test_del_skips_if_already_zeroed(self) -> None:
        """__del__ should be a no-op if zero() was already called."""
        sb = SecureBytes(b"already-zeroed")
        sb.zero()
        assert sb.is_zeroed
        sb.__del__()  # Should not raise or change state
        assert sb.is_zeroed

    def test_to_bytes_warns_after_zeroing(self, caplog: pytest.LogCaptureFixture) -> None:
        """Accessing key material after zeroing should log a warning."""
        sb = SecureBytes(b"warn-test")
        sb.zero()

        import logging
        with caplog.at_level(logging.WARNING, logger="expose.crypto.signing"):
            result = sb.to_bytes()

        assert result == b"\x00" * len(b"warn-test")
        assert "zeroization" in caplog.text

    def test_len(self) -> None:
        data = b"length-check"
        sb = SecureBytes(data)
        assert len(sb) == len(data)
        sb.zero()
        assert len(sb) == len(data)  # length preserved after zeroing

    def test_repr_live(self) -> None:
        sb = SecureBytes(b"repr-test")
        r = repr(sb)
        assert "live" in r
        assert "9" in r  # len=9

    def test_repr_zeroed(self) -> None:
        sb = SecureBytes(b"repr-test")
        sb.zero()
        r = repr(sb)
        assert "zeroed" in r

    def test_accepts_bytearray_input(self) -> None:
        data = bytearray(b"bytearray input")
        sb = SecureBytes(data)
        assert sb.to_bytes() == bytes(data)

    def test_empty_data(self) -> None:
        sb = SecureBytes(b"")
        assert len(sb) == 0
        sb.zero()
        assert sb.is_zeroed
        assert sb.to_bytes() == b""
