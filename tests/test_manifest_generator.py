"""Tests for the manifest generator (pipeline metadata envelope).

Coverage:

1. ``generate`` produces a valid :class:`Manifest` instance.
2. Manifest validates against the Pydantic model (extra fields rejected).
3. ``artifact.canonical_artifact_hash`` matches the input hash.
4. ``signature_metadata.signature_format`` is ``unsigned`` (lab mode per ADR-004).
5. ``serialize_manifest`` produces valid JSON bytes.
6. ``compute_manifest_hash`` returns a 64-char hex string.
7. ``collectors_enabled`` includes all supplied collectors.
8. Run timestamps (``generated_at``) are preserved.
9. ``pipeline_version`` is set correctly.
10. Round-trip: generate -> serialize -> parse -> matches original.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest

from expose.crypto.fips_adapter import compute_sha256_hex
from expose.pipeline.manifest_generator import (
    ManifestGenerator,
    compute_manifest_hash,
    serialize_manifest,
)
from expose.types.manifest import Manifest, SignatureFormat

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Synthetic tenant / run UUIDs reused across the suite.
TENANT_ID = UUID("018f1f00-0000-7000-8000-00000000A001")
RUN_ID = UUID("018f1f00-0000-7000-8000-000000000001")

# A valid 40-char lowercase hex string matching the GitSha1 constraint.
PIPELINE_VERSION = "a" * 40

# A valid sha256:<hex> reference string.
ARTIFACT_HASH = "sha256:" + "b" * 64

STARTED_AT = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)
COMPLETED_AT = datetime(2026, 5, 10, 12, 5, 0, tzinfo=UTC)

COLLECTORS = ["dns-zone-transfer", "ct-crtsh", "rdap-whois"]


@pytest.fixture
def generator() -> ManifestGenerator:
    """Fresh generator instance per test."""
    return ManifestGenerator()


@pytest.fixture
def manifest(generator: ManifestGenerator) -> Manifest:
    """A pre-built manifest for tests that only inspect output."""
    return generator.generate(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        artifact_hash=ARTIFACT_HASH,
        artifact_size_bytes=123_456,
        entity_count=42,
        relationship_count=17,
        pipeline_version=PIPELINE_VERSION,
        started_at=STARTED_AT,
        completed_at=COMPLETED_AT,
        collectors_used=COLLECTORS,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_generate_produces_valid_manifest(manifest: Manifest) -> None:
    """generate() returns a Manifest instance — Pydantic validated."""
    assert isinstance(manifest, Manifest)


def test_manifest_model_rejects_extra_fields(generator: ManifestGenerator) -> None:
    """Manifest is strict (extra='forbid'); injecting fields raises."""
    m = generator.generate(
        run_id=RUN_ID,
        tenant_id=TENANT_ID,
        artifact_hash=ARTIFACT_HASH,
        artifact_size_bytes=100,
        entity_count=1,
        relationship_count=0,
        pipeline_version=PIPELINE_VERSION,
        started_at=STARTED_AT,
        completed_at=COMPLETED_AT,
        collectors_used=[],
    )
    data = m.model_dump()
    data["unexpected_field"] = "should fail"
    with pytest.raises(Exception):  # noqa: B017 — ValidationError is the concrete type
        Manifest.model_validate(data)


def test_artifact_hash_matches_input(manifest: Manifest) -> None:
    """canonical_artifact_hash on the manifest matches the supplied hash."""
    assert manifest.canonical_artifact_hash == ARTIFACT_HASH


def test_signature_unsigned(manifest: Manifest) -> None:
    """Lab mode: signature_format is UNSIGNED per ADR-004."""
    assert manifest.signature_metadata.signature_format == SignatureFormat.UNSIGNED
    assert manifest.signature_metadata.signed_by == "lab-operator (unsigned)"


def test_serialize_produces_valid_json(manifest: Manifest) -> None:
    """serialize_manifest returns bytes that parse as valid JSON."""
    raw = serialize_manifest(manifest)
    assert isinstance(raw, bytes)
    parsed = json.loads(raw)
    assert isinstance(parsed, dict)
    assert parsed["schema_version"] == "expose-manifest/v1"


def test_compute_manifest_hash_returns_hex64(manifest: Manifest) -> None:
    """compute_manifest_hash returns a 64-char lowercase hex string."""
    raw = serialize_manifest(manifest)
    h = compute_manifest_hash(raw)
    assert isinstance(h, str)
    assert len(h) == 64
    # Must be valid hex (int conversion succeeds).
    int(h, 16)


def test_collectors_enabled_matches(manifest: Manifest) -> None:
    """All supplied collector identifiers appear in collectors_enabled."""
    assert manifest.collectors_enabled is not None
    assert manifest.collectors_enabled == COLLECTORS


def test_run_timestamps_preserved(manifest: Manifest) -> None:
    """generated_at reflects the completed_at timestamp from the run."""
    assert manifest.generated_at == COMPLETED_AT


def test_pipeline_version_set(manifest: Manifest) -> None:
    """pipeline_version matches the supplied git SHA-1."""
    assert manifest.pipeline_version == PIPELINE_VERSION


def test_round_trip(manifest: Manifest) -> None:
    """generate -> serialize -> parse -> model matches the original."""
    raw = serialize_manifest(manifest)
    restored = Manifest.model_validate_json(raw)
    assert restored == manifest


def test_hash_uses_fips_adapter(manifest: Manifest) -> None:
    """compute_manifest_hash produces the same digest as the FIPS adapter."""
    raw = serialize_manifest(manifest)
    expected = compute_sha256_hex(raw)
    actual = compute_manifest_hash(raw)
    assert actual == expected


def test_schema_version_constant(manifest: Manifest) -> None:
    """schema_version is always 'expose-manifest/v1'."""
    assert manifest.schema_version == "expose-manifest/v1"
