"""Manifest generator — builds a :class:`Manifest` for a completed pipeline run.

The manifest is the metadata envelope accompanying each canonical artifact. It
records provenance (who ran, when, which collectors), integrity hashes (SHA-256
of the canonical artifact via the FIPS adapter), and signing status (lab-unsigned
per ADR-004 until cosign integration lands).

The :func:`serialize_manifest` and :func:`compute_manifest_hash` helpers round-
trip the manifest to JSON bytes and compute a FIPS-validated hash over the
serialized form, respectively. Downstream consumers (artifact storage, audit
logs, the NATS broker's completion events) use these to create integrity-chain
links without reimplementing serialization.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from expose.crypto.fips_adapter import compute_sha256_hex
from expose.types.manifest import (
    GitSha1,
    Manifest,
    ManifestSignature,
    Sha256Ref,
    SignatureFormat,
)


class ManifestGenerator:
    """Builds a :class:`Manifest` for a completed pipeline run.

    Stateless — all inputs are passed to :meth:`generate`. Instantiate once and
    reuse across runs, or create per-run; both patterns are valid.
    """

    def generate(
        self,
        *,
        run_id: UUID,
        tenant_id: UUID,
        artifact_hash: Sha256Ref,
        artifact_size_bytes: int,
        entity_count: int,
        relationship_count: int,
        pipeline_version: GitSha1,
        started_at: datetime,
        completed_at: datetime,
        collectors_used: list[str],
    ) -> Manifest:
        """Assemble a :class:`Manifest` from run metadata.

        Parameters
        ----------
        run_id:
            UUIDv7 identifying this pipeline run.
        tenant_id:
            Tenant that owns this run (ADR-007 multi-tenancy).
        artifact_hash:
            SHA-256 of the canonical artifact JSON, as a ``sha256:<hex>``
            reference string matching the schema's ``Sha256Ref`` pattern.
        artifact_size_bytes:
            Size of the serialized canonical artifact in bytes. Carried for
            quick size inspection without fetching the artifact; **not** stored
            in the manifest schema (informational parameter only).
        entity_count:
            Number of entities (targets) in the canonical artifact. Mapped to
            the schema's ``target_count`` field.
        relationship_count:
            Number of relationships in the canonical artifact. Informational
            parameter for callers; **not** stored in the current manifest
            schema (will land when the schema adds a ``relationship_count``
            field).
        pipeline_version:
            Git commit SHA-1 (40-char lowercase hex) of the EXPOSE codebase
            that produced this run.
        started_at:
            Pipeline run start timestamp.
        completed_at:
            Pipeline run completion timestamp. Used as ``generated_at`` in the
            manifest (the manifest is generated at the moment the run completes).
        collectors_used:
            Identifiers of the collectors that contributed to this run.

        Returns
        -------
        Manifest
            A fully populated manifest with ``signature_metadata.signature_format``
            set to ``unsigned`` (lab mode per ADR-004).
        """
        signature = ManifestSignature(
            signature_format=SignatureFormat.UNSIGNED,
            signed_by="lab-operator (unsigned)",
        )

        return Manifest(
            schema_version="expose-manifest/v1",
            run_id=run_id,
            tenant_id=tenant_id,
            generated_at=completed_at,
            pipeline_version=pipeline_version,
            canonical_artifact_hash=artifact_hash,
            target_count=entity_count,
            collectors_enabled=collectors_used,
            signature_metadata=signature,
        )


def serialize_manifest(manifest: Manifest) -> bytes:
    """Serialize a :class:`Manifest` to canonical JSON bytes (UTF-8).

    Uses Pydantic's ``model_dump_json`` with ``indent=2`` for human-readable
    output and ``by_alias=True`` to match the JSON Schema field names.
    """
    return manifest.model_dump_json(indent=2, by_alias=True).encode("utf-8")


def compute_manifest_hash(manifest_bytes: bytes) -> str:
    """Return the FIPS-validated SHA-256 hex digest of serialized manifest JSON.

    Routes through :func:`expose.crypto.fips_adapter.compute_sha256_hex` —
    the sole legal SHA-256 path inside ``src/expose/`` per ADR-010.

    Returns a 64-character lowercase hex string (no ``sha256:`` prefix).
    """
    return compute_sha256_hex(manifest_bytes)


__all__ = [
    "ManifestGenerator",
    "compute_manifest_hash",
    "serialize_manifest",
]
