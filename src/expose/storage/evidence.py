"""Content-addressed evidence storage manager (issue #111).

Evidence blobs (raw HTTP responses, certificate PEMs, DNS responses,
screenshots, etc.) are stored content-addressed by their SHA-256 digest.
This guarantees deduplication at the storage layer: identical content always
resolves to the same key regardless of how many entities or runs reference
it.

The :class:`EvidenceManager` sits above the :class:`StorageBackend` ABC and
provides:

- **Content-addressed store/retrieve** — the caller supplies raw bytes and
  metadata; the manager computes the SHA-256 digest (via the FIPS adapter
  per ADR-010) and uses it as the storage key.
- **Entity association** — metadata tracks which entity produced the
  evidence, enabling :meth:`list_for_entity` queries.
- **TTL-based lifecycle** — each blob carries a ``retention_seconds``
  value (default 90 days).  :meth:`expire` scans stored metadata and
  removes blobs whose retention window has elapsed.
- **Integrity validation** — :meth:`retrieve` re-hashes the stored bytes
  and raises :class:`EvidenceIntegrityError` if the digest no longer
  matches, catching silent corruption.

All hashing routes through :func:`expose.crypto.fips_adapter.compute_sha256_hex`
(the sole legal SHA-256 path per ADR-010).

Keys follow the existing tenant-scoped convention::

    evidence / {content_hash}
    evidence / meta / {content_hash}.json

The caller is responsible for prepending the tenant prefix
(``tenant/{tenant_id}/``) when constructing the manager, keeping this
module tenant-agnostic and testable without tenant fixtures.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from expose.crypto.fips_adapter import compute_sha256_hex
from expose.storage.base import StorageBackend, StorageKeyNotFoundError


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EVIDENCE_PREFIX = "evidence"
_META_PREFIX = "evidence/meta"
_DEFAULT_RETENTION_SECONDS = 90 * 24 * 3600  # 90 days
_BATCH_SIZE = 100
_META_FETCH_BATCH_SIZE = 50


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class EvidenceIntegrityError(RuntimeError):
    """Raised when a retrieved blob's SHA-256 digest does not match its key.

    This indicates silent corruption in the storage backend (bit-rot, partial
    write, or tampering).  Callers should treat the blob as untrusted and
    trigger an incident workflow.
    """


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class EvidenceRef(BaseModel):
    """Immutable reference to a stored evidence blob.

    Returned by :meth:`EvidenceManager.store` and
    :meth:`EvidenceManager.list_for_entity`.  The ``content_hash`` field
    doubles as the content-addressed storage key.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    content_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[a-f0-9]{64}$",
        description="SHA-256 hex digest of the stored content.",
    )
    content_type: str = Field(
        default="application/octet-stream",
        description="MIME type of the evidence blob.",
    )
    size_bytes: int = Field(ge=0, description="Size of the stored content in bytes.")
    stored_at: datetime = Field(description="UTC timestamp when the blob was stored.")
    metadata: dict = Field(
        default_factory=dict,
        description="Caller-supplied metadata (entity_id, run_id, collector, etc.).",
    )
    retention_seconds: int = Field(
        default=_DEFAULT_RETENTION_SECONDS,
        ge=0,
        description="How long to retain the blob (seconds from stored_at).",
    )


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class EvidenceManager:
    """Content-addressed evidence storage with lifecycle management.

    Args:
        backend: Any :class:`StorageBackend` implementation (local or S3).
        key_prefix: Optional prefix prepended to all keys (e.g.
            ``tenant/{tenant_id}``).  Enables tenant isolation without
            coupling this class to the tenancy model.
        default_retention_seconds: Default TTL for stored blobs when the
            caller does not specify one.
        verify_on_read: Default integrity-verification policy for
            :meth:`retrieve`.  When ``True`` (the default), every
            retrieval re-computes the SHA-256 digest and compares it to
            the content-addressed key.  Set to ``False`` to skip the
            hash check by default, avoiding a CPU bottleneck for large
            blobs.  Individual :meth:`retrieve` calls can still override
            via the ``verify_integrity`` parameter.
    """

    def __init__(
        self,
        backend: StorageBackend,
        *,
        key_prefix: str = "",
        default_retention_seconds: int = _DEFAULT_RETENTION_SECONDS,
        verify_on_read: bool = True,
    ) -> None:
        self._backend = backend
        self._key_prefix = key_prefix.rstrip("/")
        self._default_retention_seconds = default_retention_seconds
        self._verify_on_read = verify_on_read

    # -- key helpers --------------------------------------------------------

    def _blob_key(self, content_hash: str) -> str:
        """Storage key for the evidence blob itself."""
        parts = [self._key_prefix, _EVIDENCE_PREFIX, content_hash]
        return "/".join(p for p in parts if p)

    def _meta_key(self, content_hash: str) -> str:
        """Storage key for the JSON metadata sidecar."""
        parts = [self._key_prefix, _META_PREFIX, f"{content_hash}.json"]
        return "/".join(p for p in parts if p)

    # -- public API ---------------------------------------------------------

    async def store(
        self,
        content: bytes,
        metadata: dict | None = None,
        *,
        content_type: str = "application/octet-stream",
        retention_seconds: int | None = None,
    ) -> EvidenceRef:
        """Store an evidence blob, returning an :class:`EvidenceRef`.

        If the exact same content has already been stored, the blob is not
        re-written (content-addressed dedup) but the metadata sidecar is
        updated to reflect the latest store call.

        Args:
            content: Raw bytes of the evidence blob.
            metadata: Caller-supplied metadata dict.  Should include at
                minimum ``entity_id`` for :meth:`list_for_entity` queries.
            content_type: MIME type hint.
            retention_seconds: TTL override.  ``None`` uses the manager's
                default.

        Returns:
            An :class:`EvidenceRef` describing the stored blob.
        """
        content_hash = compute_sha256_hex(content)
        retention = (
            retention_seconds
            if retention_seconds is not None
            else self._default_retention_seconds
        )

        blob_key = self._blob_key(content_hash)
        meta_key = self._meta_key(content_hash)

        # Content-addressed dedup: skip the blob write if it already exists.
        if not await self._backend.exists(blob_key):
            await self._backend.put(blob_key, content, content_type)

        now = datetime.now(tz=UTC)
        ref = EvidenceRef(
            content_hash=content_hash,
            content_type=content_type,
            size_bytes=len(content),
            stored_at=now,
            metadata=metadata or {},
            retention_seconds=retention,
        )

        # Persist the metadata sidecar as JSON.
        meta_bytes = ref.model_dump_json(indent=2).encode()
        await self._backend.put(meta_key, meta_bytes, "application/json")

        return ref

    async def retrieve(
        self, content_hash: str, *, verify_integrity: bool | None = None
    ) -> bytes:
        """Retrieve an evidence blob by its SHA-256 content hash.

        Re-hashes the retrieved bytes and raises :class:`EvidenceIntegrityError`
        if the digest does not match -- catching silent corruption.

        Args:
            content_hash: 64-character lowercase hex SHA-256 digest.
            verify_integrity: Whether to re-hash the blob for integrity
                verification.  ``None`` (the default) defers to the
                instance-level ``verify_on_read`` setting.  Pass ``True``
                or ``False`` to override per call.  Skipping verification
                avoids the SHA-256 re-computation, which can be a CPU
                bottleneck for large blobs.

        Returns:
            The raw evidence bytes.

        Raises:
            StorageKeyNotFoundError: if no blob exists for *content_hash*.
            EvidenceIntegrityError: if the stored bytes fail integrity check
                (only when verification is enabled).
        """
        blob_key = self._blob_key(content_hash)
        data = await self._backend.get(blob_key)

        # Resolve effective verification flag: explicit arg > instance default.
        should_verify = (
            verify_integrity if verify_integrity is not None else self._verify_on_read
        )

        if should_verify:
            # Integrity validation: re-hash and compare.
            actual_hash = compute_sha256_hex(data)
            if actual_hash != content_hash:
                msg = (
                    f"Evidence integrity check failed for {content_hash}: "
                    f"stored data hashes to {actual_hash}"
                )
                raise EvidenceIntegrityError(msg)

        return data

    async def exists(self, content_hash: str) -> bool:
        """Check whether an evidence blob exists for *content_hash*."""
        return await self._backend.exists(self._blob_key(content_hash))

    async def delete(self, content_hash: str) -> bool:
        """Delete an evidence blob and its metadata sidecar.

        Returns ``True`` if the blob existed and was removed, ``False``
        otherwise.  The metadata sidecar is always cleaned up if present.
        """
        blob_deleted = await self._backend.delete(self._blob_key(content_hash))
        # Best-effort metadata cleanup -- ignore if already gone.
        await self._backend.delete(self._meta_key(content_hash))
        return blob_deleted

    async def get_ref(self, content_hash: str) -> EvidenceRef | None:
        """Load the :class:`EvidenceRef` metadata for *content_hash*.

        Returns ``None`` if no metadata sidecar exists.
        """
        meta_key = self._meta_key(content_hash)
        try:
            meta_bytes = await self._backend.get(meta_key)
        except StorageKeyNotFoundError:
            return None
        return EvidenceRef.model_validate_json(meta_bytes)

    async def list_for_entity(self, entity_id: UUID) -> list[EvidenceRef]:
        """Return all :class:`EvidenceRef` objects associated with *entity_id*.

        Scans metadata sidecars under the evidence/meta prefix and filters
        by ``metadata.entity_id``.  For production scale this would be
        backed by a database index; the storage-scan approach is acceptable
        for lab/dev deployments.

        Keys are processed in batches of ``_BATCH_SIZE`` to avoid loading
        all metadata into memory at once.  Within each batch, metadata
        fetches are parallelised in sub-batches of ``_META_FETCH_BATCH_SIZE``
        via ``asyncio.gather`` (issue #154).
        """
        meta_prefix = (
            f"{self._key_prefix}/{_META_PREFIX}"
            if self._key_prefix
            else _META_PREFIX
        )
        keys = await self._backend.list_keys(prefix=meta_prefix)
        results: list[EvidenceRef] = []
        entity_str = str(entity_id)

        for batch_start in range(0, len(keys), _BATCH_SIZE):
            batch_keys = keys[batch_start : batch_start + _BATCH_SIZE]

            # Fetch metadata in sub-batches of _META_FETCH_BATCH_SIZE
            for fetch_start in range(0, len(batch_keys), _META_FETCH_BATCH_SIZE):
                fetch_keys = batch_keys[
                    fetch_start : fetch_start + _META_FETCH_BATCH_SIZE
                ]

                async def _fetch_ref(key: str) -> EvidenceRef | None:
                    try:
                        meta_bytes = await self._backend.get(key)
                        ref = EvidenceRef.model_validate_json(meta_bytes)
                        if ref.metadata.get("entity_id") == entity_str:
                            return ref
                    except (StorageKeyNotFoundError, Exception):
                        pass
                    return None

                refs = await asyncio.gather(
                    *[_fetch_ref(k) for k in fetch_keys],
                )
                results.extend(r for r in refs if r is not None)

        return results

    async def expire(self) -> list[str]:
        """Remove evidence blobs whose retention window has elapsed.

        Scans all metadata sidecars, computes expiry from
        ``stored_at + retention_seconds``, and deletes expired blobs
        along with their metadata.

        Keys are processed in batches of ``_BATCH_SIZE`` with metadata
        fetches parallelised in sub-batches of ``_META_FETCH_BATCH_SIZE``
        via ``asyncio.gather`` (issue #154).

        Returns:
            List of content hashes that were expired and deleted.
        """
        meta_prefix = (
            f"{self._key_prefix}/{_META_PREFIX}"
            if self._key_prefix
            else _META_PREFIX
        )
        keys = await self._backend.list_keys(prefix=meta_prefix)
        now = datetime.now(tz=UTC)
        expired: list[str] = []

        for batch_start in range(0, len(keys), _BATCH_SIZE):
            batch_keys = keys[batch_start : batch_start + _BATCH_SIZE]

            # Fetch metadata in sub-batches of _META_FETCH_BATCH_SIZE
            for fetch_start in range(0, len(batch_keys), _META_FETCH_BATCH_SIZE):
                fetch_keys = batch_keys[
                    fetch_start : fetch_start + _META_FETCH_BATCH_SIZE
                ]

                async def _fetch_ref(key: str) -> EvidenceRef | None:
                    try:
                        meta_bytes = await self._backend.get(key)
                        return EvidenceRef.model_validate_json(meta_bytes)
                    except (StorageKeyNotFoundError, Exception):
                        return None

                refs = await asyncio.gather(
                    *[_fetch_ref(k) for k in fetch_keys],
                )

                for ref in refs:
                    if ref is None:
                        continue
                    expiry = ref.stored_at.timestamp() + ref.retention_seconds
                    if now.timestamp() >= expiry:
                        await self.delete(ref.content_hash)
                        expired.append(ref.content_hash)

        return expired

    async def expire_evidence(
        self,
        tenant_id: str,
        max_age_days: int,
    ) -> list[str]:
        """Convenience method: expire evidence older than *max_age_days*.

        Unlike :meth:`expire` which uses per-blob ``retention_seconds``,
        this method applies a blanket age cutoff to all blobs under the
        manager's prefix.  Designed for administrative retention policies
        (e.g. "delete all evidence older than 90 days for tenant X").

        The *tenant_id* parameter is used for logging and audit purposes
        only -- the actual scoping is controlled by the manager's
        ``key_prefix`` (set at construction time).

        Args:
            tenant_id: Tenant identifier (for logging/audit).
            max_age_days: Maximum age in days.  Blobs stored more than
                this many days ago are deleted regardless of their
                per-blob ``retention_seconds``.

        Returns:
            List of content hashes that were expired and deleted.
        """
        meta_prefix = (
            f"{self._key_prefix}/{_META_PREFIX}"
            if self._key_prefix
            else _META_PREFIX
        )
        keys = await self._backend.list_keys(prefix=meta_prefix)
        now = datetime.now(tz=UTC)
        cutoff_seconds = max_age_days * 24 * 3600
        expired: list[str] = []

        for batch_start in range(0, len(keys), _BATCH_SIZE):
            batch_keys = keys[batch_start : batch_start + _BATCH_SIZE]

            for fetch_start in range(0, len(batch_keys), _META_FETCH_BATCH_SIZE):
                fetch_keys = batch_keys[
                    fetch_start : fetch_start + _META_FETCH_BATCH_SIZE
                ]

                async def _fetch_ref(key: str) -> EvidenceRef | None:
                    try:
                        meta_bytes = await self._backend.get(key)
                        return EvidenceRef.model_validate_json(meta_bytes)
                    except (StorageKeyNotFoundError, Exception):
                        return None

                refs = await asyncio.gather(
                    *[_fetch_ref(k) for k in fetch_keys],
                )

                for ref in refs:
                    if ref is None:
                        continue
                    age_seconds = now.timestamp() - ref.stored_at.timestamp()
                    if age_seconds >= cutoff_seconds:
                        await self.delete(ref.content_hash)
                        expired.append(ref.content_hash)

        return expired

    async def verify_integrity(self, content_hash: str) -> bool:
        """Verify the integrity of a stored evidence blob.

        Re-computes the SHA-256 digest of the stored bytes and compares
        it to the content-addressed key.

        Args:
            content_hash: 64-character lowercase hex SHA-256 digest.

        Returns:
            ``True`` if the stored data matches the content hash,
            ``False`` if the blob is corrupted or missing.
        """
        try:
            blob_key = self._blob_key(content_hash)
            data = await self._backend.get(blob_key)
            actual_hash = compute_sha256_hex(data)
            return actual_hash == content_hash
        except StorageKeyNotFoundError:
            return False


__all__ = [
    "EvidenceIntegrityError",
    "EvidenceManager",
    "EvidenceRef",
]
