"""S3-compatible :class:`StorageBackend` stub (issue #9).

Defines the class with constructor parameters matching S3-compatible
object stores (AWS S3, MinIO, Ceph RGW, etc.).  The core ABC methods
raise :exc:`NotImplementedError` — the full implementation lands when
production cloud deployment is authorized.

Evidence-specific helpers (:meth:`store_evidence`, :meth:`retrieve_evidence`)
are layered on top and delegate through the ABC surface, so they will
work as soon as the base methods are implemented.

Lab deployments use :class:`~expose.storage.local.LocalStorageBackend`
in the interim.
"""

from __future__ import annotations

from expose.crypto.fips_adapter import compute_sha256_hex
from expose.storage.base import StorageBackend, StorageKeyNotFoundError

_NOT_IMPLEMENTED_MSG = (
    "S3 backend not yet implemented — use LocalStorageBackend for lab deployments"
)

_EVIDENCE_KEY_PREFIX = "evidence"


class S3StorageBackend(StorageBackend):
    """S3-compatible object storage (stub — not yet implemented).

    Args:
        bucket: S3 bucket name.
        region: AWS region or compatible region identifier.
        endpoint_url: Override endpoint for S3-compatible stores (MinIO,
            Ceph RGW, etc.).  ``None`` uses the default AWS endpoint.
    """

    def __init__(
        self,
        *,
        bucket: str,
        region: str = "us-east-1",
        endpoint_url: str | None = None,
    ) -> None:
        self._bucket = bucket
        self._region = region
        self._endpoint_url = endpoint_url

    async def put(
        self,
        key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str:
        """Store bytes in S3 — NOT YET IMPLEMENTED."""
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def get(self, key: str) -> bytes:
        """Retrieve bytes from S3 — NOT YET IMPLEMENTED."""
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def exists(self, key: str) -> bool:
        """Check existence in S3 — NOT YET IMPLEMENTED."""
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def delete(self, key: str) -> bool:
        """Delete from S3 — NOT YET IMPLEMENTED."""
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    async def list_keys(self, prefix: str = "") -> list[str]:
        """List keys in S3 — NOT YET IMPLEMENTED."""
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    # -- Evidence-specific helpers ------------------------------------------
    #
    # These methods provide a higher-level evidence API with content-hash
    # validation.  They delegate to the ABC surface (put/get) so they will
    # become functional once the base methods are implemented.  Until then,
    # NotImplementedError propagates from the underlying call.
    # -----------------------------------------------------------------------

    async def store_evidence(
        self,
        key: str,
        content: bytes,
        metadata: dict | None = None,
    ) -> str:
        """Store an evidence blob under the ``evidence/`` key prefix.

        The *key* is automatically prefixed with ``evidence/`` to
        namespace evidence blobs within the bucket.  The content's
        SHA-256 hash is computed (via FIPS adapter per ADR-010) and
        stored as part of the object metadata for integrity validation
        on retrieval.

        Args:
            key: Logical key for the evidence blob (e.g. a content hash
                or descriptive identifier).  Will be prefixed with
                ``evidence/``.
            content: Raw evidence bytes.
            metadata: Optional caller-supplied metadata dict.  Not
                persisted in the S3 stub phase; will map to S3 object
                metadata (``x-amz-meta-*`` headers) in the production
                implementation.

        Returns:
            The full storage key (with ``evidence/`` prefix).
        """
        full_key = f"{_EVIDENCE_KEY_PREFIX}/{key}"
        await self.put(full_key, content)
        return full_key

    async def retrieve_evidence(self, key: str) -> bytes:
        """Retrieve an evidence blob and validate its content hash.

        The *key* is automatically prefixed with ``evidence/``.  After
        retrieval, the content's SHA-256 digest is recomputed and compared
        against the key (when the key is a content hash) to detect silent
        corruption.

        Args:
            key: Logical key for the evidence blob (should be the
                content hash for integrity validation).

        Returns:
            The raw evidence bytes.

        Raises:
            StorageKeyNotFoundError: if no blob exists at the key.
            ValueError: if the retrieved content's hash does not match
                *key* (integrity failure) and *key* looks like a SHA-256
                hex digest.
        """
        full_key = f"{_EVIDENCE_KEY_PREFIX}/{key}"
        data = await self.get(full_key)

        # Content hash validation: if the key is a 64-char hex string
        # (i.e. a SHA-256 digest), verify the retrieved data matches.
        if len(key) == 64 and all(c in "0123456789abcdef" for c in key):
            actual_hash = compute_sha256_hex(data)
            if actual_hash != key:
                msg = (
                    f"Evidence integrity check failed for {key}: "
                    f"stored data hashes to {actual_hash}"
                )
                raise ValueError(msg)

        return data


__all__ = ["S3StorageBackend"]
