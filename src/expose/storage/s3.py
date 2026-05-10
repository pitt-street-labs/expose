"""S3-compatible :class:`StorageBackend` stub (issue #9).

Defines the class with constructor parameters matching S3-compatible
object stores (AWS S3, MinIO, Ceph RGW, etc.).  All methods raise
:exc:`NotImplementedError` — the full implementation lands when production
cloud deployment is authorized.

Lab deployments use :class:`~expose.storage.local.LocalStorageBackend`
in the interim.
"""

from __future__ import annotations

from expose.storage.base import StorageBackend

_NOT_IMPLEMENTED_MSG = (
    "S3 backend not yet implemented — use LocalStorageBackend for lab deployments"
)


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


__all__ = ["S3StorageBackend"]
