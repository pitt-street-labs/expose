"""S3-compatible :class:`StorageBackend` implementation (issue #111).

Implements the full :class:`StorageBackend` ABC against any S3-compatible
object store (AWS S3, MinIO, Ceph RGW, etc.) using ``boto3``.  All I/O
is dispatched to a thread executor via :func:`asyncio.to_thread` so the
async contract is maintained without requiring ``aioboto3``.

If ``boto3`` is not installed, the class can still be imported (for type
checking and test mocking) but instantiation raises :exc:`ImportError`
with a clear message.

Evidence-specific helpers (:meth:`store_evidence`, :meth:`retrieve_evidence`)
are layered on top and delegate through the ABC surface, providing
content-hash validation on retrieval.

Keys follow the tenant-scoped convention::

    tenant / {tenant_id} / run / {run_id} / {sha256_hex}

MinIO support is activated by passing ``endpoint_url`` to the constructor,
which overrides the default AWS endpoint in the ``boto3`` client.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from expose.crypto.fips_adapter import compute_sha256_hex
from expose.storage.base import StorageBackend, StorageKeyNotFoundError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional boto3 import — graceful degradation when not installed.
# ---------------------------------------------------------------------------

_boto3: Any = None
_botocore_exceptions: Any = None

try:
    import boto3 as _boto3_mod
    import botocore.exceptions as _botocore_exc_mod

    _boto3 = _boto3_mod
    _botocore_exceptions = _botocore_exc_mod
except ImportError:  # pragma: no cover
    pass

_EVIDENCE_KEY_PREFIX = "evidence"


class S3StorageBackend(StorageBackend):
    """S3-compatible object storage backend.

    Uses ``boto3`` synchronous client dispatched through
    :func:`asyncio.to_thread` to satisfy the async ABC contract.

    Args:
        bucket: S3 bucket name.
        region: AWS region or compatible region identifier.
        endpoint_url: Override endpoint for S3-compatible stores (MinIO,
            Ceph RGW, etc.).  ``None`` uses the default AWS endpoint.
        aws_access_key_id: Explicit access key.  ``None`` defers to the
            boto3 credential chain (env vars, instance profile, etc.).
        aws_secret_access_key: Explicit secret key.
        client: Pre-configured ``boto3`` S3 client for testing.  When
            provided, ``region``, ``endpoint_url``, and credential
            arguments are ignored.
    """

    def __init__(
        self,
        *,
        bucket: str,
        region: str = "us-east-1",
        endpoint_url: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        client: Any | None = None,
    ) -> None:
        self._bucket = bucket
        self._region = region
        self._endpoint_url = endpoint_url

        if client is not None:
            self._client = client
        elif _boto3 is None:
            msg = (
                "boto3 is required for S3StorageBackend. "
                "Install it with: pip install boto3"
            )
            raise ImportError(msg)
        else:
            kwargs: dict[str, Any] = {
                "service_name": "s3",
                "region_name": region,
            }
            if endpoint_url is not None:
                kwargs["endpoint_url"] = endpoint_url
            if aws_access_key_id is not None:
                kwargs["aws_access_key_id"] = aws_access_key_id
            if aws_secret_access_key is not None:
                kwargs["aws_secret_access_key"] = aws_secret_access_key
            self._client = _boto3.client(**kwargs)

    # -- ABC implementation ---------------------------------------------------

    async def put(
        self,
        key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str:
        """Store bytes in S3 under *key*, return the S3 URI.

        The object is written with the specified ``ContentType`` and a
        custom metadata header ``x-amz-meta-sha256`` containing the
        FIPS-compliant SHA-256 hex digest of *data* for integrity
        verification on retrieval.
        """
        sha256_hex = compute_sha256_hex(data)

        await asyncio.to_thread(
            self._client.put_object,
            Bucket=self._bucket,
            Key=key,
            Body=data,
            ContentType=content_type,
            Metadata={"sha256": sha256_hex},
        )

        return f"s3://{self._bucket}/{key}"

    async def get(self, key: str) -> bytes:
        """Retrieve bytes from S3 by key.

        Raises:
            StorageKeyNotFoundError: when no object exists for *key*.
        """
        try:
            response = await asyncio.to_thread(
                self._client.get_object,
                Bucket=self._bucket,
                Key=key,
            )
            body = response["Body"]
            data = await asyncio.to_thread(body.read)
            return data
        except Exception as exc:
            # Catch both botocore ClientError (NoSuchKey, 404) and any
            # other exception that indicates the key does not exist.
            if _botocore_exceptions is not None and isinstance(
                exc, _botocore_exceptions.ClientError
            ):
                error_code = exc.response.get("Error", {}).get("Code", "")
                if error_code in ("NoSuchKey", "404"):
                    raise StorageKeyNotFoundError(
                        f"No object stored for key {key!r}"
                    ) from exc
            # Re-check for mock-based testing where the exception type
            # may not be a real ClientError.
            error_str = str(exc)
            if "NoSuchKey" in error_str or "404" in error_str:
                raise StorageKeyNotFoundError(
                    f"No object stored for key {key!r}"
                ) from exc
            raise

    async def exists(self, key: str) -> bool:
        """Check existence via S3 HEAD request."""
        try:
            await asyncio.to_thread(
                self._client.head_object,
                Bucket=self._bucket,
                Key=key,
            )
            return True
        except Exception:
            return False

    async def delete(self, key: str) -> bool:
        """Delete an object from S3.

        Returns ``True`` if the key existed and was removed, ``False``
        otherwise.  S3 ``delete_object`` is idempotent and does not
        error on missing keys, so we check existence first.
        """
        if not await self.exists(key):
            return False

        await asyncio.to_thread(
            self._client.delete_object,
            Bucket=self._bucket,
            Key=key,
        )
        return True

    async def list_keys(self, prefix: str = "") -> list[str]:
        """List all object keys matching *prefix* via S3 pagination.

        Uses the ``list_objects_v2`` paginator to handle buckets with
        more than 1000 keys.
        """
        keys: list[str] = []
        kwargs: dict[str, Any] = {"Bucket": self._bucket}
        if prefix:
            kwargs["Prefix"] = prefix

        # Paginate through all results.
        continuation_token: str | None = None
        while True:
            if continuation_token:
                kwargs["ContinuationToken"] = continuation_token

            response = await asyncio.to_thread(
                self._client.list_objects_v2,
                **kwargs,
            )

            for obj in response.get("Contents", []):
                keys.append(obj["Key"])

            if response.get("IsTruncated"):
                continuation_token = response.get("NextContinuationToken")
            else:
                break

        return keys

    # -- Evidence-specific helpers ------------------------------------------

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
        stored as S3 object metadata (``x-amz-meta-sha256``) for
        integrity validation on retrieval.

        Args:
            key: Logical key for the evidence blob (e.g. a content hash
                or descriptive identifier).
            content: Raw evidence bytes.
            metadata: Optional caller-supplied metadata dict.  Stored as
                S3 object metadata (``x-amz-meta-*`` headers).

        Returns:
            The full storage key (with ``evidence/`` prefix).
        """
        full_key = f"{_EVIDENCE_KEY_PREFIX}/{key}"

        # Merge caller metadata with the SHA-256 integrity hash.
        sha256_hex = compute_sha256_hex(content)
        s3_metadata = {"sha256": sha256_hex}
        if metadata:
            # Prefix caller keys with "user-" to avoid collision with
            # our internal metadata keys.
            for k, v in metadata.items():
                s3_metadata[f"user-{k}"] = str(v)

        await asyncio.to_thread(
            self._client.put_object,
            Bucket=self._bucket,
            Key=full_key,
            Body=content,
            ContentType="application/octet-stream",
            Metadata=s3_metadata,
        )

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

    # -- Content-addressed key generation -----------------------------------

    @staticmethod
    def content_key(
        tenant_id: str,
        run_id: str,
        content: bytes,
    ) -> str:
        """Generate a content-addressed key for an evidence blob.

        Follows the convention ``{tenant_id}/{run_id}/{sha256_hex}``
        for tenant-scoped, run-scoped, content-addressed storage.

        Args:
            tenant_id: Tenant UUID string.
            run_id: Run identifier string.
            content: Raw bytes to hash.

        Returns:
            The content-addressed key path.
        """
        sha256_hex = compute_sha256_hex(content)
        return f"{tenant_id}/{run_id}/{sha256_hex}"


__all__ = ["S3StorageBackend"]
