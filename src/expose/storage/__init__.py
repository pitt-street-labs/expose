"""Object storage abstraction for evidence blobs and artifacts (issue #9).

EXPOSE generates evidence blobs (raw HTTP responses, cert PEMs, DNS
responses) and canonical artifacts that need persistent storage beyond the
Postgres relational layer.  This package provides a pluggable
:class:`StorageBackend` ABC with a local-filesystem implementation for
lab/dev deployments and an S3-compatible stub for future cloud deployments.

Sub-modules:

- ``base`` — :class:`StorageBackend` ABC and :class:`StorageKeyNotFoundError`.
- ``local`` — :class:`LocalStorageBackend` (filesystem-backed, lab/dev).
- ``s3`` — :class:`S3StorageBackend` (stub — interface ready, impl deferred).

Keys follow the tenant-scoped convention
``tenant/{tenant_id}/evidence/{sha256_hex}`` and
``tenant/{tenant_id}/artifacts/{run_id}.json`` to ensure per-tenant
isolation at the storage layer (per ADR-007).
"""

from expose.storage.base import StorageBackend, StorageKeyNotFoundError
from expose.storage.local import LocalStorageBackend
from expose.storage.s3 import S3StorageBackend

__all__ = [
    "LocalStorageBackend",
    "S3StorageBackend",
    "StorageBackend",
    "StorageKeyNotFoundError",
]
