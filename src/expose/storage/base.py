"""Abstract base for evidence and artifact storage backends.

EXPOSE generates evidence blobs (raw HTTP responses, cert PEMs, DNS
responses) and canonical artifacts that need persistent storage beyond the
Postgres relational layer.  This module defines the :class:`StorageBackend`
ABC that all concrete backends implement.

Keys follow a tenant-scoped convention::

    tenant / {tenant_id} / evidence / {sha256_hex}
    tenant / {tenant_id} / artifacts / {run_id}.json

This ensures per-tenant isolation at the storage layer (per ADR-007) and
makes prefix-based listing straightforward for garbage collection, export,
and compliance workflows.

Implementations:

- :class:`expose.storage.local.LocalStorageBackend` — local filesystem
  (lab/dev deployments).
- :class:`expose.storage.s3.S3StorageBackend` — S3-compatible stub
  (interface ready; production implementation deferred per issue #9).
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class StorageKeyNotFoundError(KeyError):
    """Raised by :meth:`StorageBackend.get` when no value is stored for a key.

    Subclasses :exc:`KeyError` so call sites may use either
    ``except StorageKeyNotFoundError`` (precise) or ``except KeyError``
    (broad) — consistent with the pattern established by
    :class:`expose.secrets.backend.SecretNotFoundError`.
    """


class StorageBackend(ABC):
    """Async blob storage for evidence and artifacts.

    v1 ships :class:`~expose.storage.local.LocalStorageBackend` for tests
    and lab deployments.  S3-compatible backends will be wired in Sprint 5+
    against this same surface (issue #9 in the Gitea backlog).

    Contract:

    - All methods are async so callers can swap implementations without
      branching on backend kind.
    - :meth:`get` raises :class:`StorageKeyNotFoundError` on miss; never
      returns ``None`` for an absent key.
    - :meth:`put` returns the storage URI so callers can persist a
      reference.
    - :meth:`delete` returns ``True`` if the key existed and was removed,
      ``False`` otherwise — idempotent, never raises on missing keys.
    - :meth:`list_keys` returns keys matching a prefix; an empty prefix
      returns all keys.
    """

    @abstractmethod
    async def put(
        self,
        key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str:
        """Store bytes under *key*, return the storage URI.

        Args:
            key: Tenant-scoped storage key (e.g.
                ``tenant/{id}/evidence/{hash}``).
            data: Raw bytes to store.
            content_type: MIME type hint for downstream consumers.

        Returns:
            A URI string representing the stored object (format is
            backend-specific).
        """

    @abstractmethod
    async def get(self, key: str) -> bytes:
        """Retrieve bytes by key.

        Raises:
            StorageKeyNotFoundError: when no value is stored for *key*.
        """

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Return ``True`` if *key* has a stored value."""

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete the value stored under *key*.

        Returns:
            ``True`` if *key* existed and was removed, ``False`` if it did
            not exist.  Never raises on missing keys.
        """

    @abstractmethod
    async def list_keys(self, prefix: str = "") -> list[str]:
        """Return all keys matching *prefix*.

        An empty prefix returns every key in the backend.  Order is
        implementation-defined; callers requiring a stable order should
        sort.
        """


__all__ = ["StorageBackend", "StorageKeyNotFoundError"]
