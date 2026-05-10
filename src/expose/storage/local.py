"""Local-filesystem :class:`StorageBackend` implementation.

Stores evidence blobs and artifacts as files under a configurable root
directory.  Keys are mapped directly to file paths relative to that root,
so the tenant-scoped key convention (``tenant/{id}/evidence/{hash}``)
naturally produces a per-tenant directory tree.

NOT FOR PRODUCTION S3-SCALE WORKLOADS.  The implementation uses synchronous
:mod:`pathlib` operations because local disk I/O is fast enough for the lab
deployment target.  The ABC mandates ``async`` signatures so the caller
contract is uniform; production S3 backends will use truly async I/O via
``aioboto3`` or equivalent.

Thread/async safety: synchronous file operations execute on the event
loop's thread.  For the lab's single-task workload this is acceptable.
High-concurrency deployments should use ``asyncio.to_thread`` wrappers or
switch to the S3 backend.
"""

from __future__ import annotations

from pathlib import Path

from expose.storage.base import StorageBackend, StorageKeyNotFoundError


class LocalStorageBackend(StorageBackend):
    """Filesystem-backed :class:`StorageBackend` for tests + lab deployments.

    Args:
        root: Base directory under which all objects are stored.  Created
            on first :meth:`put` if it does not already exist.
    """

    def __init__(self, root: Path) -> None:
        self._root = root

    def _resolve(self, key: str) -> Path:
        """Map a storage key to an absolute filesystem path.

        The key is resolved relative to :attr:`_root`.  Any ``..``
        components are collapsed by :meth:`Path.resolve`, so keys cannot
        escape the root (defense-in-depth; the caller is expected to pass
        well-formed keys).
        """
        return (self._root / key).resolve()

    async def put(
        self,
        key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str:
        """Write *data* to the filesystem under *key*.

        Parent directories are created automatically.  The *content_type*
        is accepted for API compatibility but not persisted (local
        filesystem has no native content-type metadata).

        Returns:
            A ``file://`` URI pointing to the stored file.
        """
        path = self._resolve(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path.as_uri()

    async def get(self, key: str) -> bytes:
        """Read and return the bytes stored under *key*.

        Raises:
            StorageKeyNotFoundError: when the file does not exist.
        """
        path = self._resolve(key)
        if not path.is_file():
            raise StorageKeyNotFoundError(f"No object stored for key {key!r}")
        return path.read_bytes()

    async def exists(self, key: str) -> bool:
        """Return ``True`` if a file exists at the path for *key*."""
        return self._resolve(key).is_file()

    async def delete(self, key: str) -> bool:
        """Remove the file for *key* if it exists.

        Returns:
            ``True`` if the file existed and was removed, ``False``
            otherwise.
        """
        path = self._resolve(key)
        if not path.is_file():
            return False
        path.unlink()
        return True

    async def list_keys(self, prefix: str = "") -> list[str]:
        """Return all keys under *prefix* by walking the filesystem.

        Keys are returned as POSIX-style relative paths from the root,
        matching the convention used by :meth:`put`.
        """
        search_root = self._root / prefix if prefix else self._root
        if not search_root.exists():
            return []
        # If the prefix resolves to a file, return just that key.
        if search_root.is_file():
            return [search_root.relative_to(self._root).as_posix()]
        return sorted(
            p.relative_to(self._root).as_posix() for p in search_root.rglob("*") if p.is_file()
        )


__all__ = ["LocalStorageBackend"]
