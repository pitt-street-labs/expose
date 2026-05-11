"""In-memory :class:`SecretsBackend` with optional file persistence.

Holds plaintext in process memory with automatic save/load to a JSON file
so credentials survive server restarts. NOT FOR PRODUCTION — no audit log,
no encryption-at-rest. For production, use the Vault or cloud-KMS backends.

Per-tenant isolation is enforced by keying internally on ``(tenant_id, key)``
rather than allowing tenant A queries to ever see tenant B's storage.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Final
from uuid import UUID

from expose.secrets.backend import SecretNotFoundError, SecretsBackend

logger = logging.getLogger(__name__)

_DEFAULT_PERSIST_PATH = Path.home() / ".expose-credentials.json"


class InMemoryBackend(SecretsBackend):
    """In-memory :class:`SecretsBackend` with optional file persistence.

    When ``persist_path`` is provided, credentials are saved to a JSON file
    on every ``set()`` and loaded from disk on initialization. This ensures
    credentials survive server restarts without requiring Vault infrastructure.
    """

    _STORE_KEY_TYPE: Final[type[tuple[str, str]]] = tuple

    def __init__(self, persist_path: Path | None = None) -> None:
        self._store: dict[tuple[str, str], str] = {}
        self._persist_path = persist_path
        if persist_path:
            self._load_from_disk()

    def _load_from_disk(self) -> None:
        if not self._persist_path or not self._persist_path.exists():
            return
        try:
            data = json.loads(self._persist_path.read_text())
            for entry in data:
                self._store[(entry["t"], entry["k"])] = entry["v"]
            logger.info(
                "Loaded %d credentials from %s", len(data), self._persist_path
            )
        except Exception:
            logger.warning("Failed to load credentials from %s", self._persist_path, exc_info=True)

    async def _save_to_disk(self) -> None:
        if not self._persist_path:
            return
        try:
            data = json.dumps([{"t": t, "k": k, "v": v} for (t, k), v in self._store.items()])
            await asyncio.to_thread(self._write_file, data)
        except Exception:
            logger.warning("Failed to save credentials to %s", self._persist_path, exc_info=True)

    def _write_file(self, data: str) -> None:
        fd = os.open(str(self._persist_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data.encode())
        finally:
            os.close(fd)

    async def get(self, *, tenant_id: UUID, key: str) -> str:
        try:
            return self._store[(str(tenant_id), key)]
        except KeyError:
            raise SecretNotFoundError(
                f"No secret stored for tenant {tenant_id} key {key!r}"
            ) from None

    async def set(self, *, tenant_id: UUID, key: str, value: str) -> None:
        self._store[(str(tenant_id), key)] = value
        await self._save_to_disk()

    async def delete(self, *, tenant_id: UUID, key: str) -> None:
        self._store.pop((str(tenant_id), key), None)
        await self._save_to_disk()

    async def list_keys(self, *, tenant_id: UUID) -> Sequence[str]:
        target = str(tenant_id)
        return sorted(k for (t, k) in self._store if t == target)

    def __repr__(self) -> str:
        tenants = {tenant for (tenant, _key) in self._store}
        return (
            f"InMemoryBackend(tenants={len(tenants)}, total_keys={len(self._store)})"
        )


__all__ = ["InMemoryBackend"]
