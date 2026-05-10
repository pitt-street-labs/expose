"""HashiCorp Vault KV v2 secrets backend (issue #8).

Production-ready :class:`SecretsBackend` implementation that delegates to a
HashiCorp Vault instance using its HTTP API.  Secrets are stored in the KV
version 2 engine at::

    {mount_path}/data/expose/tenants/{tenant_id}/{key}

Per-tenant isolation is enforced by including ``tenant_id`` in the Vault path.
A Vault policy can further restrict each tenant's access scope to its own
sub-tree (recommended in multi-tenant deployments per ADR-007).

Authentication is via the ``X-Vault-Token`` header.  The token may be supplied
directly via the constructor or resolved from the ``VAULT_TOKEN`` environment
variable (standard Vault CLI convention).

Thread/async safety: the underlying :class:`httpx.AsyncClient` is safe for
concurrent use from multiple asyncio tasks.  No internal locking is needed.

Security:

- Secret values are NEVER logged.  Only the path (tenant + key) appears in
  error messages or audit trail.
- TLS is on by default (``tls_verify=True``).  Passing ``tls_verify=False``
  should only be used in development/test environments.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from uuid import UUID

import httpx

from expose.secrets.backend import SecretNotFoundError, SecretsBackend

logger = logging.getLogger(__name__)

# HTTP status codes used in Vault API responses.
_HTTP_FORBIDDEN = 403
_HTTP_NOT_FOUND = 404
_HTTP_OK = 200
_HTTP_NO_CONTENT = 204


class VaultAuthError(PermissionError):
    """Raised when Vault returns HTTP 403 (forbidden / token invalid)."""


class VaultSecretsBackend(SecretsBackend):
    """HashiCorp Vault KV v2 secrets backend.

    Stores secrets at: ``{mount_path}/data/expose/tenants/{tenant_id}/{key}``

    Parameters
    ----------
    vault_addr:
        Base URL of the Vault server (default ``http://127.0.0.1:8200``).
    vault_token:
        Vault authentication token.  Falls back to the ``VAULT_TOKEN``
        environment variable if not supplied.
    mount_path:
        KV v2 engine mount point (default ``secret``).
    tls_verify:
        Whether to verify TLS certificates (default ``True``).
    """

    def __init__(
        self,
        vault_addr: str = "http://127.0.0.1:8200",
        vault_token: str | None = None,
        mount_path: str = "secret",
        tls_verify: bool = True,
    ) -> None:
        resolved_token = vault_token or os.environ.get("VAULT_TOKEN", "")
        self._vault_addr = vault_addr.rstrip("/")
        self._mount_path = mount_path
        self._client = httpx.AsyncClient(
            base_url=self._vault_addr,
            headers={"X-Vault-Token": resolved_token},
            verify=tls_verify,
        )

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _data_path(self, tenant_id: UUID, key: str) -> str:
        """KV v2 ``data`` path for reads and writes."""
        return f"/v1/{self._mount_path}/data/expose/tenants/{tenant_id}/{key}"

    def _metadata_path(self, tenant_id: UUID) -> str:
        """KV v2 ``metadata`` path for LIST operations."""
        return f"/v1/{self._mount_path}/metadata/expose/tenants/{tenant_id}/"

    def _delete_metadata_path(self, tenant_id: UUID, key: str) -> str:
        """KV v2 ``metadata`` path for permanent DELETE of a key."""
        return f"/v1/{self._mount_path}/metadata/expose/tenants/{tenant_id}/{key}"

    # ------------------------------------------------------------------
    # SecretsBackend implementation
    # ------------------------------------------------------------------

    async def get(self, *, tenant_id: UUID, key: str) -> str:
        """Read a secret from Vault KV v2.

        Raises:
            SecretNotFoundError: when the key does not exist (HTTP 404).
            VaultAuthError: when the token is invalid or lacks permission (HTTP 403).
        """
        resp = await self._client.get(self._data_path(tenant_id, key))
        if resp.status_code == _HTTP_NOT_FOUND:
            raise SecretNotFoundError(
                f"No secret stored for tenant {tenant_id} key {key!r}"
            )
        if resp.status_code == _HTTP_FORBIDDEN:
            raise VaultAuthError(
                f"Vault auth error reading tenant {tenant_id} key {key!r}"
            )
        resp.raise_for_status()
        payload: dict[str, object] = resp.json()
        data = payload.get("data", {})
        if isinstance(data, dict):
            inner = data.get("data", {})
            if isinstance(inner, dict):
                value = inner.get("value")
                if isinstance(value, str):
                    return value
        raise SecretNotFoundError(
            f"No secret stored for tenant {tenant_id} key {key!r}"
        )

    async def set(self, *, tenant_id: UUID, key: str, value: str) -> None:
        """Write a secret to Vault KV v2.

        Overwrites any existing value under this path (idempotent).

        Raises:
            VaultAuthError: when the token is invalid or lacks permission.
        """
        resp = await self._client.post(
            self._data_path(tenant_id, key),
            json={"data": {"value": value}},
        )
        if resp.status_code == _HTTP_FORBIDDEN:
            raise VaultAuthError(
                f"Vault auth error writing tenant {tenant_id} key {key!r}"
            )
        resp.raise_for_status()
        logger.debug("Vault: wrote secret for tenant=%s key=%r", tenant_id, key)

    async def delete(self, *, tenant_id: UUID, key: str) -> None:
        """Delete a secret from Vault KV v2 (metadata-level permanent delete).

        Idempotent: deleting a non-existent key is a no-op (Vault returns 204
        or 404; both are treated as success).
        """
        resp = await self._client.delete(
            self._delete_metadata_path(tenant_id, key),
        )
        if resp.status_code == _HTTP_FORBIDDEN:
            raise VaultAuthError(
                f"Vault auth error deleting tenant {tenant_id} key {key!r}"
            )
        # 204 = deleted, 404 = already absent — both are success for
        # idempotent delete semantics.
        if resp.status_code not in (_HTTP_OK, _HTTP_NO_CONTENT, _HTTP_NOT_FOUND):
            resp.raise_for_status()
        logger.debug("Vault: deleted secret for tenant=%s key=%r", tenant_id, key)

    async def list_keys(self, *, tenant_id: UUID) -> Sequence[str]:
        """List secret keys for a tenant via the Vault LIST method.

        Returns an empty sequence when the tenant sub-tree does not exist
        (Vault returns 404 for LIST on a missing path).
        """
        resp = await self._client.request(
            "LIST",
            self._metadata_path(tenant_id),
        )
        if resp.status_code == _HTTP_NOT_FOUND:
            return []
        if resp.status_code == _HTTP_FORBIDDEN:
            raise VaultAuthError(
                f"Vault auth error listing keys for tenant {tenant_id}"
            )
        resp.raise_for_status()
        payload: dict[str, object] = resp.json()
        data = payload.get("data", {})
        if isinstance(data, dict):
            keys = data.get("keys", [])
            if isinstance(keys, list):
                return sorted(str(k) for k in keys)
        return []

    async def close(self) -> None:
        """Close the underlying HTTP client.

        Call this during application shutdown to release connections.
        """
        await self._client.aclose()

    def __repr__(self) -> str:
        """Render addr + mount only; never token or secrets."""
        return (
            f"VaultSecretsBackend(addr={self._vault_addr!r}, "
            f"mount={self._mount_path!r})"
        )


__all__ = ["VaultAuthError", "VaultSecretsBackend"]
