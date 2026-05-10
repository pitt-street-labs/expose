"""Environment-variable :class:`SecretsBackend` implementation (issue #8).

A lightweight production backend that reads secrets from environment variables.
Useful in Kubernetes deployments where secrets are injected as env vars via
``Secret`` resources, or in CI/CD pipelines where credentials are set in the
runner's environment.

Key convention::

    EXPOSE_SECRET_{TENANT_ID}_{KEY}

where both ``TENANT_ID`` and ``KEY`` are uppercased, with hyphens replaced by
underscores.  Example:

- tenant ``018f1f00-0000-7000-8000-00000000a001``, key ``api_key``
  resolves to ``EXPOSE_SECRET_018F1F00_0000_7000_8000_00000000A001_API_KEY``

Per-tenant isolation is enforced by embedding the full tenant UUID in the
environment variable name.  :meth:`list_keys` scans ``os.environ`` for
matching prefixes.

Security:

- Secret values are NEVER logged.  Only the derived env-var name appears in
  error messages.
- The ``set`` and ``delete`` methods mutate the **process-level** environment
  (``os.environ``).  They exist for test symmetry and import/rotation tooling;
  Kubernetes deployments typically provide env vars at pod startup and treat
  them as immutable.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from uuid import UUID

from expose.secrets.backend import SecretNotFoundError, SecretsBackend

_PREFIX = "EXPOSE_SECRET_"


def _env_key(tenant_id: UUID, key: str) -> str:
    """Derive the environment variable name for a (tenant_id, key) pair.

    Both the tenant UUID and the logical key are uppercased, with hyphens
    replaced by underscores so they are valid shell identifiers.
    """
    tenant_part = str(tenant_id).upper().replace("-", "_")
    key_part = key.upper().replace("-", "_")
    return f"{_PREFIX}{tenant_part}_{key_part}"


class EnvSecretsBackend(SecretsBackend):
    """Reads secrets from environment variables.

    Key convention: ``EXPOSE_SECRET_{TENANT_ID}_{KEY}`` (uppercased,
    hyphens replaced with underscores).

    Example::

        EXPOSE_SECRET_018F1F00_0000_7000_8000_00000000A001_API_KEY=sk-xxx
    """

    async def get(self, *, tenant_id: UUID, key: str) -> str:
        """Return the value of the derived environment variable.

        Raises:
            SecretNotFoundError: when the env var is not set.
        """
        env_name = _env_key(tenant_id, key)
        value = os.environ.get(env_name)
        if value is None:
            raise SecretNotFoundError(
                f"No secret stored for tenant {tenant_id} key {key!r}"
            )
        return value

    async def set(self, *, tenant_id: UUID, key: str, value: str) -> None:
        """Set the environment variable for ``(tenant_id, key)``.

        Mutates the current process environment.  In Kubernetes deployments,
        secrets are typically injected at pod startup and this method is only
        used for import/rotation tooling and testing.
        """
        env_name = _env_key(tenant_id, key)
        os.environ[env_name] = value

    async def delete(self, *, tenant_id: UUID, key: str) -> None:
        """Remove the environment variable for ``(tenant_id, key)``.

        Idempotent: removing an absent variable is a no-op.
        """
        env_name = _env_key(tenant_id, key)
        os.environ.pop(env_name, None)

    async def list_keys(self, *, tenant_id: UUID) -> Sequence[str]:
        """Return logical keys for the given tenant by scanning ``os.environ``.

        Scans all environment variables for the tenant-specific prefix and
        reverse-maps matched variables back to their logical key names
        (lowercased, underscores preserved).
        """
        tenant_prefix = f"{_PREFIX}{str(tenant_id).upper().replace('-', '_')}_"
        results: list[str] = []
        for env_var in os.environ:
            if env_var.startswith(tenant_prefix):
                # Strip the prefix to recover the logical key portion.
                raw_key = env_var[len(tenant_prefix) :]
                # Return lowercased key to match the convention used at set()
                # time — the caller set ``key="api_key"`` and we stored it
                # uppercased.
                results.append(raw_key.lower())
        return sorted(results)

    def __repr__(self) -> str:
        """Render type only; never keys or values."""
        return "EnvSecretsBackend()"


__all__ = ["EnvSecretsBackend"]
