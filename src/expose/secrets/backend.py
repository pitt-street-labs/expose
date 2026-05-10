"""Abstract base for per-tenant secrets backends (per SPEC §6.4 / §10.1).

The ABC commits to a tiny async surface area:

- :meth:`SecretsBackend.get` — raises :class:`SecretNotFoundError` on miss
  (consistent with the dispatcher's expectation that a missing credential is a
  catastrophic per-collector failure, not a silently-empty value).
- :meth:`SecretsBackend.set` — overwrite-on-conflict semantics so importers and
  rotation flows are idempotent.
- :meth:`SecretsBackend.delete` — idempotent (no-op when key absent), so
  cleanup paths can be re-run safely.
- :meth:`SecretsBackend.list_keys` — for debugging and migration tooling. Keys
  only — secret values are never enumerated in bulk.

Every method takes ``tenant_id`` as a keyword-only argument. Per ADR-007,
tenant context is propagated explicitly at every layer; backends MUST scope
storage per tenant so a credential set for tenant A is unreachable from
tenant B (see :file:`tests/test_secrets.py::test_tenant_isolation`).

Implementations MUST NOT log secret values. The :class:`InMemoryBackend`
``__repr__`` includes counts only as a model for production backends.

Naming: an :exc:`SecretNotFoundError` subclasses :exc:`KeyError` so
``backend.get(...)`` reads as a mapping-style lookup at call sites that prefer
``except KeyError`` (e.g., legacy collector code being ported in).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from uuid import UUID


class SecretNotFoundError(KeyError):
    """Raised by :meth:`SecretsBackend.get` when no value is stored for a key.

    Subclasses :exc:`KeyError` so call sites may use either
    ``except SecretNotFoundError`` (precise) or ``except KeyError`` (broad).
    The message is the canonical form used by the in-memory backend; other
    backends should follow the same shape for log-grep stability.
    """


class SecretsBackend(ABC):
    """Per-tenant secrets storage.

    v1 ships :class:`expose.secrets.memory_backend.InMemoryBackend` for tests
    and local development. Production deployments wire Vault / cloud-KMS /
    Vaultwarden implementations against this same surface (issue #8 in the
    Gitea backlog tracks production-hardening implementations).

    Contract:

    - All methods are async; even sync-internal backends should expose async
      methods so the dispatcher does not branch on backend kind.
    - All methods take ``tenant_id`` as a keyword-only argument; positional
      ``tenant_id`` is not accepted (call-site clarity over brevity).
    - ``get`` raises :class:`SecretNotFoundError` on miss; never returns
      ``None`` for an absent key (a stored empty-string value IS a hit).
    - ``set`` overwrites silently on conflict; importers and key-rotation
      flows depend on this idempotence.
    - ``delete`` is idempotent — deleting an absent key is a no-op, not an
      error. Audit logging for the delete still fires.
    - ``list_keys`` returns the *keys* stored for the tenant — never values.
    """

    @abstractmethod
    async def get(self, *, tenant_id: UUID, key: str) -> str:
        """Return the secret value stored for ``(tenant_id, key)``.

        Raises:
            SecretNotFoundError: when no value is stored for the key.
        """

    @abstractmethod
    async def set(self, *, tenant_id: UUID, key: str, value: str) -> None:
        """Store ``value`` under ``(tenant_id, key)``, overwriting any prior value.

        Implementations MUST NOT log ``value`` at any level. The audit log
        entry, if any, references the key only.
        """

    @abstractmethod
    async def delete(self, *, tenant_id: UUID, key: str) -> None:
        """Remove the value stored under ``(tenant_id, key)``.

        Idempotent: deleting an absent key is a successful no-op so cleanup
        paths and rotation scripts can be re-run without special-casing.
        """

    @abstractmethod
    async def list_keys(self, *, tenant_id: UUID) -> Sequence[str]:
        """Return the keys (NOT values) stored for ``tenant_id``.

        Order is implementation-defined; callers requiring a stable order
        should sort. Keys for OTHER tenants MUST NOT appear in the result.
        """


__all__ = ["SecretNotFoundError", "SecretsBackend"]
