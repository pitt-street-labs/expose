"""In-memory :class:`SecretsBackend` implementation.

NOT FOR PRODUCTION. Loses all data on process exit, holds plaintext in process
memory, no audit log, no encryption-at-rest. The implementation exists so that:

- Unit tests do not require a Vault / KMS dependency to exercise the dispatcher
  contract.
- Local development (``expose run --tenant default``) can wire up collector
  credentials without standing up secret infrastructure first.
- The :file:`tests/test_secrets.py` suite has a concrete subject that validates
  the abstract contract — production backends inherit and pass the same tests
  via parametrization (Sprint 5+).

Per-tenant isolation is enforced by keying internally on ``(tenant_id, key)``
rather than allowing tenant A queries to ever see tenant B's storage.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final
from uuid import UUID

from expose.secrets.backend import SecretNotFoundError, SecretsBackend


class InMemoryBackend(SecretsBackend):
    """In-memory :class:`SecretsBackend` for tests + local dev only.

    Internal layout: a ``dict`` keyed on ``(tenant_id_str, key)`` -> value.
    The tenant component is stringified to its canonical UUID form so that
    equivalent UUIDs (e.g., constructed via different hex/byte paths) resolve
    to the same storage slot.

    Thread/async safety: this implementation is NOT thread-safe and not
    designed for concurrent ``set`` from many tasks. Production backends will
    delegate concurrency to their backing store. For the current single-task
    test suite and local-dev path, the bare ``dict`` is sufficient.

    The :meth:`__repr__` deliberately includes only structural counts; secret
    values and even the keys are never serialized into the repr to prevent
    accidental disclosure via ``logging.debug(backend)`` or REPL inspection.
    """

    # The store value type is plain ``str`` because every method returns
    # ``str`` and we never want a richer object accidentally getting
    # ``__repr__``-ed somewhere it could leak.
    _STORE_KEY_TYPE: Final[type[tuple[str, str]]] = tuple

    def __init__(self) -> None:
        """Initialize an empty in-memory store."""
        self._store: dict[tuple[str, str], str] = {}

    async def get(self, *, tenant_id: UUID, key: str) -> str:
        """Return the stored value for ``(tenant_id, key)``.

        Raises:
            SecretNotFoundError: when no value is stored for ``key``.
        """
        try:
            return self._store[(str(tenant_id), key)]
        except KeyError:
            # Build the message without including any value-side state.
            raise SecretNotFoundError(
                f"No secret stored for tenant {tenant_id} key {key!r}"
            ) from None

    async def set(self, *, tenant_id: UUID, key: str, value: str) -> None:
        """Store ``value`` under ``(tenant_id, key)``, overwriting any prior value."""
        self._store[(str(tenant_id), key)] = value

    async def delete(self, *, tenant_id: UUID, key: str) -> None:
        """Remove the value stored under ``(tenant_id, key)``.

        No-op when no value is stored (idempotent per the ABC contract).
        """
        self._store.pop((str(tenant_id), key), None)

    async def list_keys(self, *, tenant_id: UUID) -> Sequence[str]:
        """Return the keys stored for ``tenant_id`` (sorted for determinism).

        Sorted output makes test assertions stable across Python dict-ordering
        changes; production backends are not required to sort but doing so is
        cheap and aids debugging.
        """
        target = str(tenant_id)
        return sorted(k for (t, k) in self._store if t == target)

    def __repr__(self) -> str:
        """Render structural counts only — no tenant IDs, keys, or values.

        Format: ``InMemoryBackend(tenants=N, total_keys=M)``. The repr is the
        only string surface that can leak via ``logging.debug(self)`` or REPL
        echo, so it deliberately excludes the underlying store contents. See
        :file:`tests/test_secrets.py::test_repr_does_not_leak_values`.
        """
        tenants = {tenant for (tenant, _key) in self._store}
        return (
            f"InMemoryBackend(tenants={len(tenants)}, total_keys={len(self._store)})"
        )


__all__ = ["InMemoryBackend"]
