"""Per-tenant secrets storage abstraction (per ADR-008 + SPEC §6.4 / §10.1).

The secrets backend is the single chokepoint between collector code and
credential storage. Per SPEC §6.4, collector credentials are *fetched
just-in-time per call* from the configured backend; instances do not persist
secret values beyond the lifetime of a single ``expand`` invocation.

Per ADR-008's threat model, compromise of LLM provider credentials is an
explicit threat the secrets backend abstraction is designed to mitigate:
backends scope keys per tenant, log access for audit, and never log secret
values themselves.

Sub-modules:

- ``backend`` — :class:`SecretsBackend` ABC and :class:`SecretNotFoundError`.
- ``memory_backend`` — :class:`InMemoryBackend` (test/dev only).
- ``env_backend`` — :class:`EnvSecretsBackend` (lightweight production —
  reads secrets from environment variables, useful for Kubernetes).
- ``vault_backend`` — :class:`VaultSecretsBackend` (production — HashiCorp
  Vault KV v2 via httpx).
"""

from expose.secrets.backend import SecretNotFoundError, SecretsBackend
from expose.secrets.env_backend import EnvSecretsBackend
from expose.secrets.memory_backend import InMemoryBackend
from expose.secrets.vault_backend import VaultAuthError, VaultSecretsBackend

__all__ = [
    "EnvSecretsBackend",
    "InMemoryBackend",
    "SecretNotFoundError",
    "SecretsBackend",
    "VaultAuthError",
    "VaultSecretsBackend",
]
