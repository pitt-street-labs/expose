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
- ``memory_backend`` — :class:`InMemoryBackend` (test/dev only — production
  deployments wire Vaultwarden / cloud KMS / HashiCorp Vault implementations
  per SPEC §6.4).

This package is the v1 framework. Issue #8 tracks Vault/KMS-backed
implementations for production-hardening.
"""

from expose.secrets.backend import SecretNotFoundError, SecretsBackend
from expose.secrets.memory_backend import InMemoryBackend

__all__ = [
    "InMemoryBackend",
    "SecretNotFoundError",
    "SecretsBackend",
]
