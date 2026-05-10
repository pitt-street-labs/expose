"""Per-tenant collector credential resolution (per SPEC §6.4).

The ``CredentialResolver`` bridges the ``SecretsBackend`` and the dispatcher's
``CollectorConfig`` construction. Each collector declares its credential
requirements via a ``CollectorCredentialSpec``; the resolver fetches
tenant-specific values from the backend just before dispatch.

Design properties:

- **Just-in-time resolution.** Credentials are fetched per dispatch, not cached.
  SPEC §6.4 requires that secret material is held only for the lifetime of a
  single ``expand`` invocation.
- **Fail-fast on missing keys.** If a required key is absent from the backend,
  ``CredentialResolutionError`` is raised *before* the collector is constructed.
  This keeps collector code free of credential-presence checks.
- **Unknown collectors are credential-free.** A collector ID not present in
  ``CREDENTIAL_SPECS`` is treated as needing no credentials. This prevents
  the registry from having to be kept in lock-step with the spec table during
  early sprints.
- **Secret values are never logged.** The resolver returns ``CollectorCredential``
  instances whose ``secret_value`` field is handled by the dispatcher's existing
  no-log policy.

Secrets backend key convention: ``collector.{collector_id}.{key_name}``
(matches the pattern established in ``tests/test_secrets.py``).
"""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from expose.collectors.base import CollectorCredential
from expose.secrets.backend import SecretNotFoundError, SecretsBackend


class CollectorCredentialSpec(BaseModel):
    """Declares what credentials a collector needs.

    Each entry describes the credential slots a collector will look up at
    dispatch time. Collectors with ``required_keys == []`` (e.g., Tier-1
    passive collectors like ``ct-crtsh``) need no credentials and will
    always receive an empty credentials dict.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    collector_id: str = Field(min_length=1)
    required_keys: list[str] = Field(default_factory=list)


class CredentialResolutionError(Exception):
    """Required credentials could not be resolved from the secrets backend.

    Raised when one or more keys declared in a collector's
    ``CollectorCredentialSpec.required_keys`` are absent from the secrets
    backend for the target tenant. The message includes the collector ID,
    tenant ID, and list of missing key names — but never the secret values
    themselves.
    """


# ============================================================================
# Registry of known credential requirements per collector
# ============================================================================
#
# All Sprint 1-2 collectors are Tier-1 / Tier-3 passive or active probes that
# operate against public data sources and require no API keys.  Future Tier-2
# collectors (Shodan, SecurityTrails, etc.) will add entries with non-empty
# required_keys lists.
CREDENTIAL_SPECS: dict[str, CollectorCredentialSpec] = {
    "ct-crtsh": CollectorCredentialSpec(
        collector_id="ct-crtsh",
        required_keys=[],
    ),
    "cloud-ranges": CollectorCredentialSpec(
        collector_id="cloud-ranges",
        required_keys=[],
    ),
    "rdap-whois": CollectorCredentialSpec(
        collector_id="rdap-whois",
        required_keys=[],
    ),
    "active-dns-resolve": CollectorCredentialSpec(
        collector_id="active-dns-resolve",
        required_keys=[],
    ),
    "active-http-fingerprint": CollectorCredentialSpec(
        collector_id="active-http-fingerprint",
        required_keys=[],
    ),
    # Future Tier-2 collectors that need keys:
    # "shodan": CollectorCredentialSpec(
    #     collector_id="shodan",
    #     required_keys=["api_key"],
    # ),
    # "securitytrails": CollectorCredentialSpec(
    #     collector_id="securitytrails",
    #     required_keys=["api_key"],
    # ),
}


class CredentialResolver:
    """Resolves per-tenant credentials for a collector from the secrets backend.

    Called by the dispatcher just before constructing ``CollectorConfig``.
    Credentials are fetched just-in-time per SPEC §6.4 — values are not
    cached across dispatches.

    The resolver encodes the secrets backend key as
    ``collector.{collector_id}.{key_name}`` to match the convention in the
    existing test suite (see ``tests/test_secrets.py``).
    """

    def __init__(self, backend: SecretsBackend) -> None:
        self._backend = backend

    async def resolve(
        self, tenant_id: UUID, collector_id: str
    ) -> dict[str, CollectorCredential]:
        """Fetch credentials for the given collector and tenant.

        Returns a dict of ``{key_name: CollectorCredential}``.

        If a required key is missing from the backend,
        ``CredentialResolutionError`` is raised with the list of missing keys.

        If no credentials are needed (empty ``required_keys`` or unknown
        ``collector_id``), returns ``{}``.
        """
        spec = CREDENTIAL_SPECS.get(collector_id)
        if spec is None or not spec.required_keys:
            return {}

        credentials: dict[str, CollectorCredential] = {}
        missing: list[str] = []

        for key in spec.required_keys:
            backend_key = f"collector.{collector_id}.{key}"
            try:
                value = await self._backend.get(tenant_id=tenant_id, key=backend_key)
                credentials[key] = CollectorCredential(name=key, secret_value=value)
            except SecretNotFoundError:
                missing.append(key)

        if missing:
            raise CredentialResolutionError(
                f"Missing credentials for collector {collector_id!r}, "
                f"tenant {tenant_id}: {missing}"
            )

        return credentials


__all__ = [
    "CREDENTIAL_SPECS",
    "CollectorCredentialSpec",
    "CredentialResolutionError",
    "CredentialResolver",
]
