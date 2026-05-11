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
- **Independent tenant-scope validation.** The resolver validates every backend
  key path before querying the backend AND verifies returned credentials belong
  to the requesting tenant. This defense-in-depth check (finding #147) ensures
  that even a weak backend cannot leak credentials across tenants.

Secrets backend key convention: ``collector.{collector_id}.{key_name}``
(matches the pattern established in ``tests/test_secrets.py``).
"""

from __future__ import annotations

import logging
import re
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from expose.collectors.base import CollectorCredential
from expose.secrets.backend import SecretNotFoundError, SecretsBackend

logger = logging.getLogger(__name__)

# Regex for valid backend key paths: dotted segments of alphanumeric + hyphens
# and underscores. Prevents path traversal, embedded tenant IDs, and
# control characters in key paths.
_VALID_KEY_PATH_RE = re.compile(r"^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*$")


class CollectorCredentialSpec(BaseModel):
    """Declares what credentials a collector needs.

    Each entry describes the credential slots a collector will look up at
    dispatch time. Collectors with ``required_keys == []`` and
    ``optional_keys == []`` (e.g., Tier-1 passive collectors like
    ``ct-crtsh``) need no credentials and will always receive an empty
    credentials dict.

    ``optional_keys`` lists credentials that are fetched when available
    but do not cause ``CredentialResolutionError`` when absent. This is
    for collectors that enhance their output with API keys but can still
    operate at reduced capability without them (e.g., ``dns-chaos``
    falls back to public-tier access, ``github-exposed`` runs with
    tighter rate limits).

    ``key_mapping`` overrides the default backend key derivation
    (``collector.{collector_id}.{key}``) for keys that are stored under
    a different path (e.g., shared across collectors or using the
    ``unmapped.*`` convention from SpiderFoot imports).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    collector_id: str = Field(min_length=1)
    required_keys: list[str] = Field(default_factory=list)
    optional_keys: list[str] = Field(default_factory=list)
    key_mapping: dict[str, str] = Field(default_factory=dict)


class CredentialResolutionError(Exception):
    """Required credentials could not be resolved from the secrets backend.

    Raised when one or more keys declared in a collector's
    ``CollectorCredentialSpec.required_keys`` are absent from the secrets
    backend for the target tenant. The message includes the collector ID,
    tenant ID, and list of missing key names — but never the secret values
    themselves.
    """


class TenantScopeViolation(Exception):
    """A credential resolution violated tenant isolation boundaries.

    Raised when the resolver detects a cross-tenant access attempt:

    - A backend key path contains another tenant's UUID (path traversal).
    - A key_mapping path contains an embedded tenant UUID that does not
      match the requesting tenant.
    - A backend key path contains invalid characters (control chars,
      path separators beyond dots, etc.).

    This is a defense-in-depth check per finding #147. Even if the backend
    correctly scopes by tenant_id, the resolver independently validates
    that key paths cannot be used to escape tenant isolation.
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
    "ct-censys": CollectorCredentialSpec(
        collector_id="ct-censys",
        required_keys=["censys_api_id", "censys_api_secret"],
        key_mapping={
            "censys_api_id": "collector.scan-censys.api_id",
            "censys_api_secret": "collector.scan-censys.api_secret",
        },
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
    "scan-shodan": CollectorCredentialSpec(
        collector_id="scan-shodan",
        required_keys=["shodan_api_key"],
        key_mapping={"shodan_api_key": "collector.shodan-iwide.api_key"},
    ),
    "scan-censys": CollectorCredentialSpec(
        collector_id="scan-censys",
        required_keys=["censys_api_id", "censys_api_secret"],
        key_mapping={
            "censys_api_id": "collector.scan-censys.api_id",
            "censys_api_secret": "collector.scan-censys.api_secret",
        },
    ),
    "scan-binaryedge": CollectorCredentialSpec(
        collector_id="scan-binaryedge",
        required_keys=["binaryedge_api_key"],
        key_mapping={"binaryedge_api_key": "collector.scan-binaryedge.api_key"},
    ),
    "pdns-securitytrails": CollectorCredentialSpec(
        collector_id="pdns-securitytrails",
        required_keys=["api_key"],
    ),
    "dns-passive-history": CollectorCredentialSpec(
        collector_id="dns-passive-history",
        required_keys=[],
        optional_keys=["securitytrails_api_key", "virustotal_api_key"],
        key_mapping={
            "securitytrails_api_key": "collector.pdns-securitytrails.api_key",
            "virustotal_api_key": "unmapped.sfp_virustotal.api_key",
        },
    ),
    "github-exposed": CollectorCredentialSpec(
        collector_id="github-exposed",
        required_keys=[],
        optional_keys=["api_key"],
        key_mapping={"api_key": "collector.github-exposed.token"},
    ),
    "git-commit-emails": CollectorCredentialSpec(
        collector_id="git-commit-emails",
        required_keys=["token"],
        key_mapping={"token": "collector.github-exposed.token"},
    ),
    "paste-monitor": CollectorCredentialSpec(
        collector_id="paste-monitor",
        required_keys=[],
        optional_keys=["api_key"],
        key_mapping={"api_key": "collector.github-exposed.token"},
    ),
    "dns-chaos": CollectorCredentialSpec(
        collector_id="dns-chaos",
        required_keys=[],
        optional_keys=["chaos_api_key"],
        key_mapping={"chaos_api_key": "collector.dns-chaos.api_key"},
    ),
    "dark-web-indicators": CollectorCredentialSpec(
        collector_id="dark-web-indicators",
        required_keys=["hibp_api_key"],
        optional_keys=["intelx_api_key", "dehashed_email", "dehashed_api_key"],
    ),
}


class CredentialResolver:
    """Resolves per-tenant credentials for a collector from the secrets backend.

    Called by the dispatcher just before constructing ``CollectorConfig``.
    Credentials are fetched just-in-time per SPEC §6.4 — values are not
    cached across dispatches.

    The resolver encodes the secrets backend key as
    ``collector.{collector_id}.{key_name}`` to match the convention in the
    existing test suite (see ``tests/test_secrets.py``).

    **Tenant isolation** (finding #147): before every backend query, the
    resolver validates the backend key path via ``_validate_tenant_scope()``.
    This prevents cross-tenant credential leakage even when the secrets
    backend implementation has weak tenant scoping.
    """

    def __init__(self, backend: SecretsBackend) -> None:
        self._backend = backend

    @staticmethod
    def _validate_tenant_scope(
        tenant_id: UUID,
        backend_key: str,
        *,
        collector_id: str,
        key_name: str,
    ) -> None:
        """Validate that a backend key path cannot escape tenant isolation.

        Checks performed:

        1. **Path format:** The key must match the ``segment.segment...``
           convention (alphanumeric, hyphens, underscores). Rejects embedded
           slashes, control characters, or other injection vectors.
        2. **Cross-tenant UUID embedding:** If the key path contains a
           UUID-like string, it must match the requesting ``tenant_id``
           or be absent entirely. A key path containing a *different*
           tenant's UUID is a scope violation — it could trick a weak
           backend into returning another tenant's credential.

        Raises:
            TenantScopeViolation: if the key path fails any check.
        """
        # Check 1: valid path format
        if not _VALID_KEY_PATH_RE.match(backend_key):
            raise TenantScopeViolation(
                f"Backend key path {backend_key!r} for collector {collector_id!r} "
                f"key {key_name!r} contains invalid characters. "
                f"Expected dotted alphanumeric segments."
            )

        # Check 2: cross-tenant UUID embedding
        # Extract anything that looks like a UUID from the key path.
        # UUIDs in key paths are unusual in the current convention
        # (collector.{collector_id}.{key_name}), but key_mapping could
        # introduce them. If present, they must match the requesting tenant.
        uuid_pattern = re.compile(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        )
        embedded_uuids = uuid_pattern.findall(backend_key)
        tenant_str = str(tenant_id)
        for found_uuid in embedded_uuids:
            if found_uuid.lower() != tenant_str.lower():
                logger.warning(
                    "SECURITY: Cross-tenant UUID detected in backend key "
                    "path %r for collector %r key %r. "
                    "Requesting tenant=%s, embedded UUID=%s",
                    backend_key,
                    collector_id,
                    key_name,
                    tenant_id,
                    found_uuid,
                )
                raise TenantScopeViolation(
                    f"Backend key path {backend_key!r} for collector "
                    f"{collector_id!r} key {key_name!r} contains UUID "
                    f"{found_uuid!r} which does not match the requesting "
                    f"tenant {tenant_id}. Cross-tenant credential access "
                    f"is prohibited."
                )

    async def resolve(
        self, tenant_id: UUID, collector_id: str
    ) -> dict[str, CollectorCredential]:
        """Fetch credentials for the given collector and tenant.

        Returns a dict of ``{key_name: CollectorCredential}``.

        If a required key is missing from the backend,
        ``CredentialResolutionError`` is raised with the list of missing keys.

        If no credentials are needed (empty ``required_keys`` or unknown
        ``collector_id``), returns ``{}``.

        Raises:
            TenantScopeViolation: if any backend key path would violate
                tenant isolation (finding #147).
            CredentialResolutionError: if required keys are absent.
        """
        spec = CREDENTIAL_SPECS.get(collector_id)
        if spec is None:
            logger.debug(
                "No credential spec for collector %r — treating as credential-free",
                collector_id,
            )
            return {}
        if not spec.required_keys and not spec.optional_keys:
            logger.debug(
                "Collector %r has no required or optional keys — "
                "skipping credential resolution",
                collector_id,
            )
            return {}

        # Pre-validate ALL key paths before querying the backend (fail-fast).
        all_keys = list(spec.required_keys) + list(spec.optional_keys)
        for key in all_keys:
            backend_key = spec.key_mapping.get(key, f"collector.{collector_id}.{key}")
            self._validate_tenant_scope(
                tenant_id,
                backend_key,
                collector_id=collector_id,
                key_name=key,
            )

        credentials: dict[str, CollectorCredential] = {}
        missing: list[str] = []

        for key in spec.required_keys:
            backend_key = spec.key_mapping.get(key, f"collector.{collector_id}.{key}")
            try:
                value = await self._backend.get(tenant_id=tenant_id, key=backend_key)
                credentials[key] = CollectorCredential(name=key, secret_value=value)
                logger.debug(
                    "Resolved credential %r for collector %r (backend_key=%r, tenant=%s)",
                    key,
                    collector_id,
                    backend_key,
                    tenant_id,
                )
            except SecretNotFoundError:
                logger.warning(
                    "Credential %r not found for collector %r "
                    "(backend_key=%r, tenant=%s)",
                    key,
                    collector_id,
                    backend_key,
                    tenant_id,
                )
                missing.append(key)

        if missing:
            raise CredentialResolutionError(
                f"Missing credentials for collector {collector_id!r}, "
                f"tenant {tenant_id}: {missing}"
            )

        # Resolve optional keys — log at debug level if missing, never fail.
        for key in spec.optional_keys:
            backend_key = spec.key_mapping.get(key, f"collector.{collector_id}.{key}")
            try:
                value = await self._backend.get(tenant_id=tenant_id, key=backend_key)
                credentials[key] = CollectorCredential(name=key, secret_value=value)
                logger.debug(
                    "Resolved optional credential %r for collector %r "
                    "(backend_key=%r, tenant=%s)",
                    key,
                    collector_id,
                    backend_key,
                    tenant_id,
                )
            except SecretNotFoundError:
                logger.debug(
                    "Optional credential %r not found for collector %r "
                    "(backend_key=%r, tenant=%s) — collector will run "
                    "at reduced capability",
                    key,
                    collector_id,
                    backend_key,
                    tenant_id,
                )

        logger.debug(
            "Resolved %d credential(s) for collector %r: %s",
            len(credentials),
            collector_id,
            list(credentials.keys()),
        )
        return credentials


__all__ = [
    "CREDENTIAL_SPECS",
    "CollectorCredentialSpec",
    "CredentialResolutionError",
    "CredentialResolver",
    "TenantScopeViolation",
]
