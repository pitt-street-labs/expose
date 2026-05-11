"""FastAPI router for per-tenant credential management.

Provides CRUD-style operations on credential "slots" — the named API keys
and tokens that EXPOSE collectors consume. Each slot has a well-known ID
(e.g., ``shodan_api_key``) and maps to one or more collector IDs that
depend on it.

Endpoints:

* **List**              — ``GET    /v1/tenants/{tenant_id}/credentials/``
* **Import SpiderFoot** — ``POST   /v1/tenants/{tenant_id}/credentials/import/spiderfoot``
* **Import Bundle**     — ``POST   /v1/tenants/{tenant_id}/credentials/import/bundle``
* **Export Bundle**     — ``GET    /v1/tenants/{tenant_id}/credentials/export/bundle``
* **Test Credential**   — ``POST   /v1/tenants/{tenant_id}/credentials/{credential_id}/test``

State is stored through the :class:`expose.secrets.SecretsBackend` ABC.
Phase 1 uses :class:`InMemoryBackend`; production deployments wire Vault
or cloud-KMS implementations.

Security:

- No secret values are logged at any level.
- Export masks values by default (last 4 chars visible).
- The module-level ``_backend`` is a placeholder; the orchestrator replaces
  it at startup via dependency injection (see ``app.py`` pattern).
"""

from __future__ import annotations

import logging
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from expose.collectors.base import CollectorConfig, CollectorCredential
from expose.collectors.registry import DEFAULT_REGISTRY
from expose.import_.credential_bundle import (
    export_bundle,
    mask_value,
)
from expose.secrets.backend import SecretNotFoundError, SecretsBackend
from expose.secrets.memory_backend import GLOBAL_TENANT_ID, InMemoryBackend, _DEFAULT_PERSIST_PATH

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level backend (Phase 1: in-memory; orchestrator replaces at startup)
# ---------------------------------------------------------------------------
_backend: SecretsBackend = InMemoryBackend(persist_path=_DEFAULT_PERSIST_PATH)


def set_backend(backend: SecretsBackend) -> None:
    """Replace the module-level secrets backend (called by orchestrator)."""
    global _backend  # noqa: PLW0603
    _backend = backend


# ---------------------------------------------------------------------------
# Known credential slots
# ---------------------------------------------------------------------------


class _SlotDef:
    """Internal definition of a known credential slot."""

    __slots__ = ("backend_key", "collector_ids", "credential_id", "display_name")

    def __init__(
        self,
        credential_id: str,
        display_name: str,
        collector_ids: list[str],
        backend_key: str,
    ) -> None:
        self.credential_id = credential_id
        self.display_name = display_name
        self.collector_ids = collector_ids
        self.backend_key = backend_key


# Registry of all known credential slots. The ``backend_key`` follows the
# ``collector.<collector_id>.<key_name>`` convention from credential_resolver.py
# for mapped collectors, and ``unmapped.<source>.<key_name>`` for future/unmapped
# slots.
KNOWN_SLOTS: list[_SlotDef] = [
    _SlotDef(
        credential_id="shodan_api_key",
        display_name="Shodan API Key",
        collector_ids=["shodan-iwide"],
        backend_key="collector.shodan-iwide.api_key",
    ),
    _SlotDef(
        credential_id="securitytrails_api_key",
        display_name="SecurityTrails API Key",
        collector_ids=["pdns-securitytrails"],
        backend_key="collector.pdns-securitytrails.api_key",
    ),
    _SlotDef(
        credential_id="virustotal_api_key",
        display_name="VirusTotal API Key",
        collector_ids=["dns-passive-history"],
        backend_key="unmapped.sfp_virustotal.api_key",
    ),
    _SlotDef(
        credential_id="censys_api_id",
        display_name="Censys API ID",
        collector_ids=["scan-censys"],
        backend_key="collector.scan-censys.api_id",
    ),
    _SlotDef(
        credential_id="censys_api_secret",
        display_name="Censys API Secret",
        collector_ids=["scan-censys"],
        backend_key="collector.scan-censys.api_secret",
    ),
    _SlotDef(
        credential_id="binaryedge_api_key",
        display_name="BinaryEdge API Key",
        collector_ids=["scan-binaryedge"],
        backend_key="collector.scan-binaryedge.api_key",
    ),
    _SlotDef(
        credential_id="github_token",
        display_name="GitHub Token",
        collector_ids=["github-exposed"],
        backend_key="collector.github-exposed.token",
    ),
    _SlotDef(
        credential_id="passivetotal_api_key",
        display_name="PassiveTotal API Key",
        collector_ids=["pdns-passivetotal"],
        backend_key="collector.pdns-passivetotal.api_key",
    ),
    _SlotDef(
        credential_id="greynoise_api_key",
        display_name="GreyNoise API Key",
        collector_ids=[],
        backend_key="unmapped.sfp_greynoise.api_key",
    ),
    _SlotDef(
        credential_id="urlscan_api_key",
        display_name="urlscan.io API Key",
        collector_ids=[],
        backend_key="unmapped.sfp_urlscan.api_key",
    ),
    _SlotDef(
        credential_id="chaos_api_key",
        display_name="ProjectDiscovery Chaos API Key",
        collector_ids=["dns-chaos"],
        backend_key="collector.dns-chaos.api_key",
    ),
    _SlotDef(
        credential_id="hibp_api_key",
        display_name="Have I Been Pwned API Key",
        collector_ids=["dark-web-indicators"],
        backend_key="collector.dark-web-indicators.hibp_api_key",
    ),
    _SlotDef(
        credential_id="intelx_api_key",
        display_name="Intelligence X API Key",
        collector_ids=["dark-web-indicators"],
        backend_key="collector.dark-web-indicators.intelx_api_key",
    ),
    _SlotDef(
        credential_id="dehashed_email",
        display_name="DeHashed Account Email",
        collector_ids=["dark-web-indicators"],
        backend_key="collector.dark-web-indicators.dehashed_email",
    ),
    _SlotDef(
        credential_id="dehashed_api_key",
        display_name="DeHashed API Key",
        collector_ids=["dark-web-indicators"],
        backend_key="collector.dark-web-indicators.dehashed_api_key",
    ),
]

# Lookup tables for fast access
_SLOTS_BY_ID: dict[str, _SlotDef] = {s.credential_id: s for s in KNOWN_SLOTS}
_SLOTS_BY_BACKEND_KEY: dict[str, _SlotDef] = {s.backend_key: s for s in KNOWN_SLOTS}


# ---------------------------------------------------------------------------
# SpiderFoot backend-key to credential-slot-id mapping
# ---------------------------------------------------------------------------
# The SpiderFoot importer writes keys like ``collector.shodan-iwide.api_key``
# or ``unmapped.sfp_virustotal.api_key``. This mapping translates those
# backend keys back to our credential_id namespace.
_SF_BACKEND_KEY_TO_SLOT: dict[str, str] = {
    slot.backend_key: slot.credential_id for slot in KNOWN_SLOTS
}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CredentialSlot(BaseModel):
    """Status of a single credential slot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    credential_id: str
    display_name: str
    collector_ids: list[str]
    status: str  # "configured", "missing", "expired"
    masked_value: str | None  # "****abcd" or None if missing
    source: str = "tenant"  # "tenant" or "global"


class CredentialStatusResponse(BaseModel):
    """Response for the list-credentials endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    slots: list[CredentialSlot]
    configured_count: int
    total_count: int


class ImportResult(BaseModel):
    """Result of a credential import operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    imported_count: int
    skipped_count: int
    errors: list[str]
    slot_names: list[str]


class SpiderFootImportRequest(BaseModel):
    """Request body for SpiderFoot credential import.

    Accepts a dictionary of SpiderFoot-style key-value pairs, where keys
    follow the ``scope.opt`` convention (e.g., ``sfp_shodan.api_key``).
    """

    model_config = ConfigDict(extra="forbid")

    credentials: dict[str, str]


class BundleImportRequest(BaseModel):
    """Request body for native bundle import."""

    model_config = ConfigDict(extra="forbid")

    format_version: str = "1.0"
    credentials: dict[str, str]


class BundleExportResponse(BaseModel):
    """Response for the export-bundle endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: str
    exported_at: str
    credentials: dict[str, str]


class CredentialTestResult(BaseModel):
    """Result of testing a single credential."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    credential_id: str
    status: str  # "ok", "failed", "not_configured", "no_test_available"
    message: str


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/v1/tenants/{tenant_id}/credentials",
    tags=["credentials"],
)


global_router = APIRouter(
    prefix="/v1/credentials/global",
    tags=["credentials"],
)


@router.get("/", response_model=CredentialStatusResponse)
async def list_credentials(tenant_id: UUID) -> CredentialStatusResponse:
    """List all credential slots with their current status.

    Returns every known credential slot with a status indicator:
    ``configured`` if a value exists in the backend, ``missing`` otherwise.
    Configured slots include a masked representation of the stored value.
    """
    slots: list[CredentialSlot] = []
    configured_count = 0
    global_tid = UUID(GLOBAL_TENANT_ID)

    for slot_def in KNOWN_SLOTS:
        # Check tenant-specific first
        try:
            value = await _backend.get(tenant_id=tenant_id, key=slot_def.backend_key)
            # Determine source: did we find it under this tenant or via global fallback?
            # Check if the tenant has its own copy by directly inspecting the store
            # (the get() method falls back to global automatically).
            source = "tenant"
            if hasattr(_backend, "_store"):
                tid_str = str(tenant_id)
                if (tid_str, slot_def.backend_key) not in _backend._store:
                    source = "global"
            slots.append(
                CredentialSlot(
                    credential_id=slot_def.credential_id,
                    display_name=slot_def.display_name,
                    collector_ids=slot_def.collector_ids,
                    status="configured",
                    masked_value=mask_value(value),
                    source=source,
                )
            )
            configured_count += 1
        except SecretNotFoundError:
            slots.append(
                CredentialSlot(
                    credential_id=slot_def.credential_id,
                    display_name=slot_def.display_name,
                    collector_ids=slot_def.collector_ids,
                    status="missing",
                    masked_value=None,
                    source="tenant",
                )
            )

    return CredentialStatusResponse(
        tenant_id=tenant_id,
        slots=slots,
        configured_count=configured_count,
        total_count=len(KNOWN_SLOTS),
    )


@router.post("/import/spiderfoot", response_model=ImportResult)
async def import_spiderfoot(
    tenant_id: UUID, body: SpiderFootImportRequest
) -> ImportResult:
    """Import credentials from SpiderFoot-style key-value pairs.

    Accepts a flat dictionary where keys follow the SpiderFoot convention
    (``sfp_<module>.<opt>``). Each key is looked up against the known
    SpiderFoot module map to determine the corresponding EXPOSE credential
    slot. Unrecognized keys are skipped with an error message.
    """
    imported_count = 0
    skipped_count = 0
    errors: list[str] = []
    slot_names: list[str] = []

    # Build a reverse map: "sfp_<module>.<opt>" -> backend_key
    from expose.import_.spiderfoot import SPIDERFOOT_MODULE_MAP  # noqa: PLC0415

    for sf_key, value in body.credentials.items():
        if not value or not value.strip():
            skipped_count += 1
            errors.append(f"Empty value for key {sf_key!r}")
            continue

        # Parse the SpiderFoot key format: "sfp_<module>.<opt>" or just "sfp_<module>"
        parts = sf_key.split(".", 1)
        sf_module = parts[0]
        sf_opt = parts[1] if len(parts) > 1 else "api_key"

        # Look up the module in the SpiderFoot map
        collector_id = SPIDERFOOT_MODULE_MAP.get(sf_module)

        # Build the backend key following the same convention as SpiderFootImporter
        if collector_id is not None:
            backend_key = f"collector.{collector_id}.{sf_opt}"
        else:
            backend_key = f"unmapped.{sf_module}.{sf_opt}"

        # Check if this backend key maps to a known slot
        slot_def = _SLOTS_BY_BACKEND_KEY.get(backend_key)
        if slot_def is not None:
            await _backend.set(tenant_id=tenant_id, key=backend_key, value=value.strip())
            imported_count += 1
            slot_names.append(slot_def.credential_id)
            logger.info(
                "credential_imported_spiderfoot",
                extra={
                    "tenant_id": str(tenant_id),
                    "credential_id": slot_def.credential_id,
                    "sf_module": sf_module,
                    "value": "<redacted>",
                },
            )
        else:
            # Store under the unmapped key anyway — operator may need it later
            await _backend.set(tenant_id=tenant_id, key=backend_key, value=value.strip())
            imported_count += 1
            slot_names.append(backend_key)
            logger.info(
                "credential_imported_spiderfoot_unmapped",
                extra={
                    "tenant_id": str(tenant_id),
                    "backend_key": backend_key,
                    "sf_module": sf_module,
                    "value": "<redacted>",
                },
            )

    return ImportResult(
        imported_count=imported_count,
        skipped_count=skipped_count,
        errors=errors,
        slot_names=slot_names,
    )


@router.post("/import/bundle", response_model=ImportResult)
async def import_bundle_endpoint(
    tenant_id: UUID, body: BundleImportRequest
) -> ImportResult:
    """Import credentials from a native JSON bundle.

    Accepts credential slot IDs as keys (e.g., ``shodan_api_key``) mapped
    to their plaintext values. Only recognized slot IDs are imported;
    unknown keys are skipped with an error message.
    """
    imported_count = 0
    skipped_count = 0
    errors: list[str] = []
    slot_names: list[str] = []

    for slot_id, value in body.credentials.items():
        if not value or not value.strip():
            skipped_count += 1
            errors.append(f"Empty value for slot {slot_id!r}")
            continue

        # Check if the slot_id is a known credential slot
        slot_def = _SLOTS_BY_ID.get(slot_id)
        if slot_def is None:
            skipped_count += 1
            errors.append(f"Unknown credential slot: {slot_id!r}")
            continue

        # Reject masked values — they would overwrite real credentials
        if value.startswith("****"):
            skipped_count += 1
            errors.append(f"Masked value for slot {slot_id!r} — cannot import masked credentials")
            continue

        await _backend.set(
            tenant_id=tenant_id,
            key=slot_def.backend_key,
            value=value.strip(),
        )
        imported_count += 1
        slot_names.append(slot_id)

        logger.info(
            "credential_imported_bundle",
            extra={
                "tenant_id": str(tenant_id),
                "credential_id": slot_id,
                "value": "<redacted>",
            },
        )

    return ImportResult(
        imported_count=imported_count,
        skipped_count=skipped_count,
        errors=errors,
        slot_names=slot_names,
    )


@router.get("/export/bundle", response_model=BundleExportResponse)
async def export_bundle_endpoint(tenant_id: UUID) -> BundleExportResponse:
    """Export configured credentials as a JSON bundle with masked values.

    Only credential slots that have values stored in the backend are
    included. Values are masked (last 4 chars visible) — this endpoint
    is for verification, not backup. A full-value export would require
    a separate privileged endpoint (future).
    """
    secrets: dict[str, str] = {}

    for slot_def in KNOWN_SLOTS:
        try:
            value = await _backend.get(tenant_id=tenant_id, key=slot_def.backend_key)
            secrets[slot_def.credential_id] = value
        except SecretNotFoundError:
            continue

    bundle = export_bundle(secrets, mask=True)

    return BundleExportResponse(
        format_version=bundle.format_version,
        exported_at=bundle.exported_at.isoformat(),
        credentials=bundle.credentials,
    )


@router.post("/{credential_id}/test", response_model=CredentialTestResult)
async def test_credential(tenant_id: UUID, credential_id: str) -> CredentialTestResult:
    """Test a credential by running the associated collector's health check.

    Instantiates the first registered collector that uses this credential
    and calls its ``health_check()`` method, which probes the upstream API
    for reachability and key validity.  Falls back to a presence check if
    no collector is registered for the slot.
    """
    slot_def = _SLOTS_BY_ID.get(credential_id)
    if slot_def is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown credential slot: {credential_id!r}",
        )

    try:
        value = await _backend.get(tenant_id=tenant_id, key=slot_def.backend_key)
    except SecretNotFoundError:
        return CredentialTestResult(
            credential_id=credential_id,
            status="not_configured",
            message=f"No value stored for {slot_def.display_name}.",
        )

    if not value.strip():
        return CredentialTestResult(
            credential_id=credential_id,
            status="failed",
            message=f"{slot_def.display_name} is stored but empty.",
        )

    if not slot_def.collector_ids:
        return CredentialTestResult(
            credential_id=credential_id,
            status="ok",
            message=f"{slot_def.display_name} is configured (no collector mapped for live test).",
        )

    collector_id = slot_def.collector_ids[0]
    if not DEFAULT_REGISTRY.is_registered(collector_id):
        return CredentialTestResult(
            credential_id=credential_id,
            status="ok",
            message=f"{slot_def.display_name} is configured (collector {collector_id!r} not loaded).",
        )

    cred_key = slot_def.backend_key.rsplit(".", 1)[-1]
    config = CollectorConfig(
        tenant_id=tenant_id,
        run_id=uuid4(),
        request_timeout_seconds=15.0,
        credentials={
            cred_key: CollectorCredential(name=cred_key, secret_value=value),
        },
    )

    try:
        collector_cls = DEFAULT_REGISTRY.get(collector_id)
        collector = collector_cls(config)
        result = await collector.health_check()
    except Exception as exc:
        logger.warning("Health check failed for %s: %s", credential_id, exc)
        return CredentialTestResult(
            credential_id=credential_id,
            status="failed",
            message=f"{slot_def.display_name} health check error: {exc}",
        )

    if result.status.value == "success":
        latency = f" ({result.latency_ms:.0f}ms)" if result.latency_ms else ""
        return CredentialTestResult(
            credential_id=credential_id,
            status="ok",
            message=f"{slot_def.display_name} — upstream healthy{latency}",
        )

    return CredentialTestResult(
        credential_id=credential_id,
        status="failed",
        message=f"{slot_def.display_name} — {result.error_message or 'upstream unreachable'}",
    )


# ---------------------------------------------------------------------------
# Global credential endpoints — shared across all tenants
# ---------------------------------------------------------------------------

_GLOBAL_UUID = UUID(GLOBAL_TENANT_ID)


@global_router.get("/", response_model=CredentialStatusResponse)
async def list_global_credentials() -> CredentialStatusResponse:
    """List all global credential slots with their current status.

    Global credentials serve as defaults for tenants that have not
    configured their own keys.
    """
    slots: list[CredentialSlot] = []
    configured_count = 0

    for slot_def in KNOWN_SLOTS:
        # Directly check the global tenant — no fallback needed here.
        if hasattr(_backend, "_store"):
            key_present = (GLOBAL_TENANT_ID, slot_def.backend_key) in _backend._store
        else:
            try:
                await _backend.get(tenant_id=_GLOBAL_UUID, key=slot_def.backend_key)
                key_present = True
            except SecretNotFoundError:
                key_present = False

        if key_present:
            value = _backend._store[(GLOBAL_TENANT_ID, slot_def.backend_key)] if hasattr(_backend, "_store") else await _backend.get(tenant_id=_GLOBAL_UUID, key=slot_def.backend_key)
            slots.append(
                CredentialSlot(
                    credential_id=slot_def.credential_id,
                    display_name=slot_def.display_name,
                    collector_ids=slot_def.collector_ids,
                    status="configured",
                    masked_value=mask_value(value),
                    source="global",
                )
            )
            configured_count += 1
        else:
            slots.append(
                CredentialSlot(
                    credential_id=slot_def.credential_id,
                    display_name=slot_def.display_name,
                    collector_ids=slot_def.collector_ids,
                    status="missing",
                    masked_value=None,
                    source="global",
                )
            )

    return CredentialStatusResponse(
        tenant_id=_GLOBAL_UUID,
        slots=slots,
        configured_count=configured_count,
        total_count=len(KNOWN_SLOTS),
    )


@global_router.post("/import/bundle", response_model=ImportResult)
async def import_global_bundle(body: BundleImportRequest) -> ImportResult:
    """Import credentials as global keys (shared across all tenants).

    Same format as the per-tenant bundle import but stores keys under
    the global tenant ID. These keys automatically apply to any tenant
    that has not configured its own value for the same slot.
    """
    imported_count = 0
    skipped_count = 0
    errors: list[str] = []
    slot_names: list[str] = []

    for slot_id, value in body.credentials.items():
        if not value or not value.strip():
            skipped_count += 1
            errors.append(f"Empty value for slot {slot_id!r}")
            continue

        slot_def = _SLOTS_BY_ID.get(slot_id)
        if slot_def is None:
            skipped_count += 1
            errors.append(f"Unknown credential slot: {slot_id!r}")
            continue

        if value.startswith("****"):
            skipped_count += 1
            errors.append(f"Masked value for slot {slot_id!r} — cannot import masked credentials")
            continue

        await _backend.set(
            tenant_id=_GLOBAL_UUID,
            key=slot_def.backend_key,
            value=value.strip(),
        )
        imported_count += 1
        slot_names.append(slot_id)

        logger.info(
            "credential_imported_global_bundle",
            extra={
                "credential_id": slot_id,
                "value": "<redacted>",
            },
        )

    return ImportResult(
        imported_count=imported_count,
        skipped_count=skipped_count,
        errors=errors,
        slot_names=slot_names,
    )


@global_router.get("/export/bundle", response_model=BundleExportResponse)
async def export_global_bundle() -> BundleExportResponse:
    """Export global credentials as a JSON bundle with masked values."""
    secrets: dict[str, str] = {}

    for slot_def in KNOWN_SLOTS:
        if hasattr(_backend, "_store"):
            if (GLOBAL_TENANT_ID, slot_def.backend_key) in _backend._store:
                secrets[slot_def.credential_id] = _backend._store[(GLOBAL_TENANT_ID, slot_def.backend_key)]
        else:
            try:
                value = await _backend.get(tenant_id=_GLOBAL_UUID, key=slot_def.backend_key)
                secrets[slot_def.credential_id] = value
            except SecretNotFoundError:
                continue

    bundle = export_bundle(secrets, mask=True)

    return BundleExportResponse(
        format_version=bundle.format_version,
        exported_at=bundle.exported_at.isoformat(),
        credentials=bundle.credentials,
    )


__all__ = [
    "KNOWN_SLOTS",
    "BundleExportResponse",
    "BundleImportRequest",
    "CredentialSlot",
    "CredentialStatusResponse",
    "CredentialTestResult",
    "ImportResult",
    "SpiderFootImportRequest",
    "global_router",
    "router",
    "set_backend",
]
