"""FastAPI router for tenant configuration CRUD operations.

Implements per-tenant configuration management:

* **Get**    -- ``GET   /v1/tenants/{tenant_id}/config`` -> 200
* **Replace** -- ``PUT   /v1/tenants/{tenant_id}/config`` -> 200
* **Patch**  -- ``PATCH /v1/tenants/{tenant_id}/config`` -> 200

Configuration covers scope rules, collector selection, scheduling,
egress profile, and LLM enrichment settings.  State is stored in-memory
(module-level dict) for Phase 1; database persistence lands in Phase 3.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Valid option sets
# ---------------------------------------------------------------------------

VALID_EGRESS_PROFILES: frozenset[str] = frozenset(
    {"direct", "socks5", "wireguard", "http_connect"}
)

VALID_SCOPE_RULE_TYPES: frozenset[str] = frozenset(
    {
        "apex_domain",
        "exact_domain",
        "ip_address",
        "cidr",
        "asn",
        "cloud_account",
        "registrant_org",
    }
)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ScopeRuleConfig(BaseModel):
    """A single scope rule within a tenant's configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_type: str
    value: str
    is_exclusion: bool = False


class TenantConfigResponse(BaseModel):
    """Full tenant configuration returned by all config endpoints."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    scope_rules: list[ScopeRuleConfig]
    enabled_collectors: list[str]
    schedule_cron: str | None
    egress_profile: str
    llm_enabled: bool
    llm_provider: str | None
    llm_cost_ceiling_per_run: float
    updated_at: datetime
    updated_by: str | None


class TenantConfigUpdate(BaseModel):
    """Body for ``PUT`` and ``PATCH`` on tenant config.

    All fields are optional for PATCH semantics.  For PUT, the caller is
    expected to supply all fields (missing fields reset to defaults).
    """

    model_config = ConfigDict(extra="forbid")

    scope_rules: list[ScopeRuleConfig] | None = None
    enabled_collectors: list[str] | None = None
    schedule_cron: str | None = None
    egress_profile: str | None = None
    llm_enabled: bool | None = None
    llm_provider: str | None = None
    llm_cost_ceiling_per_run: float | None = None


# ---------------------------------------------------------------------------
# In-memory config store (Phase 1 -- replaced by DB in Phase 3)
# ---------------------------------------------------------------------------

_configs: dict[UUID, dict[str, object]] = {}


def _default_config(tenant_id: UUID) -> dict[str, object]:
    """Return sensible defaults for a tenant that has no stored config."""
    return {
        "tenant_id": tenant_id,
        "scope_rules": [],
        "enabled_collectors": [],
        "schedule_cron": None,
        "egress_profile": "direct",
        "llm_enabled": False,
        "llm_provider": None,
        "llm_cost_ceiling_per_run": 0.0,
        "updated_at": datetime.now(UTC),
        "updated_by": None,
    }


def _to_response(cfg: dict[str, object]) -> TenantConfigResponse:
    """Build a frozen response model from the internal dict."""
    return TenantConfigResponse.model_validate(cfg)


def _validate_scope_rules(rules: list[ScopeRuleConfig]) -> None:
    """Raise ``HTTPException(422)`` if any rule has an invalid ``rule_type``."""
    for rule in rules:
        if rule.rule_type not in VALID_SCOPE_RULE_TYPES:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Invalid scope rule type: {rule.rule_type!r}. "
                    f"Must be one of {sorted(VALID_SCOPE_RULE_TYPES)}."
                ),
            )


def _validate_egress_profile(profile: str) -> None:
    """Raise ``HTTPException(422)`` if the egress profile is not recognised."""
    if profile not in VALID_EGRESS_PROFILES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Invalid egress profile: {profile!r}. "
                f"Must be one of {sorted(VALID_EGRESS_PROFILES)}."
            ),
        )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/v1/tenants/{tenant_id}/config",
    tags=["tenant-config"],
)


@router.get("/", response_model=TenantConfigResponse)
async def get_tenant_config(
    tenant_id: UUID,
) -> TenantConfigResponse:
    """Return the current configuration for a tenant.

    If no configuration has been set, sensible defaults are returned.
    """
    cfg = _configs.get(tenant_id, _default_config(tenant_id))
    return _to_response(cfg)


@router.put("/", response_model=TenantConfigResponse)
async def replace_tenant_config(
    tenant_id: UUID,
    body: TenantConfigUpdate,
) -> TenantConfigResponse:
    """Replace the entire tenant configuration.

    Fields not supplied in the body are reset to their defaults.
    """
    defaults = _default_config(tenant_id)

    # Build the replacement config from body, falling back to defaults.
    new_cfg: dict[str, object] = dict(defaults)

    if body.scope_rules is not None:
        _validate_scope_rules(body.scope_rules)
        new_cfg["scope_rules"] = [r.model_dump() for r in body.scope_rules]
    if body.enabled_collectors is not None:
        new_cfg["enabled_collectors"] = body.enabled_collectors
    if body.schedule_cron is not None:
        new_cfg["schedule_cron"] = body.schedule_cron
    if body.egress_profile is not None:
        _validate_egress_profile(body.egress_profile)
        new_cfg["egress_profile"] = body.egress_profile
    if body.llm_enabled is not None:
        new_cfg["llm_enabled"] = body.llm_enabled
    if body.llm_provider is not None:
        new_cfg["llm_provider"] = body.llm_provider
    if body.llm_cost_ceiling_per_run is not None:
        new_cfg["llm_cost_ceiling_per_run"] = body.llm_cost_ceiling_per_run

    now = datetime.now(UTC)
    new_cfg["updated_at"] = now
    new_cfg["updated_by"] = "api"

    _configs[tenant_id] = new_cfg

    changed_fields = [
        f for f in TenantConfigUpdate.model_fields if getattr(body, f) is not None
    ]
    logger.warning(
        "Tenant config REPLACED: tenant_id=%s changed_fields=%s timestamp=%s",
        tenant_id,
        changed_fields,
        now.isoformat(),
    )

    return _to_response(new_cfg)


@router.patch("/", response_model=TenantConfigResponse)
async def patch_tenant_config(
    tenant_id: UUID,
    body: TenantConfigUpdate,
) -> TenantConfigResponse:
    """Partially update the tenant configuration.

    Only fields present in the request body are modified; all others
    are preserved from the existing configuration (or defaults if no
    configuration exists yet).
    """
    existing = _configs.get(tenant_id, _default_config(tenant_id))
    merged: dict[str, object] = dict(existing)

    if body.scope_rules is not None:
        _validate_scope_rules(body.scope_rules)
        merged["scope_rules"] = [r.model_dump() for r in body.scope_rules]
    if body.enabled_collectors is not None:
        merged["enabled_collectors"] = body.enabled_collectors
    if body.schedule_cron is not None:
        merged["schedule_cron"] = body.schedule_cron
    if body.egress_profile is not None:
        _validate_egress_profile(body.egress_profile)
        merged["egress_profile"] = body.egress_profile
    if body.llm_enabled is not None:
        merged["llm_enabled"] = body.llm_enabled
    if body.llm_provider is not None:
        merged["llm_provider"] = body.llm_provider
    if body.llm_cost_ceiling_per_run is not None:
        merged["llm_cost_ceiling_per_run"] = body.llm_cost_ceiling_per_run

    now = datetime.now(UTC)
    merged["updated_at"] = now
    merged["updated_by"] = "api"

    _configs[tenant_id] = merged

    changed_fields = [
        f for f in TenantConfigUpdate.model_fields if getattr(body, f) is not None
    ]
    logger.warning(
        "Tenant config PATCHED: tenant_id=%s changed_fields=%s timestamp=%s",
        tenant_id,
        changed_fields,
        now.isoformat(),
    )

    return _to_response(merged)
