"""FastAPI router for webhook configuration CRUD and test-delivery endpoint.

Implements per-tenant webhook management:

* **List**   -- ``GET    /v1/tenants/{tenant_id}/webhooks/``       -> 200
* **Create** -- ``POST   /v1/tenants/{tenant_id}/webhooks/``       -> 201
* **Delete** -- ``DELETE /v1/tenants/{tenant_id}/webhooks/{id}``   -> 204
* **Test**   -- ``POST   /v1/tenants/{tenant_id}/webhooks/{id}/test`` -> 200

Webhook state is stored in-memory (module-level dict) for Phase 1 — same
pattern as ``expose.api.tenant_config``. Database persistence lands in
Phase 3.

The router is intentionally *not* wired into ``app.py`` yet — it will be
mounted once the integration plan is approved.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from expose.pipeline.webhook_delivery import (
    WebhookConfig,
    WebhookDeliveryEngine,
    WebhookDeliveryResult,
)

__all__ = ["router"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class WebhookCreateRequest(BaseModel):
    """Body for ``POST /v1/tenants/{tenant_id}/webhooks/``."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1)
    secret: str = Field(min_length=16)
    event_types: frozenset[str] | None = None
    enabled: bool = True


class WebhookConfigResponse(BaseModel):
    """Webhook configuration returned by list / create endpoints."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    webhook_id: str
    tenant_id: UUID
    url: str
    event_types: frozenset[str] | None = None
    enabled: bool
    created_at: datetime


# ---------------------------------------------------------------------------
# In-memory store (Phase 1 -- replaced by DB in Phase 3)
# ---------------------------------------------------------------------------

# {tenant_id: {webhook_id: {config + metadata}}}
_webhooks: dict[UUID, dict[str, dict[str, object]]] = {}

logger.warning(
    "Webhook configuration is stored in-memory only (Phase 1). "
    "Configuration will be lost on process restart."
)


def _get_tenant_webhooks(tenant_id: UUID) -> dict[str, dict[str, object]]:
    """Return the webhook dict for a tenant, creating it lazily."""
    if tenant_id not in _webhooks:
        _webhooks[tenant_id] = {}
    return _webhooks[tenant_id]


def _to_response(record: dict[str, object]) -> WebhookConfigResponse:
    """Build a response model from the internal dict, excluding the secret."""
    safe = {k: v for k, v in record.items() if k != "secret"}
    return WebhookConfigResponse.model_validate(safe)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/v1/tenants/{tenant_id}/webhooks",
    tags=["webhooks"],
)


@router.get("/", response_model=list[WebhookConfigResponse])
async def list_webhooks(tenant_id: UUID) -> list[WebhookConfigResponse]:
    """Return all webhook configurations for a tenant."""
    tenant_hooks = _get_tenant_webhooks(tenant_id)
    return [_to_response(hook) for hook in tenant_hooks.values()]


@router.post("/", response_model=WebhookConfigResponse, status_code=201)
async def create_webhook(
    tenant_id: UUID,
    body: WebhookCreateRequest,
) -> WebhookConfigResponse:
    """Register a new webhook endpoint for a tenant."""
    webhook_id = str(uuid.uuid4())
    now = datetime.now(UTC)

    record: dict[str, object] = {
        "webhook_id": webhook_id,
        "tenant_id": tenant_id,
        "url": body.url,
        "secret": body.secret,
        "event_types": body.event_types,
        "enabled": body.enabled,
        "created_at": now,
    }

    tenant_hooks = _get_tenant_webhooks(tenant_id)
    tenant_hooks[webhook_id] = record

    logger.warning(
        "Webhook CREATED: tenant_id=%s webhook_id=%s url=%s timestamp=%s",
        tenant_id,
        webhook_id,
        body.url,
        now.isoformat(),
    )

    return _to_response(record)


@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(tenant_id: UUID, webhook_id: str) -> None:
    """Remove a webhook configuration."""
    tenant_hooks = _get_tenant_webhooks(tenant_id)
    if webhook_id not in tenant_hooks:
        raise HTTPException(status_code=404, detail="Webhook not found")

    del tenant_hooks[webhook_id]

    logger.warning(
        "Webhook DELETED: tenant_id=%s webhook_id=%s",
        tenant_id,
        webhook_id,
    )


@router.post("/{webhook_id}/test", response_model=WebhookDeliveryResult)
async def test_webhook(tenant_id: UUID, webhook_id: str) -> WebhookDeliveryResult:
    """Send a test event to verify webhook configuration.

    Delivers a synthetic ``webhook.test`` event to the configured URL and
    returns the delivery result (including success/failure, status code,
    and any error message).
    """
    tenant_hooks = _get_tenant_webhooks(tenant_id)
    if webhook_id not in tenant_hooks:
        raise HTTPException(status_code=404, detail="Webhook not found")

    record = tenant_hooks[webhook_id]
    config = WebhookConfig(
        url=str(record["url"]),
        secret=str(record["secret"]),
        event_types=None,  # test event bypasses type filtering
        enabled=True,
    )

    test_event = {
        "event_type": "webhook.test",
        "tenant_id": str(tenant_id),
        "webhook_id": webhook_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "data": {"message": "Webhook test delivery"},
    }

    engine = WebhookDeliveryEngine(max_retries=1)
    return await engine.deliver(config, test_event)
