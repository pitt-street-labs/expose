"""Webhook event delivery engine with HMAC-SHA256 signing and retry.

Delivers pipeline lifecycle events to externally configured webhook endpoints.
Each delivery:

1. Serializes the event to canonical JSON bytes.
2. Computes an HMAC-SHA256 signature over the payload using the webhook's
   shared secret (via ``cryptography.hazmat.primitives.hmac`` — FIPS-validated
   when running against a FIPS-mode OpenSSL build, consistent with ADR-010).
3. POSTs to the webhook URL with typed headers (``X-EXPOSE-Signature``,
   ``X-EXPOSE-Event``, ``X-EXPOSE-Delivery``).
4. Retries with exponential backoff on 5xx responses or network errors.

The engine is deliberately stateless — it receives a ``WebhookConfig`` and an
event dict per call. Storage and filtering are handled by the API layer
(``expose.api.webhooks``).

Note: This module uses ``cryptography.hazmat.primitives.hmac`` (not stdlib
``hmac`` / ``hashlib``) to stay within the FIPS-validated crypto boundary
enforced by the banned-import scanner in ``tests/test_fips_crypto_gate.py``.
While webhook HMAC signing is not operating on artifact data, consistency with
the project-wide FIPS posture avoids gate violations and keeps the crypto
surface area auditable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "WebhookConfig",
    "WebhookDeliveryEngine",
    "WebhookDeliveryResult",
]

logger = logging.getLogger(__name__)

# Backoff schedule (seconds) for retries on 5xx / network errors.
_RETRY_DELAYS = (1.0, 2.0, 4.0)

# HTTP status code boundaries for retry logic.
_HTTP_OK = 200
_HTTP_REDIRECT_UPPER = 300
_HTTP_SERVER_ERROR = 500


class WebhookConfig(BaseModel):
    """Configuration for a single webhook endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str = Field(min_length=1)
    secret: str = Field(min_length=16)  # HMAC signing key
    event_types: frozenset[str] | None = None  # None = all events
    enabled: bool = True


class WebhookDeliveryResult(BaseModel):
    """Outcome of a single webhook delivery attempt (possibly after retries)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    webhook_url: str
    event_type: str
    status_code: int | None
    success: bool
    attempt: int
    error: str | None = None


def _compute_hmac_sha256(key: bytes, data: bytes) -> str:
    """Compute HMAC-SHA256 over *data* using *key*, returning lowercase hex.

    Uses ``cryptography.hazmat.primitives.hmac.HMAC`` so the digest routes
    through the same FIPS-validated OpenSSL backend as the rest of the EXPOSE
    crypto surface.
    """
    h = HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize().hex()


class WebhookDeliveryEngine:
    """Delivers events to configured webhook endpoints with HMAC signing and retry."""

    def __init__(self, max_retries: int = 3) -> None:
        self._max_retries = max_retries

    async def deliver(self, config: WebhookConfig, event: dict[str, Any]) -> WebhookDeliveryResult:
        """POST *event* as JSON to *config.url* with HMAC-SHA256 signature.

        Returns a ``WebhookDeliveryResult`` summarizing the outcome. On 5xx
        responses or network errors the engine retries up to ``max_retries``
        times with exponential backoff (1 s, 2 s, 4 s).

        Non-retryable failures (4xx, invalid URL) return immediately.
        """
        event_type = event.get("event_type", "unknown")
        delivery_id = str(uuid.uuid4())

        # Serialize to canonical JSON bytes.
        payload = _json_bytes(event)

        # Compute HMAC-SHA256 signature.
        signature = _compute_hmac_sha256(config.secret.encode(), payload)

        headers = {
            "Content-Type": "application/json",
            "X-EXPOSE-Signature": f"sha256={signature}",
            "X-EXPOSE-Event": event_type,
            "X-EXPOSE-Delivery": delivery_id,
        }

        last_error: str | None = None
        last_status: int | None = None

        for attempt in range(1, self._max_retries + 1):
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        config.url,
                        content=payload,
                        headers=headers,
                        timeout=10.0,
                    )
                last_status = response.status_code

                if response.status_code < _HTTP_SERVER_ERROR:
                    # 2xx = success, 4xx = non-retryable client error.
                    is_success = _HTTP_OK <= response.status_code < _HTTP_REDIRECT_UPPER
                    return WebhookDeliveryResult(
                        webhook_url=config.url,
                        event_type=event_type,
                        status_code=response.status_code,
                        success=is_success,
                        attempt=attempt,
                        error=None if is_success else (f"HTTP {response.status_code}"),
                    )

                # 5xx — retryable.
                last_error = f"HTTP {response.status_code}"
                logger.warning(
                    "Webhook delivery %s attempt %d/%d got %d from %s",
                    delivery_id,
                    attempt,
                    self._max_retries,
                    response.status_code,
                    config.url,
                )

            except httpx.HTTPError as exc:
                last_status = None
                last_error = str(exc) or type(exc).__name__
                logger.warning(
                    "Webhook delivery %s attempt %d/%d network error: %s",
                    delivery_id,
                    attempt,
                    self._max_retries,
                    last_error,
                )

            # Exponential backoff before next retry (skip sleep after last attempt).
            if attempt < self._max_retries:
                delay = _RETRY_DELAYS[min(attempt - 1, len(_RETRY_DELAYS) - 1)]
                await asyncio.sleep(delay)

        # All retries exhausted.
        return WebhookDeliveryResult(
            webhook_url=config.url,
            event_type=event_type,
            status_code=last_status,
            success=False,
            attempt=self._max_retries,
            error=last_error,
        )


def _json_bytes(obj: dict[str, Any]) -> bytes:
    """Serialize a dict to compact JSON bytes (deterministic key order)."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
