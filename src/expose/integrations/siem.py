"""Base SIEM adapter ABC and shared types.

Every SIEM integration adapter subclasses ``SIEMAdapter`` and implements the
three core methods: ``send_observations``, ``send_finding``, and
``health_check``.  ``DeliveryResult`` captures the outcome of each delivery
attempt; ``SIEMConfig`` holds vendor-neutral connection parameters.

The adapter lifecycle follows the same stateless-per-call pattern as
``expose.pipeline.webhook_delivery.WebhookDeliveryEngine``: callers
construct a config, build an adapter, and invoke delivery methods
directly. Persistence and retry orchestration live in the calling layer.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "DeliveryResult",
    "SIEMAdapter",
    "SIEMConfig",
]

logger = logging.getLogger(__name__)

# Backoff schedule (seconds) for retries on 5xx / network errors.
_RETRY_DELAYS = (1.0, 2.0, 4.0)

# HTTP status code boundaries.
_HTTP_OK = 200
_HTTP_REDIRECT_UPPER = 300
_HTTP_SERVER_ERROR = 500


class DeliveryResult(BaseModel):
    """Outcome of a SIEM delivery attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    adapter_id: str
    success: bool
    events_sent: int = Field(ge=0)
    events_failed: int = Field(ge=0)
    error: str | None = None
    duration_ms: float = Field(ge=0.0)


class SIEMConfig(BaseModel):
    """Vendor-neutral SIEM connection configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    adapter_type: str  # "splunk", "sentinel", "chronicle"
    endpoint: str = Field(min_length=1)
    auth_token: str = Field(min_length=1)
    enabled: bool = True
    batch_size: int = Field(default=100, ge=1, le=1000)


class SIEMAdapter(ABC):
    """Base class for SIEM integration adapters.

    Subclasses set ``adapter_id`` and ``display_name`` as class attributes
    and implement the three abstract methods.
    """

    adapter_id: str
    display_name: str

    def __init__(self, config: SIEMConfig) -> None:
        self._config = config

    @abstractmethod
    async def send_observations(
        self,
        observations: list[dict[str, Any]],
        tenant_id: UUID,
    ) -> DeliveryResult:
        """Deliver a batch of observations to the SIEM."""
        ...

    @abstractmethod
    async def send_finding(
        self,
        finding: dict[str, Any],
        tenant_id: UUID,
    ) -> DeliveryResult:
        """Deliver a single finding/alert to the SIEM."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the SIEM endpoint is reachable and authenticated."""
        ...

    # ----- shared helpers for subclasses -----

    async def _post_with_retry(
        self,
        url: str,
        *,
        headers: dict[str, str],
        content: bytes,
        request_timeout: float = 10.0,
    ) -> httpx.Response:
        """POST *content* to *url* with exponential-backoff retry on 5xx.

        Raises ``httpx.HTTPStatusError`` on non-retryable 4xx or after all
        retries are exhausted with 5xx.
        """
        last_exc: Exception | None = None

        for attempt in range(1, len(_RETRY_DELAYS) + 2):  # 4 attempts total
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        url,
                        content=content,
                        headers=headers,
                        timeout=request_timeout,
                    )
                if response.status_code < _HTTP_SERVER_ERROR:
                    return response

                # 5xx -- retryable
                last_exc = httpx.HTTPStatusError(
                    f"HTTP {response.status_code}",
                    request=response.request,
                    response=response,
                )
                logger.warning(
                    "%s: attempt %d got %d from %s",
                    self.adapter_id,
                    attempt,
                    response.status_code,
                    url,
                )
            except httpx.HTTPError as exc:
                last_exc = exc
                logger.warning(
                    "%s: attempt %d network error: %s",
                    self.adapter_id,
                    attempt,
                    exc,
                )

            # Back off before next retry (skip sleep after last attempt).
            if attempt <= len(_RETRY_DELAYS):
                await asyncio.sleep(_RETRY_DELAYS[attempt - 1])

        # All retries exhausted.
        raise last_exc  # type: ignore[misc]

    def _timed_result(
        self,
        *,
        success: bool,
        events_sent: int,
        events_failed: int,
        start: float,
        error: str | None = None,
    ) -> DeliveryResult:
        """Build a ``DeliveryResult`` with elapsed-time calculation."""
        return DeliveryResult(
            adapter_id=self.adapter_id,
            success=success,
            events_sent=events_sent,
            events_failed=events_failed,
            error=error,
            duration_ms=round((time.monotonic() - start) * 1000, 2),
        )
