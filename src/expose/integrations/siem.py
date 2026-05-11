"""Base SIEM adapter ABC and shared types.

Every SIEM integration adapter subclasses ``SIEMAdapter`` and implements the
three core methods: ``send_observations``, ``send_finding``, and
``health_check``.  ``DeliveryResult`` captures the outcome of each delivery
attempt; ``SIEMConfig`` holds vendor-neutral connection parameters.

The adapter lifecycle follows the same stateless-per-call pattern as
``expose.pipeline.webhook_delivery.WebhookDeliveryEngine``: callers
construct a config, build an adapter, and invoke delivery methods
directly. Persistence and retry orchestration live in the calling layer.

Circuit breaker: after ``_CIRCUIT_BREAKER_THRESHOLD`` consecutive failures
the adapter enters an *open* state and short-circuits all delivery calls
with an immediate failure result until ``_CIRCUIT_BREAKER_RESET_SECONDS``
elapses, at which point it transitions to *half-open* (allows one probe).
A successful probe resets the breaker; a failed probe re-opens it.
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
    "CircuitBreakerOpen",
    "DeliveryResult",
    "SIEMAdapter",
    "SIEMConfig",
]

logger = logging.getLogger(__name__)

# Backoff schedule (seconds) for retries on 5xx / 429 / network errors.
_RETRY_DELAYS = (1.0, 2.0, 4.0)

# HTTP status codes that trigger retry (rate-limited + server errors).
_HTTP_RATE_LIMITED = 429
_HTTP_SERVER_ERROR = 500

# Circuit breaker parameters.
_CIRCUIT_BREAKER_THRESHOLD = 5
_CIRCUIT_BREAKER_RESET_SECONDS = 60.0


class CircuitBreakerOpen(Exception):
    """Raised when the circuit breaker is open and the call is short-circuited."""


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

    Includes a per-instance circuit breaker that opens after
    ``_CIRCUIT_BREAKER_THRESHOLD`` consecutive delivery failures and resets
    after ``_CIRCUIT_BREAKER_RESET_SECONDS``.
    """

    adapter_id: str
    display_name: str

    def __init__(self, config: SIEMConfig) -> None:
        self._config = config
        # Circuit breaker state.
        self._consecutive_failures: int = 0
        self._circuit_open_since: float | None = None

    # ----- circuit breaker -----

    @property
    def circuit_is_open(self) -> bool:
        """Return ``True`` when the breaker is open (calls should be rejected)."""
        if self._circuit_open_since is None:
            return False
        elapsed = time.monotonic() - self._circuit_open_since
        if elapsed >= _CIRCUIT_BREAKER_RESET_SECONDS:
            # Transition to half-open — allow the next attempt as a probe.
            return False
        return True

    def _record_success(self) -> None:
        """Reset the breaker on a successful delivery."""
        self._consecutive_failures = 0
        self._circuit_open_since = None

    def _record_failure(self) -> None:
        """Increment the failure counter and trip the breaker if threshold reached."""
        self._consecutive_failures += 1
        if self._consecutive_failures >= _CIRCUIT_BREAKER_THRESHOLD:
            self._circuit_open_since = time.monotonic()
            logger.warning(
                "%s: circuit breaker opened after %d consecutive failures",
                self.adapter_id,
                self._consecutive_failures,
            )

    # ----- abstract interface -----

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

    def _is_retryable_status(self, status_code: int) -> bool:
        """Return ``True`` if the HTTP status warrants retry."""
        return status_code == _HTTP_RATE_LIMITED or status_code >= _HTTP_SERVER_ERROR

    async def _post_with_retry(
        self,
        url: str,
        *,
        headers: dict[str, str],
        content: bytes,
        request_timeout: float = 10.0,
    ) -> httpx.Response:
        """POST *content* to *url* with exponential-backoff retry on 429/5xx.

        Also respects the ``Retry-After`` header on 429 responses when present.

        Raises ``httpx.HTTPStatusError`` on non-retryable 4xx or after all
        retries are exhausted.  Raises ``CircuitBreakerOpen`` when the
        circuit breaker is in *open* state.
        """
        if self.circuit_is_open:
            raise CircuitBreakerOpen(
                f"{self.adapter_id}: circuit breaker is open — call rejected"
            )

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
                if not self._is_retryable_status(response.status_code):
                    self._record_success()
                    return response

                # Retryable status (429 or 5xx).
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

                # Honour Retry-After on 429 if present.
                if response.status_code == _HTTP_RATE_LIMITED:
                    retry_after = response.headers.get("retry-after")
                    if retry_after and attempt <= len(_RETRY_DELAYS):
                        try:
                            wait = min(float(retry_after), _RETRY_DELAYS[attempt - 1] * 2)
                            await asyncio.sleep(wait)
                            continue
                        except (ValueError, TypeError):
                            pass  # fall through to default backoff

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
        self._record_failure()
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
