"""SafeLLMClient — the safety wrapper through which ALL LLM calls flow (per ADR-005).

Enforces sanitization integrity, structured-output validation, per-call audit
logging, per-run cost ceiling, retry logic, and optional tie-breaker escalation.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ValidationError

from expose.llm.models import (
    CostTracker,
    EnrichmentRequest,
    EnrichmentResult,
    LLMHealthCheck,
    LLMRequest,
    LLMResponse,
)
from expose.observability.logging import get_logger
from expose.sanitization.canonicalize import LLM_SYSTEM_PROMPT_PREFIX

_logger = get_logger("expose.llm.client")

_OBSERVATION_TAG_RE = re.compile(r"<external_observation\b[^>]*>", re.IGNORECASE)


class LLMProvider(ABC):
    """Abstract base for LLM provider adapters."""

    provider_id: str

    @abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Send a structured-output request and return the response."""

    @abstractmethod
    async def health_check(self) -> LLMHealthCheck:
        """Check if the provider is reachable."""


def _validate_sanitization_tags(prompt: str) -> bool:
    """Verify external observation content is wrapped in ``<external_observation>`` tags.

    Returns ``True`` when either:
    - The prompt contains no raw observation markers (nothing to wrap), or
    - Every occurrence of observation-like content is inside proper tags.

    For v0.1.0 this checks that any ``<external_observation>`` tags present are
    well-formed (have matching close tags). Full content-level validation lands
    when the sanitization layer integration is complete.
    """
    open_count = len(_OBSERVATION_TAG_RE.findall(prompt))
    close_count = prompt.count("</external_observation>")
    return open_count == close_count


class SafeLLMClient:
    """Safety wrapper enforcing all ADR-005 constraints on LLM calls."""

    def __init__(
        self,
        primary_provider: LLMProvider,
        *,
        tiebreaker_provider: LLMProvider | None = None,
        cost_ceiling_per_run: float = 10.0,
        max_retries: int = 2,
    ) -> None:
        self._primary = primary_provider
        self._tiebreaker = tiebreaker_provider
        self._cost_tracker = CostTracker(ceiling=cost_ceiling_per_run)
        self._max_retries = max_retries

    @property
    def cost_tracker(self) -> CostTracker:
        return self._cost_tracker

    async def enrich(
        self,
        request: EnrichmentRequest,
        response_schema: type[BaseModel],
    ) -> EnrichmentResult:
        system_prompt = LLM_SYSTEM_PROMPT_PREFIX
        prompt = request.entity_context

        if not _validate_sanitization_tags(prompt):
            return EnrichmentResult(
                success=False,
                validation_errors=["Sanitization tag mismatch in prompt"],
            )

        llm_request = LLMRequest(
            prompt=prompt,
            system_prompt=system_prompt,
            model="",
            max_tokens=4096,
            temperature=0.0,
            response_format="json",
        )

        validation_errors: list[str] = []
        retries_used = 0
        tiebreaker_used = False

        for attempt in range(1 + self._max_retries):
            if attempt > 0:
                retries_used = attempt

            provider = self._primary
            try:
                response = await provider.complete(llm_request)
            except Exception as exc:
                validation_errors.append(f"Provider error: {exc}")
                if self._tiebreaker is not None and not tiebreaker_used:
                    tiebreaker_used = True
                    provider = self._tiebreaker
                    try:
                        response = await provider.complete(llm_request)
                    except Exception as tb_exc:
                        validation_errors.append(f"Tiebreaker error: {tb_exc}")
                        continue
                else:
                    continue

            self._cost_tracker.record(response.cost_estimate_usd)

            self._log_call(request, response)

            parsed = self._parse_and_validate(
                response.content, response_schema, validation_errors
            )
            if parsed is not None:
                return EnrichmentResult(
                    success=True,
                    parsed_response=parsed,
                    raw_response=response,
                    retries_used=retries_used,
                    cost_usd=response.cost_estimate_usd,
                    tiebreaker_used=tiebreaker_used,
                )

        return EnrichmentResult(
            success=False,
            validation_errors=validation_errors,
            retries_used=retries_used,
            tiebreaker_used=tiebreaker_used,
        )

    def _parse_and_validate(
        self,
        content: str,
        schema: type[BaseModel],
        errors: list[str],
    ) -> dict[str, Any] | None:
        try:
            raw = json.loads(content)
        except json.JSONDecodeError as exc:
            errors.append(f"JSON parse error: {exc}")
            return None

        try:
            validated = schema.model_validate(raw)
        except ValidationError as exc:
            errors.append(f"Schema validation error: {exc}")
            return None

        return validated.model_dump()

    def _log_call(self, request: EnrichmentRequest, response: LLMResponse) -> None:
        _logger.info(
            "llm.call",
            provider_id=response.provider_id,
            model=response.model,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            latency_ms=response.latency_ms,
            cost_estimate_usd=response.cost_estimate_usd,
            tenant_id=str(request.tenant_id),
            run_id=str(request.run_id),
            enrichment_type=request.enrichment_type,
        )


__all__ = [
    "LLMProvider",
    "SafeLLMClient",
]
