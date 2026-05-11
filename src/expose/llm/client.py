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
    TiebreakerPolicy,
    TiebreakerResolution,
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


def _extract_confidence(parsed: dict[str, Any]) -> float:
    """Extract a confidence score from a parsed LLM response.

    Looks for common confidence-bearing keys in order of precedence:
    ``confidence``, ``confidence_score``, ``score``.  Returns 0.0 if
    none are found.
    """
    for key in ("confidence", "confidence_score", "score"):
        val = parsed.get(key)
        if isinstance(val, (int, float)):
            return float(val)
    return 0.0


def _detect_disagreement(
    primary: dict[str, Any],
    tiebreaker: dict[str, Any],
) -> bool:
    """Return ``True`` when primary and tiebreaker reach structurally different conclusions.

    Checks a fixed set of keys that carry categorical decisions.  If any
    key is present in both results with different values, the results
    disagree.
    """
    decision_keys = (
        "recommended_tier",
        "is_noise",
        "attribution_tier",
        "label",
        "outcome",
        "verdict",
    )
    for key in decision_keys:
        if key in primary and key in tiebreaker and primary[key] != tiebreaker[key]:
            return True
    return False


class SafeLLMClient:
    """Safety wrapper enforcing all ADR-005 constraints on LLM calls."""

    def __init__(
        self,
        primary_provider: LLMProvider,
        *,
        tiebreaker_provider: LLMProvider | None = None,
        tiebreaker_policy: TiebreakerPolicy = TiebreakerPolicy.PRIMARY_WINS,
        cost_ceiling_per_run: float = 10.0,
        max_retries: int = 2,
    ) -> None:
        self._primary = primary_provider
        self._tiebreaker = tiebreaker_provider
        self._tiebreaker_policy = tiebreaker_policy
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
            primary_failed = False
            try:
                response = await provider.complete(llm_request)
            except Exception as exc:
                validation_errors.append(f"Provider error: {exc}")
                primary_failed = True
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
                # If primary failed and tiebreaker succeeded, return tiebreaker
                # result directly — no policy resolution applies.
                if primary_failed:
                    return EnrichmentResult(
                        success=True,
                        parsed_response=parsed,
                        raw_response=response,
                        retries_used=retries_used,
                        cost_usd=response.cost_estimate_usd,
                        tiebreaker_used=tiebreaker_used,
                    )

                # Primary succeeded — attempt tiebreaker policy resolution
                # if a tiebreaker provider is configured.
                resolution_result = await self._resolve_tiebreaker(
                    request,
                    llm_request,
                    response_schema,
                    parsed,
                    response,
                    retries_used,
                    validation_errors,
                )
                if resolution_result is not None:
                    return resolution_result

                # No tiebreaker configured or tiebreaker call failed —
                # return primary result as-is.
                return EnrichmentResult(
                    success=True,
                    parsed_response=parsed,
                    raw_response=response,
                    retries_used=retries_used,
                    cost_usd=response.cost_estimate_usd,
                    tiebreaker_used=False,
                )

        return EnrichmentResult(
            success=False,
            validation_errors=validation_errors,
            retries_used=retries_used,
            tiebreaker_used=tiebreaker_used,
        )

    async def _resolve_tiebreaker(
        self,
        request: EnrichmentRequest,
        llm_request: LLMRequest,
        response_schema: type[BaseModel],
        primary_parsed: dict[str, Any],
        primary_response: LLMResponse,
        retries_used: int,
        validation_errors: list[str],
    ) -> EnrichmentResult | None:
        """Apply the tiebreaker policy when both providers can produce results.

        Returns an ``EnrichmentResult`` when resolution applies (tiebreaker is
        configured and called), or ``None`` to let the caller fall through to
        the default primary-only path.
        """
        if self._tiebreaker is None:
            return None

        # Attempt tiebreaker call
        tb_errors: list[str] = []
        try:
            tb_response = await self._tiebreaker.complete(llm_request)
        except Exception as exc:
            _logger.warning(
                "llm.tiebreaker_call_failed",
                error=str(exc),
            )
            # Tiebreaker call failed — primary result stands, no resolution.
            return None

        self._cost_tracker.record(tb_response.cost_estimate_usd)
        self._log_call(request, tb_response)

        tb_parsed = self._parse_and_validate(
            tb_response.content, response_schema, tb_errors
        )
        if tb_parsed is None:
            _logger.warning(
                "llm.tiebreaker_parse_failed",
                errors=tb_errors,
            )
            # Tiebreaker returned invalid data — primary result stands.
            return None

        # Both results are valid — detect disagreement and apply policy.
        disagreement = _detect_disagreement(primary_parsed, tb_parsed)
        total_cost = primary_response.cost_estimate_usd + tb_response.cost_estimate_usd

        return self._apply_policy(
            primary_parsed=primary_parsed,
            primary_response=primary_response,
            tb_parsed=tb_parsed,
            tb_response=tb_response,
            disagreement=disagreement,
            retries_used=retries_used,
            total_cost=total_cost,
            validation_errors=validation_errors,
        )

    def _apply_policy(
        self,
        *,
        primary_parsed: dict[str, Any],
        primary_response: LLMResponse,
        tb_parsed: dict[str, Any],
        tb_response: LLMResponse,
        disagreement: bool,
        retries_used: int,
        total_cost: float,
        validation_errors: list[str],
    ) -> EnrichmentResult:
        """Select the winning result based on the configured tiebreaker policy."""
        policy = self._tiebreaker_policy

        if policy == TiebreakerPolicy.PRIMARY_WINS:
            resolution = TiebreakerResolution(
                policy=policy,
                primary_used=True,
                tiebreaker_used=False,
                reason="Primary result used per PRIMARY_WINS policy",
                disagreement_detected=disagreement,
            )
            return EnrichmentResult(
                success=True,
                parsed_response=primary_parsed,
                raw_response=primary_response,
                retries_used=retries_used,
                cost_usd=total_cost,
                tiebreaker_used=True,
                tiebreaker_resolution=resolution,
            )

        if policy == TiebreakerPolicy.CONSERVATIVE:
            primary_conf = _extract_confidence(primary_parsed)
            tb_conf = _extract_confidence(tb_parsed)
            # Lower confidence = more conservative (cautious) assessment.
            use_primary = primary_conf <= tb_conf
            winner_label = "primary" if use_primary else "tiebreaker"
            resolution = TiebreakerResolution(
                policy=policy,
                primary_used=use_primary,
                tiebreaker_used=not use_primary,
                reason=(
                    f"CONSERVATIVE: {winner_label} selected "
                    f"(primary={primary_conf:.4f}, tiebreaker={tb_conf:.4f})"
                ),
                disagreement_detected=disagreement,
            )
            chosen_parsed = primary_parsed if use_primary else tb_parsed
            chosen_response = primary_response if use_primary else tb_response
            return EnrichmentResult(
                success=True,
                parsed_response=chosen_parsed,
                raw_response=chosen_response,
                retries_used=retries_used,
                cost_usd=total_cost,
                tiebreaker_used=True,
                tiebreaker_resolution=resolution,
            )

        if policy == TiebreakerPolicy.HIGHER_CONFIDENCE:
            primary_conf = _extract_confidence(primary_parsed)
            tb_conf = _extract_confidence(tb_parsed)
            use_primary = primary_conf >= tb_conf
            winner_label = "primary" if use_primary else "tiebreaker"
            resolution = TiebreakerResolution(
                policy=policy,
                primary_used=use_primary,
                tiebreaker_used=not use_primary,
                reason=(
                    f"HIGHER_CONFIDENCE: {winner_label} selected "
                    f"(primary={primary_conf:.4f}, tiebreaker={tb_conf:.4f})"
                ),
                disagreement_detected=disagreement,
            )
            chosen_parsed = primary_parsed if use_primary else tb_parsed
            chosen_response = primary_response if use_primary else tb_response
            return EnrichmentResult(
                success=True,
                parsed_response=chosen_parsed,
                raw_response=chosen_response,
                retries_used=retries_used,
                cost_usd=total_cost,
                tiebreaker_used=True,
                tiebreaker_resolution=resolution,
            )

        # TiebreakerPolicy.ESCALATE
        resolution = TiebreakerResolution(
            policy=policy,
            primary_used=True,
            tiebreaker_used=True,
            reason="ESCALATE: both results returned for human review",
            disagreement_detected=disagreement,
        )
        return EnrichmentResult(
            success=True,
            parsed_response=primary_parsed,
            raw_response=primary_response,
            retries_used=retries_used,
            cost_usd=total_cost,
            tiebreaker_used=True,
            needs_review=True,
            tiebreaker_resolution=resolution,
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
    "TiebreakerPolicy",
    "TiebreakerResolution",
]
