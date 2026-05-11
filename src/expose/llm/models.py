"""Request/response types for the EXPOSE LLM integration layer (per ADR-005)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TiebreakerPolicy(StrEnum):
    """Determines which result wins when both primary and tiebreaker produce output."""

    PRIMARY_WINS = "primary_wins"
    CONSERVATIVE = "conservative"
    HIGHER_CONFIDENCE = "higher_confidence"
    ESCALATE = "escalate"


class TiebreakerResolution(BaseModel):
    """Audit record of how the tiebreaker policy resolved a dual-result scenario."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy: TiebreakerPolicy
    primary_used: bool
    tiebreaker_used: bool
    reason: str
    disagreement_detected: bool = False


class LLMRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt: str
    system_prompt: str = ""
    model: str
    max_tokens: int = 4096
    temperature: float = 0.0
    response_format: str = "json"


class LLMResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str
    model: str
    provider_id: str
    input_tokens: int
    output_tokens: int
    latency_ms: float
    cost_estimate_usd: float


class LLMHealthCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_id: str
    healthy: bool
    latency_ms: float | None = None
    error_message: str | None = None


class EnrichmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    run_id: UUID
    entity_context: str
    enrichment_type: str


class EnrichmentResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    success: bool
    parsed_response: dict[str, Any] | None = None
    raw_response: LLMResponse | None = None
    validation_errors: list[str] = Field(default_factory=list)
    retries_used: int = 0
    cost_usd: float = 0.0
    tiebreaker_used: bool = False
    needs_review: bool = False
    tiebreaker_resolution: TiebreakerResolution | None = None


class CostCeilingExceededError(Exception):
    """Raised when accumulated LLM costs exceed the per-run ceiling."""


class CostTracker:
    """Per-run cost accumulator with ceiling enforcement."""

    def __init__(self, ceiling: float) -> None:
        self._ceiling = ceiling
        self._total: float = 0.0

    def record(self, cost: float) -> None:
        self._total += cost
        if self._total > self._ceiling:
            msg = (
                f"LLM cost ceiling exceeded: ${self._total:.4f} > ${self._ceiling:.2f}"
            )
            raise CostCeilingExceededError(msg)

    @property
    def total(self) -> float:
        return self._total


__all__ = [
    "CostCeilingExceededError",
    "CostTracker",
    "EnrichmentRequest",
    "EnrichmentResult",
    "LLMHealthCheck",
    "LLMRequest",
    "LLMResponse",
    "TiebreakerPolicy",
    "TiebreakerResolution",
]
