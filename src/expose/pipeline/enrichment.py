"""Stage 4b -- LLM enrichment for medium-confidence entities.

Provides structured-output enrichment functions that the RunExecutor
can optionally invoke after graph upsert (Stage 4).  Each function
takes entity data and returns a structured enrichment result.

Per ADR-005, the LLM never invents observations -- it reasons over
existing graph data and produces structured outputs validated against
Pydantic schemas.
"""

from __future__ import annotations

import json
from typing import Any, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from expose.llm.client import SafeLLMClient
from expose.llm.models import EnrichmentRequest, EnrichmentResult
from expose.observability.logging import get_logger
from expose.sanitization.canonicalize import wrap_for_llm_prompt

_logger = get_logger("expose.pipeline.enrichment")

_T = TypeVar("_T", bound=BaseModel)

# Attribution-check confidence band: only entities in [0.4, 0.7) are
# enriched -- confirmed/high-confidence entities are already decisive,
# and requires_review entities need human triage, not LLM second-guessing.
_ATTR_CHECK_LOW = 0.4
_ATTR_CHECK_HIGH = 0.7


# ---------------------------------------------------------------------------
# Enrichment response schemas (Pydantic -- structured-output validation)
# ---------------------------------------------------------------------------


class AttributionEnrichment(BaseModel):
    """LLM output for attribution sanity-check."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    original_confidence: float
    adjusted_confidence: float = Field(ge=0.0, le=1.0)
    adjustment_reasoning: str
    recommended_tier: str  # "confirmed", "high", "medium", "requires_review"
    signals_considered: list[str] = Field(default_factory=list)


class TechStackEnrichment(BaseModel):
    """LLM output for tech-stack inference from HTTP fingerprints."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    inferred_technologies: list[str] = Field(default_factory=list)
    infrastructure_pattern: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = ""


class NoiseClassification(BaseModel):
    """LLM output for noise/signal classification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_noise: bool
    noise_reason: str | None = None
    noise_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------


class EnrichmentPipeline:
    """Orchestrates Stage 4b enrichment for a set of entities.

    The pipeline is stateless across calls -- each ``enrich_entity`` invocation
    is independent.  The ``SafeLLMClient`` handles cost-ceiling tracking,
    retries, and audit logging internally.

    When ``llm_client`` is ``None`` the pipeline degrades gracefully: every
    call returns an empty dict, making LLM enrichment purely opt-in.
    """

    def __init__(self, llm_client: SafeLLMClient | None = None) -> None:
        self._client = llm_client

    # -- public entry point -------------------------------------------------

    async def enrich_entity(
        self,
        *,
        entity_type: str,
        canonical_identifier: str,
        properties: dict[str, Any],
        attribution_confidence: float,
        tenant_id: UUID,
        run_id: UUID,
    ) -> dict[str, Any]:
        """Run all applicable enrichment passes for a single entity.

        Returns a dict of enrichment results keyed by enrichment type
        (``"attribution"``, ``"tech_stack"``, ``"noise"``).  Values are
        plain dicts (model-dumped Pydantic objects).

        If no LLM client is configured, returns ``{}``.
        """
        if self._client is None:
            return {}

        results: dict[str, Any] = {}

        # 1. Attribution sanity-check for medium-confidence entities
        if _ATTR_CHECK_LOW <= attribution_confidence < _ATTR_CHECK_HIGH:
            result = await self._attribution_check(
                entity_type=entity_type,
                canonical_identifier=canonical_identifier,
                properties=properties,
                attribution_confidence=attribution_confidence,
                tenant_id=tenant_id,
                run_id=run_id,
            )
            if result is not None:
                results["attribution"] = result.model_dump()

        # 2. Tech-stack inference when HTTP fingerprint data is present
        collector_id = properties.get("_collector_id", "")
        if collector_id == "active-http-fingerprint":
            result_ts = await self._tech_stack_inference(
                entity_type=entity_type,
                canonical_identifier=canonical_identifier,
                properties=properties,
                tenant_id=tenant_id,
                run_id=run_id,
            )
            if result_ts is not None:
                results["tech_stack"] = result_ts.model_dump()

        # 3. Noise classification for low-confidence or ambiguous entities
        if attribution_confidence < _ATTR_CHECK_LOW:
            result_nc = await self._noise_classification(
                entity_type=entity_type,
                canonical_identifier=canonical_identifier,
                properties=properties,
                attribution_confidence=attribution_confidence,
                tenant_id=tenant_id,
                run_id=run_id,
            )
            if result_nc is not None:
                results["noise"] = result_nc.model_dump()

        return results

    # -- private enrichment functions ---------------------------------------

    async def _attribution_check(
        self,
        *,
        entity_type: str,
        canonical_identifier: str,
        properties: dict[str, Any],
        attribution_confidence: float,
        tenant_id: UUID,
        run_id: UUID,
    ) -> AttributionEnrichment | None:
        """Build prompt, call SafeLLMClient, parse response."""
        context_parts = [
            f"Entity type: {entity_type}",
            f"Identifier: {canonical_identifier}",
            f"Current attribution confidence: {attribution_confidence}",
        ]
        # Include relevant properties (excluding internal underscore keys
        # that are pipeline metadata, not observation data).
        public_props = {
            k: v for k, v in properties.items() if not k.startswith("_")
        }
        if public_props:
            context_parts.append(
                f"Properties: {json.dumps(public_props, default=str)}"
            )

        raw_context = "\n".join(context_parts)
        wrapped = wrap_for_llm_prompt(raw_context, source="attribution_check")

        prompt = (
            "Analyze this entity and assess whether the current attribution "
            "confidence is appropriate.  Return a JSON object with fields: "
            "original_confidence (float), adjusted_confidence (float 0-1), "
            "adjustment_reasoning (string), recommended_tier (one of: "
            "confirmed, high, medium, requires_review), "
            "signals_considered (list of strings).\n\n"
            f"{wrapped}"
        )

        return await self._call_llm(
            prompt=prompt,
            enrichment_type="attribution_check",
            response_schema=AttributionEnrichment,
            tenant_id=tenant_id,
            run_id=run_id,
        )

    async def _tech_stack_inference(
        self,
        *,
        entity_type: str,
        canonical_identifier: str,
        properties: dict[str, Any],
        tenant_id: UUID,
        run_id: UUID,
    ) -> TechStackEnrichment | None:
        """Infer technology stack from HTTP fingerprint observations."""
        context_parts = [
            f"Entity type: {entity_type}",
            f"Identifier: {canonical_identifier}",
        ]
        # Include HTTP-relevant properties.
        http_props = {
            k: v
            for k, v in properties.items()
            if not k.startswith("_")
        }
        if http_props:
            context_parts.append(
                f"HTTP observations: {json.dumps(http_props, default=str)}"
            )

        raw_context = "\n".join(context_parts)
        wrapped = wrap_for_llm_prompt(raw_context, source="tech_stack_inference")

        prompt = (
            "Analyze the HTTP fingerprint data for this entity and infer the "
            "technology stack.  Return a JSON object with fields: "
            "inferred_technologies (list of strings), "
            "infrastructure_pattern (string or null), "
            "confidence (float 0-1), reasoning (string).\n\n"
            f"{wrapped}"
        )

        return await self._call_llm(
            prompt=prompt,
            enrichment_type="tech_stack_inference",
            response_schema=TechStackEnrichment,
            tenant_id=tenant_id,
            run_id=run_id,
        )

    async def _noise_classification(
        self,
        *,
        entity_type: str,
        canonical_identifier: str,
        properties: dict[str, Any],
        attribution_confidence: float,
        tenant_id: UUID,
        run_id: UUID,
    ) -> NoiseClassification | None:
        """Classify whether a low-confidence entity is noise or signal."""
        context_parts = [
            f"Entity type: {entity_type}",
            f"Identifier: {canonical_identifier}",
            f"Attribution confidence: {attribution_confidence}",
        ]
        public_props = {
            k: v for k, v in properties.items() if not k.startswith("_")
        }
        if public_props:
            context_parts.append(
                f"Properties: {json.dumps(public_props, default=str)}"
            )

        raw_context = "\n".join(context_parts)
        wrapped = wrap_for_llm_prompt(raw_context, source="noise_classification")

        prompt = (
            "Determine whether this low-confidence entity is likely noise "
            "(false positive, parked domain, CDN artefact, etc.) or a genuine "
            "signal worth further investigation.  Return a JSON object with "
            "fields: is_noise (bool), noise_reason (string or null), "
            "noise_confidence (float 0-1).\n\n"
            f"{wrapped}"
        )

        return await self._call_llm(
            prompt=prompt,
            enrichment_type="noise_classification",
            response_schema=NoiseClassification,
            tenant_id=tenant_id,
            run_id=run_id,
        )

    # -- shared LLM call helper ---------------------------------------------

    async def _call_llm(
        self,
        *,
        prompt: str,
        enrichment_type: str,
        response_schema: type[_T],
        tenant_id: UUID,
        run_id: UUID,
    ) -> _T | None:
        """Call ``SafeLLMClient.enrich`` and return a validated model or None.

        Catches all exceptions so a single LLM failure never crashes the
        pipeline -- the enrichment pass simply produces no output.
        """
        assert self._client is not None  # guarded by caller

        request = EnrichmentRequest(
            tenant_id=tenant_id,
            run_id=run_id,
            entity_context=prompt,
            enrichment_type=enrichment_type,
        )

        try:
            result: EnrichmentResult = await self._client.enrich(
                request, response_schema
            )
        except Exception:
            _logger.warning(
                "enrichment.llm_error",
                enrichment_type=enrichment_type,
                tenant_id=str(tenant_id),
                run_id=str(run_id),
                exc_info=True,
            )
            return None

        if not result.success:
            _logger.info(
                "enrichment.validation_failed",
                enrichment_type=enrichment_type,
                errors=result.validation_errors,
            )
            return None

        # result.parsed_response is a plain dict -- re-validate through the
        # target schema to get a typed Pydantic model.
        return response_schema.model_validate(result.parsed_response)


__all__ = [
    "AttributionEnrichment",
    "EnrichmentPipeline",
    "NoiseClassification",
    "TechStackEnrichment",
]
