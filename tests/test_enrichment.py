"""Tests for Stage 4b LLM enrichment pipeline."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from pydantic import ValidationError

from expose.llm.client import SafeLLMClient
from expose.llm.models import EnrichmentRequest, EnrichmentResult, LLMResponse
from expose.pipeline.enrichment import (
    AttributionEnrichment,
    EnrichmentPipeline,
    NoiseClassification,
    TechStackEnrichment,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TENANT_ID = uuid4()
_RUN_ID = uuid4()


def _make_enrichment_result(
    parsed: dict,
    *,
    success: bool = True,
) -> EnrichmentResult:
    """Build an EnrichmentResult with the given parsed response."""
    raw = LLMResponse(
        content=json.dumps(parsed),
        model="test-model",
        provider_id="test",
        input_tokens=100,
        output_tokens=50,
        latency_ms=42.0,
        cost_estimate_usd=0.001,
    )
    return EnrichmentResult(
        success=success,
        parsed_response=parsed if success else None,
        raw_response=raw if success else None,
    )


def _mock_client(enrichment_result: EnrichmentResult) -> SafeLLMClient:
    """Build a SafeLLMClient mock whose ``enrich`` returns the given result."""
    client = AsyncMock(spec=SafeLLMClient)
    client.enrich = AsyncMock(return_value=enrichment_result)
    return client


# ---------------------------------------------------------------------------
# 1. No client -> empty dict
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrichment_pipeline_no_client() -> None:
    """When no LLM client is configured, enrich_entity returns {}."""
    pipeline = EnrichmentPipeline(llm_client=None)
    result = await pipeline.enrich_entity(
        entity_type="domain",
        canonical_identifier="example.com",
        properties={},
        attribution_confidence=0.5,
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )
    assert result == {}


# ---------------------------------------------------------------------------
# 2. Attribution check for medium-confidence entity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_attribution_check_medium_confidence() -> None:
    """Medium-confidence entity triggers attribution check; result is parsed."""
    parsed = {
        "original_confidence": 0.55,
        "adjusted_confidence": 0.65,
        "adjustment_reasoning": "Strong WHOIS match boosts confidence.",
        "recommended_tier": "medium",
        "signals_considered": ["whois_org_match", "dns_zone_authority"],
    }
    client = _mock_client(_make_enrichment_result(parsed))
    pipeline = EnrichmentPipeline(llm_client=client)

    result = await pipeline.enrich_entity(
        entity_type="domain",
        canonical_identifier="target.example.com",
        properties={"registrar": "Example Inc."},
        attribution_confidence=0.55,
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    assert "attribution" in result
    attr = result["attribution"]
    assert attr["original_confidence"] == 0.55
    assert attr["adjusted_confidence"] == 0.65
    assert attr["recommended_tier"] == "medium"
    assert "whois_org_match" in attr["signals_considered"]

    # Verify the client was called with the right enrichment type.
    call_args = client.enrich.call_args
    request: EnrichmentRequest = call_args.args[0]
    assert request.enrichment_type == "attribution_check"


# ---------------------------------------------------------------------------
# 3. Attribution check skipped for high confidence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_attribution_check_skipped_high_confidence() -> None:
    """Entities with confidence >= 0.7 skip the attribution check entirely."""
    client = _mock_client(
        _make_enrichment_result({"unused": True}, success=True)
    )
    pipeline = EnrichmentPipeline(llm_client=client)

    result = await pipeline.enrich_entity(
        entity_type="domain",
        canonical_identifier="confirmed.example.com",
        properties={},
        attribution_confidence=0.85,
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    # No attribution key (skipped), and no tech_stack (no HTTP collector).
    assert "attribution" not in result
    # Client should not have been called at all -- high confidence, no
    # HTTP collector, and confidence >= 0.4 so no noise classification.
    client.enrich.assert_not_called()


# ---------------------------------------------------------------------------
# 4. Tech-stack enrichment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tech_stack_enrichment() -> None:
    """Entities from active-http-fingerprint collector get tech-stack inference."""
    parsed = {
        "inferred_technologies": ["nginx", "React", "Node.js"],
        "infrastructure_pattern": "reverse-proxy-spa",
        "confidence": 0.82,
        "reasoning": "Server header and response patterns indicate nginx + SPA.",
    }
    client = _mock_client(_make_enrichment_result(parsed))
    pipeline = EnrichmentPipeline(llm_client=client)

    result = await pipeline.enrich_entity(
        entity_type="subdomain",
        canonical_identifier="app.example.com",
        properties={
            "_collector_id": "active-http-fingerprint",
            "server_header": "nginx/1.25",
            "content_type": "text/html",
        },
        # High confidence -- attribution check skipped, but tech stack runs.
        attribution_confidence=0.9,
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    assert "tech_stack" in result
    ts = result["tech_stack"]
    assert "nginx" in ts["inferred_technologies"]
    assert ts["infrastructure_pattern"] == "reverse-proxy-spa"
    assert ts["confidence"] == pytest.approx(0.82)


# ---------------------------------------------------------------------------
# 5. Noise classification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_noise_classification() -> None:
    """Low-confidence entities get noise classification."""
    parsed = {
        "is_noise": True,
        "noise_reason": "Parked domain with generic registrar page.",
        "noise_confidence": 0.91,
    }
    client = _mock_client(_make_enrichment_result(parsed))
    pipeline = EnrichmentPipeline(llm_client=client)

    result = await pipeline.enrich_entity(
        entity_type="domain",
        canonical_identifier="parked.example.com",
        properties={},
        attribution_confidence=0.15,
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    assert "noise" in result
    nc = result["noise"]
    assert nc["is_noise"] is True
    assert nc["noise_reason"] == "Parked domain with generic registrar page."
    assert nc["noise_confidence"] == pytest.approx(0.91)


# ---------------------------------------------------------------------------
# 6. Pydantic models are frozen
# ---------------------------------------------------------------------------


def test_enrichment_models_frozen() -> None:
    """All enrichment response models are frozen (immutable)."""
    attr = AttributionEnrichment(
        original_confidence=0.5,
        adjusted_confidence=0.6,
        adjustment_reasoning="test",
        recommended_tier="medium",
    )
    with pytest.raises(ValidationError):
        attr.original_confidence = 0.9  # type: ignore[misc]

    ts = TechStackEnrichment()
    with pytest.raises(ValidationError):
        ts.confidence = 0.5  # type: ignore[misc]

    nc = NoiseClassification(is_noise=False)
    with pytest.raises(ValidationError):
        nc.is_noise = True  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 7. Graceful degradation on LLM error
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrichment_graceful_on_llm_error() -> None:
    """If the LLM raises an exception, enrichment returns {} without crashing."""
    client = AsyncMock(spec=SafeLLMClient)
    client.enrich = AsyncMock(side_effect=RuntimeError("LLM provider down"))
    pipeline = EnrichmentPipeline(llm_client=client)

    result = await pipeline.enrich_entity(
        entity_type="domain",
        canonical_identifier="error.example.com",
        properties={},
        attribution_confidence=0.5,  # triggers attribution check
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    # Should degrade gracefully -- empty dict, no exception raised.
    assert result == {}


# ---------------------------------------------------------------------------
# 8. Attribution check skipped for very low confidence (< 0.4)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_attribution_check_skipped_low_confidence() -> None:
    """Entities with confidence < 0.4 skip attribution check (noise path only)."""
    parsed = {
        "is_noise": False,
        "noise_reason": None,
        "noise_confidence": 0.3,
    }
    client = _mock_client(_make_enrichment_result(parsed))
    pipeline = EnrichmentPipeline(llm_client=client)

    result = await pipeline.enrich_entity(
        entity_type="ip",
        canonical_identifier="192.0.2.1",
        properties={},
        attribution_confidence=0.2,
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    # Should have noise classification but NOT attribution.
    assert "attribution" not in result
    assert "noise" in result


# ---------------------------------------------------------------------------
# 9. LLM returns unsuccessful result -> no enrichment output
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrichment_unsuccessful_llm_result() -> None:
    """When SafeLLMClient returns success=False, enrichment returns {}."""
    failed_result = EnrichmentResult(
        success=False,
        validation_errors=["Schema validation error: ..."],
    )
    client = _mock_client(failed_result)
    pipeline = EnrichmentPipeline(llm_client=client)

    result = await pipeline.enrich_entity(
        entity_type="domain",
        canonical_identifier="fail.example.com",
        properties={},
        attribution_confidence=0.5,
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    assert result == {}


# ---------------------------------------------------------------------------
# 10. Prompt wraps content in <external_observation> tags
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_prompt_uses_observation_tags() -> None:
    """Verify the entity context sent to the LLM uses <external_observation> wrapping."""
    parsed = {
        "original_confidence": 0.5,
        "adjusted_confidence": 0.55,
        "adjustment_reasoning": "No change needed.",
        "recommended_tier": "medium",
        "signals_considered": [],
    }
    client = _mock_client(_make_enrichment_result(parsed))
    pipeline = EnrichmentPipeline(llm_client=client)

    await pipeline.enrich_entity(
        entity_type="domain",
        canonical_identifier="tagged.example.com",
        properties={"registrar": "Test Corp"},
        attribution_confidence=0.5,
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    call_args = client.enrich.call_args
    request: EnrichmentRequest = call_args.args[0]
    assert "<external_observation" in request.entity_context
    assert "</external_observation>" in request.entity_context
