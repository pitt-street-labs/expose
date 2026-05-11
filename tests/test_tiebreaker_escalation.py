"""Tests for tiebreaker escalation policy (issue #15).

Validates that SafeLLMClient correctly resolves disagreements between primary
and tiebreaker LLM providers according to the configured TiebreakerPolicy.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from pydantic import BaseModel, ConfigDict

from expose.llm.client import (
    LLMProvider,
    SafeLLMClient,
    _detect_disagreement,
    _extract_confidence,
)
from expose.llm.models import (
    EnrichmentRequest,
    EnrichmentResult,
    LLMResponse,
    TiebreakerPolicy,
    TiebreakerResolution,
)

# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------


class _SampleOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    label: str
    confidence: float


def _make_provider(
    *,
    provider_id: str = "mock",
    responses: list[LLMResponse | Exception] | None = None,
) -> LLMProvider:
    provider = MagicMock(spec=LLMProvider)
    provider.provider_id = provider_id

    if responses is not None:
        side_effects: list[Any] = []
        for r in responses:
            if isinstance(r, Exception):
                side_effects.append(r)
            else:
                side_effects.append(r)
        provider.complete = AsyncMock(side_effect=side_effects)
    else:
        provider.complete = AsyncMock()

    provider.health_check = AsyncMock()
    return provider


def _make_response(
    content: str,
    *,
    provider_id: str = "mock",
    cost: float = 0.001,
) -> LLMResponse:
    return LLMResponse(
        content=content,
        model="test-model",
        provider_id=provider_id,
        input_tokens=100,
        output_tokens=50,
        latency_ms=42.0,
        cost_estimate_usd=cost,
    )


def _make_request() -> EnrichmentRequest:
    return EnrichmentRequest(
        tenant_id=uuid4(),
        run_id=uuid4(),
        entity_context=(
            "<external_observation source='test'>data</external_observation>"
        ),
        enrichment_type="attribution_sanity_check",
    )


# ---------------------------------------------------------------------------
# TiebreakerPolicy enum
# ---------------------------------------------------------------------------


def test_tiebreaker_policy_enum_values() -> None:
    """All four policy values are present with expected string representations."""
    assert TiebreakerPolicy.PRIMARY_WINS == "primary_wins"
    assert TiebreakerPolicy.CONSERVATIVE == "conservative"
    assert TiebreakerPolicy.HIGHER_CONFIDENCE == "higher_confidence"
    assert TiebreakerPolicy.ESCALATE == "escalate"
    assert len(TiebreakerPolicy) == 4


# ---------------------------------------------------------------------------
# TiebreakerResolution model validation
# ---------------------------------------------------------------------------


def test_tiebreaker_resolution_round_trip() -> None:
    """TiebreakerResolution validates, serialises, and is frozen."""
    res = TiebreakerResolution(
        policy=TiebreakerPolicy.CONSERVATIVE,
        primary_used=False,
        tiebreaker_used=True,
        reason="test reason",
        disagreement_detected=True,
    )
    assert res.policy == TiebreakerPolicy.CONSERVATIVE
    assert res.primary_used is False
    assert res.tiebreaker_used is True
    assert res.reason == "test reason"
    assert res.disagreement_detected is True

    # Frozen — mutation should raise
    with pytest.raises(Exception):  # noqa: B017
        res.reason = "mutated"  # type: ignore[misc]


def test_tiebreaker_resolution_default_disagreement() -> None:
    """disagreement_detected defaults to False."""
    res = TiebreakerResolution(
        policy=TiebreakerPolicy.PRIMARY_WINS,
        primary_used=True,
        tiebreaker_used=False,
        reason="ok",
    )
    assert res.disagreement_detected is False


# ---------------------------------------------------------------------------
# EnrichmentResult new fields
# ---------------------------------------------------------------------------


def test_enrichment_result_defaults() -> None:
    """New fields on EnrichmentResult default to None / False."""
    result = EnrichmentResult(success=True)
    assert result.needs_review is False
    assert result.tiebreaker_resolution is None


# ---------------------------------------------------------------------------
# Default policy is PRIMARY_WINS
# ---------------------------------------------------------------------------


async def test_default_policy_is_primary_wins() -> None:
    """SafeLLMClient defaults to PRIMARY_WINS when no policy is specified."""
    primary_json = json.dumps({"label": "owned", "confidence": 0.9})
    tb_json = json.dumps({"label": "not_owned", "confidence": 0.8})

    primary = _make_provider(
        provider_id="primary",
        responses=[_make_response(primary_json, provider_id="primary")],
    )
    tiebreaker = _make_provider(
        provider_id="tiebreaker",
        responses=[_make_response(tb_json, provider_id="tiebreaker")],
    )
    client = SafeLLMClient(
        primary,
        tiebreaker_provider=tiebreaker,
        max_retries=0,
    )

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is True
    assert result.parsed_response is not None
    assert result.parsed_response["label"] == "owned"
    assert result.tiebreaker_resolution is not None
    assert result.tiebreaker_resolution.policy == TiebreakerPolicy.PRIMARY_WINS


# ---------------------------------------------------------------------------
# PRIMARY_WINS uses primary even when tiebreaker differs
# ---------------------------------------------------------------------------


async def test_primary_wins_uses_primary_result() -> None:
    """PRIMARY_WINS always selects the primary result, recording disagreement."""
    primary_json = json.dumps({"label": "owned", "confidence": 0.6})
    tb_json = json.dumps({"label": "not_owned", "confidence": 0.95})

    primary = _make_provider(
        provider_id="primary",
        responses=[_make_response(primary_json, provider_id="primary")],
    )
    tiebreaker = _make_provider(
        provider_id="tiebreaker",
        responses=[_make_response(tb_json, provider_id="tiebreaker")],
    )
    client = SafeLLMClient(
        primary,
        tiebreaker_provider=tiebreaker,
        tiebreaker_policy=TiebreakerPolicy.PRIMARY_WINS,
        max_retries=0,
    )

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is True
    assert result.parsed_response is not None
    assert result.parsed_response["label"] == "owned"
    assert result.tiebreaker_resolution is not None
    assert result.tiebreaker_resolution.primary_used is True
    assert result.tiebreaker_resolution.tiebreaker_used is False
    assert result.tiebreaker_resolution.disagreement_detected is True
    assert result.needs_review is False


# ---------------------------------------------------------------------------
# CONSERVATIVE picks lower confidence
# ---------------------------------------------------------------------------


async def test_conservative_picks_lower_confidence() -> None:
    """CONSERVATIVE selects the result with lower confidence (more cautious)."""
    primary_json = json.dumps({"label": "owned", "confidence": 0.9})
    tb_json = json.dumps({"label": "owned", "confidence": 0.4})

    primary = _make_provider(
        provider_id="primary",
        responses=[_make_response(primary_json, provider_id="primary")],
    )
    tiebreaker = _make_provider(
        provider_id="tiebreaker",
        responses=[_make_response(tb_json, provider_id="tiebreaker")],
    )
    client = SafeLLMClient(
        primary,
        tiebreaker_provider=tiebreaker,
        tiebreaker_policy=TiebreakerPolicy.CONSERVATIVE,
        max_retries=0,
    )

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is True
    assert result.parsed_response is not None
    # Tiebreaker has lower confidence (0.4 < 0.9), so it should be selected.
    assert result.parsed_response["confidence"] == pytest.approx(0.4)
    assert result.tiebreaker_resolution is not None
    assert result.tiebreaker_resolution.tiebreaker_used is True
    assert result.tiebreaker_resolution.primary_used is False


async def test_conservative_picks_primary_when_lower() -> None:
    """CONSERVATIVE selects primary when primary has lower confidence."""
    primary_json = json.dumps({"label": "owned", "confidence": 0.3})
    tb_json = json.dumps({"label": "owned", "confidence": 0.8})

    primary = _make_provider(
        provider_id="primary",
        responses=[_make_response(primary_json, provider_id="primary")],
    )
    tiebreaker = _make_provider(
        provider_id="tiebreaker",
        responses=[_make_response(tb_json, provider_id="tiebreaker")],
    )
    client = SafeLLMClient(
        primary,
        tiebreaker_provider=tiebreaker,
        tiebreaker_policy=TiebreakerPolicy.CONSERVATIVE,
        max_retries=0,
    )

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is True
    assert result.parsed_response is not None
    assert result.parsed_response["confidence"] == pytest.approx(0.3)
    assert result.tiebreaker_resolution is not None
    assert result.tiebreaker_resolution.primary_used is True


# ---------------------------------------------------------------------------
# HIGHER_CONFIDENCE picks higher confidence
# ---------------------------------------------------------------------------


async def test_higher_confidence_picks_higher() -> None:
    """HIGHER_CONFIDENCE selects the result with higher confidence."""
    primary_json = json.dumps({"label": "owned", "confidence": 0.5})
    tb_json = json.dumps({"label": "owned", "confidence": 0.95})

    primary = _make_provider(
        provider_id="primary",
        responses=[_make_response(primary_json, provider_id="primary")],
    )
    tiebreaker = _make_provider(
        provider_id="tiebreaker",
        responses=[_make_response(tb_json, provider_id="tiebreaker")],
    )
    client = SafeLLMClient(
        primary,
        tiebreaker_provider=tiebreaker,
        tiebreaker_policy=TiebreakerPolicy.HIGHER_CONFIDENCE,
        max_retries=0,
    )

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is True
    assert result.parsed_response is not None
    assert result.parsed_response["confidence"] == pytest.approx(0.95)
    assert result.tiebreaker_resolution is not None
    assert result.tiebreaker_resolution.tiebreaker_used is True
    assert result.tiebreaker_resolution.primary_used is False


async def test_higher_confidence_picks_primary_when_higher() -> None:
    """HIGHER_CONFIDENCE selects primary when primary has higher confidence."""
    primary_json = json.dumps({"label": "owned", "confidence": 0.99})
    tb_json = json.dumps({"label": "owned", "confidence": 0.6})

    primary = _make_provider(
        provider_id="primary",
        responses=[_make_response(primary_json, provider_id="primary")],
    )
    tiebreaker = _make_provider(
        provider_id="tiebreaker",
        responses=[_make_response(tb_json, provider_id="tiebreaker")],
    )
    client = SafeLLMClient(
        primary,
        tiebreaker_provider=tiebreaker,
        tiebreaker_policy=TiebreakerPolicy.HIGHER_CONFIDENCE,
        max_retries=0,
    )

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is True
    assert result.parsed_response is not None
    assert result.parsed_response["confidence"] == pytest.approx(0.99)
    assert result.tiebreaker_resolution is not None
    assert result.tiebreaker_resolution.primary_used is True


# ---------------------------------------------------------------------------
# ESCALATE flags for human review
# ---------------------------------------------------------------------------


async def test_escalate_flags_needs_review() -> None:
    """ESCALATE sets needs_review=True and records both results."""
    primary_json = json.dumps({"label": "owned", "confidence": 0.9})
    tb_json = json.dumps({"label": "not_owned", "confidence": 0.85})

    primary = _make_provider(
        provider_id="primary",
        responses=[_make_response(primary_json, provider_id="primary")],
    )
    tiebreaker = _make_provider(
        provider_id="tiebreaker",
        responses=[_make_response(tb_json, provider_id="tiebreaker")],
    )
    client = SafeLLMClient(
        primary,
        tiebreaker_provider=tiebreaker,
        tiebreaker_policy=TiebreakerPolicy.ESCALATE,
        max_retries=0,
    )

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is True
    assert result.needs_review is True
    assert result.tiebreaker_resolution is not None
    assert result.tiebreaker_resolution.policy == TiebreakerPolicy.ESCALATE
    assert result.tiebreaker_resolution.primary_used is True
    assert result.tiebreaker_resolution.tiebreaker_used is True
    assert result.tiebreaker_resolution.disagreement_detected is True


# ---------------------------------------------------------------------------
# No tiebreaker provider -> no resolution
# ---------------------------------------------------------------------------


async def test_no_tiebreaker_provider_no_resolution() -> None:
    """Without a tiebreaker provider, tiebreaker_resolution stays None."""
    primary_json = json.dumps({"label": "owned", "confidence": 0.9})
    primary = _make_provider(
        provider_id="primary",
        responses=[_make_response(primary_json, provider_id="primary")],
    )
    client = SafeLLMClient(
        primary,
        tiebreaker_policy=TiebreakerPolicy.HIGHER_CONFIDENCE,
        max_retries=0,
    )

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is True
    assert result.tiebreaker_resolution is None
    assert result.tiebreaker_used is False


# ---------------------------------------------------------------------------
# Tiebreaker fails -> primary used, no resolution
# ---------------------------------------------------------------------------


async def test_tiebreaker_call_fails_returns_primary_no_resolution() -> None:
    """When tiebreaker raises, primary result stands with no resolution record."""
    primary_json = json.dumps({"label": "owned", "confidence": 0.9})
    primary = _make_provider(
        provider_id="primary",
        responses=[_make_response(primary_json, provider_id="primary")],
    )
    tiebreaker = _make_provider(
        provider_id="tiebreaker",
        responses=[RuntimeError("tiebreaker down")],
    )
    client = SafeLLMClient(
        primary,
        tiebreaker_provider=tiebreaker,
        tiebreaker_policy=TiebreakerPolicy.CONSERVATIVE,
        max_retries=0,
    )

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is True
    assert result.parsed_response is not None
    assert result.parsed_response["label"] == "owned"
    assert result.tiebreaker_resolution is None
    assert result.tiebreaker_used is False


# ---------------------------------------------------------------------------
# Primary fails -> tiebreaker used (existing behavior preserved)
# ---------------------------------------------------------------------------


async def test_primary_fails_tiebreaker_used_existing_behavior() -> None:
    """When primary throws, tiebreaker is used as fallback (pre-existing behavior)."""
    tb_json = json.dumps({"label": "fallback", "confidence": 0.7})
    primary = _make_provider(
        provider_id="primary",
        responses=[RuntimeError("primary down")],
    )
    tiebreaker = _make_provider(
        provider_id="tiebreaker",
        responses=[_make_response(tb_json, provider_id="tiebreaker")],
    )
    client = SafeLLMClient(
        primary,
        tiebreaker_provider=tiebreaker,
        tiebreaker_policy=TiebreakerPolicy.ESCALATE,
        max_retries=0,
    )

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is True
    assert result.tiebreaker_used is True
    assert result.parsed_response is not None
    assert result.parsed_response["label"] == "fallback"
    # No resolution — policy only applies when BOTH providers return valid results.
    assert result.tiebreaker_resolution is None


# ---------------------------------------------------------------------------
# Disagreement detection
# ---------------------------------------------------------------------------


def test_detect_disagreement_true() -> None:
    """Disagreement detected when a decision key differs."""
    primary = {"label": "owned", "confidence": 0.9}
    tiebreaker = {"label": "not_owned", "confidence": 0.85}
    assert _detect_disagreement(primary, tiebreaker) is True


def test_detect_disagreement_false() -> None:
    """No disagreement when decision keys match."""
    primary = {"label": "owned", "confidence": 0.9}
    tiebreaker = {"label": "owned", "confidence": 0.5}
    assert _detect_disagreement(primary, tiebreaker) is False


def test_detect_disagreement_no_shared_keys() -> None:
    """No disagreement when results share no decision keys."""
    primary = {"foo": 1}
    tiebreaker = {"bar": 2}
    assert _detect_disagreement(primary, tiebreaker) is False


# ---------------------------------------------------------------------------
# Confidence extraction
# ---------------------------------------------------------------------------


def test_extract_confidence_from_confidence_key() -> None:
    assert _extract_confidence({"confidence": 0.75}) == pytest.approx(0.75)


def test_extract_confidence_fallback_to_score() -> None:
    assert _extract_confidence({"score": 0.6}) == pytest.approx(0.6)


def test_extract_confidence_missing() -> None:
    assert _extract_confidence({"other": "val"}) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# Resolution recorded in EnrichmentResult
# ---------------------------------------------------------------------------


async def test_resolution_recorded_in_result() -> None:
    """The tiebreaker_resolution field captures the full decision record."""
    primary_json = json.dumps({"label": "owned", "confidence": 0.7})
    tb_json = json.dumps({"label": "owned", "confidence": 0.9})

    primary = _make_provider(
        provider_id="primary",
        responses=[_make_response(primary_json, provider_id="primary")],
    )
    tiebreaker = _make_provider(
        provider_id="tiebreaker",
        responses=[_make_response(tb_json, provider_id="tiebreaker")],
    )
    client = SafeLLMClient(
        primary,
        tiebreaker_provider=tiebreaker,
        tiebreaker_policy=TiebreakerPolicy.HIGHER_CONFIDENCE,
        max_retries=0,
    )

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.tiebreaker_resolution is not None
    res = result.tiebreaker_resolution
    assert res.policy == TiebreakerPolicy.HIGHER_CONFIDENCE
    assert res.tiebreaker_used is True
    assert res.primary_used is False
    assert "HIGHER_CONFIDENCE" in res.reason
    assert "0.7000" in res.reason
    assert "0.9000" in res.reason
    assert res.disagreement_detected is False
