"""Tests for SafeLLMClient (per ADR-005).

Eight tests covering enrichment happy path, retry logic, cost ceiling,
tiebreaker escalation, round-trip field propagation, and audit logging.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from pydantic import BaseModel, ConfigDict

from expose.llm.client import LLMProvider, SafeLLMClient
from expose.llm.models import (
    CostCeilingExceededError,
    EnrichmentRequest,
    LLMRequest,
    LLMResponse,
)


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
        entity_context="<external_observation source='test'>data</external_observation>",
        enrichment_type="attribution_sanity_check",
    )


async def test_successful_enrichment() -> None:
    valid_json = json.dumps({"label": "owned", "confidence": 0.95})
    provider = _make_provider(responses=[_make_response(valid_json)])
    client = SafeLLMClient(provider)

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is True
    assert result.parsed_response == {"label": "owned", "confidence": 0.95}
    assert result.retries_used == 0
    assert result.raw_response is not None


async def test_validation_failure_with_retry() -> None:
    invalid_json = '{"wrong_field": true}'
    valid_json = json.dumps({"label": "owned", "confidence": 0.85})
    provider = _make_provider(
        responses=[
            _make_response(invalid_json),
            _make_response(valid_json),
        ]
    )
    client = SafeLLMClient(provider)

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is True
    assert result.retries_used == 1
    assert result.parsed_response == {"label": "owned", "confidence": 0.85}


async def test_all_retries_exhausted() -> None:
    bad = '{"bad": true}'
    provider = _make_provider(
        responses=[
            _make_response(bad),
            _make_response(bad),
            _make_response(bad),
        ]
    )
    client = SafeLLMClient(provider, max_retries=2)

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is False
    assert len(result.validation_errors) == 3
    assert result.retries_used == 2


async def test_cost_ceiling_exceeded() -> None:
    valid_json = json.dumps({"label": "x", "confidence": 0.5})
    provider = _make_provider(
        responses=[
            _make_response(valid_json, cost=6.0),
            _make_response(valid_json, cost=6.0),
        ]
    )
    client = SafeLLMClient(provider, cost_ceiling_per_run=10.0)

    result1 = await client.enrich(_make_request(), _SampleOutput)
    assert result1.success is True

    with pytest.raises(CostCeilingExceededError):
        await client.enrich(_make_request(), _SampleOutput)


async def test_cost_tracking_accumulates() -> None:
    valid_json = json.dumps({"label": "a", "confidence": 0.9})
    provider = _make_provider(
        responses=[
            _make_response(valid_json, cost=1.5),
            _make_response(valid_json, cost=2.5),
        ]
    )
    client = SafeLLMClient(provider, cost_ceiling_per_run=100.0)

    await client.enrich(_make_request(), _SampleOutput)
    await client.enrich(_make_request(), _SampleOutput)

    assert client.cost_tracker.total == pytest.approx(4.0)


async def test_tiebreaker_provider_on_primary_failure() -> None:
    valid_json = json.dumps({"label": "tb", "confidence": 0.7})
    primary = _make_provider(
        provider_id="primary",
        responses=[RuntimeError("primary down")],
    )
    tiebreaker = _make_provider(
        provider_id="tiebreaker",
        responses=[_make_response(valid_json, provider_id="tiebreaker")],
    )
    client = SafeLLMClient(primary, tiebreaker_provider=tiebreaker, max_retries=0)

    result = await client.enrich(_make_request(), _SampleOutput)

    assert result.success is True
    assert result.tiebreaker_used is True
    assert result.parsed_response == {"label": "tb", "confidence": 0.7}


async def test_enrichment_request_round_trip() -> None:
    tenant_id = uuid4()
    run_id = uuid4()
    req = EnrichmentRequest(
        tenant_id=tenant_id,
        run_id=run_id,
        entity_context="<external_observation source='http'>test</external_observation>",
        enrichment_type="tech_stack_inference",
    )

    valid_json = json.dumps({"label": "ok", "confidence": 1.0})
    provider = _make_provider(responses=[_make_response(valid_json)])
    client = SafeLLMClient(provider)

    result = await client.enrich(req, _SampleOutput)

    assert result.success is True
    call_args = provider.complete.call_args[0][0]
    assert isinstance(call_args, LLMRequest)
    assert req.entity_context in call_args.prompt


async def test_audit_logging_called() -> None:
    valid_json = json.dumps({"label": "ok", "confidence": 0.99})
    provider = _make_provider(responses=[_make_response(valid_json)])
    client = SafeLLMClient(provider)

    with patch("expose.llm.client._logger") as mock_logger:
        await client.enrich(_make_request(), _SampleOutput)

    mock_logger.info.assert_called_once()
    call_kwargs = mock_logger.info.call_args
    assert call_kwargs[0][0] == "llm.call"
    assert "provider_id" in call_kwargs[1]
    assert "tenant_id" in call_kwargs[1]
    assert "cost_estimate_usd" in call_kwargs[1]
