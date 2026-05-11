"""Tests for LLM provider adapters (per ADR-005).

Seven tests covering request construction, health checks, and provider identity
for all four adapters. All HTTP calls are mocked via ``httpx.AsyncClient``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from expose.llm.models import LLMRequest
from expose.llm.providers.anthropic import AnthropicProvider
from expose.llm.providers.gemini import GeminiProvider
from expose.llm.providers.ollama import OllamaProvider
from expose.llm.providers.openai import OpenAIProvider


def _llm_request(prompt: str = "test", system: str = "sys") -> LLMRequest:
    return LLMRequest(
        prompt=prompt,
        system_prompt=system,
        model="",
        max_tokens=256,
        temperature=0.0,
        response_format="json",
    )


def _mock_response(data: dict[str, object], status_code: int = 200) -> httpx.Response:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


def _mock_async_client(response: httpx.Response) -> MagicMock:
    client = AsyncMock()
    client.post = AsyncMock(return_value=response)
    client.get = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


async def test_anthropic_request_headers() -> None:
    api_response = _mock_response({
        "content": [{"text": '{"result": true}'}],
        "usage": {"input_tokens": 10, "output_tokens": 5},
    })
    mock_client = _mock_async_client(api_response)

    with patch("expose.llm.providers.anthropic.httpx.AsyncClient", return_value=mock_client):
        provider = AnthropicProvider(api_key="sk-test-key")
        result = await provider.complete(_llm_request())

    call_kwargs = mock_client.post.call_args
    headers = call_kwargs[1]["headers"]
    assert headers["x-api-key"] == "sk-test-key"
    assert headers["anthropic-version"] == "2023-06-01"
    assert result.provider_id == "anthropic"


async def test_openai_request_body() -> None:
    api_response = _mock_response({
        "choices": [{"message": {"content": '{"result": true}'}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    })
    mock_client = _mock_async_client(api_response)

    with patch("expose.llm.providers.openai.httpx.AsyncClient", return_value=mock_client):
        provider = OpenAIProvider(api_key="sk-openai-key")
        result = await provider.complete(_llm_request())

    call_kwargs = mock_client.post.call_args
    body = call_kwargs[1]["json"]
    assert "messages" in body
    assert body["response_format"] == {"type": "json_object"}
    assert body["messages"][0]["role"] == "system"
    assert body["messages"][1]["role"] == "user"
    assert result.provider_id == "openai"


async def test_gemini_url_contains_model() -> None:
    api_response = _mock_response({
        "candidates": [{"content": {"parts": [{"text": '{"result": true}'}]}}],
        "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5},
    })
    mock_client = _mock_async_client(api_response)

    with patch("expose.llm.providers.gemini.httpx.AsyncClient", return_value=mock_client):
        provider = GeminiProvider(api_key="gemini-key", model="gemini-2.5-flash")
        result = await provider.complete(_llm_request())

    call_args = mock_client.post.call_args
    url = call_args[0][0]
    assert "gemini-2.5-flash" in url
    assert ":generateContent" in url
    assert result.provider_id == "gemini"


async def test_ollama_local_endpoint_zero_cost() -> None:
    api_response = _mock_response({
        "response": '{"result": true}',
        "prompt_eval_count": 10,
        "eval_count": 5,
    })
    mock_client = _mock_async_client(api_response)

    with patch("expose.llm.providers.ollama.httpx.AsyncClient", return_value=mock_client):
        provider = OllamaProvider()
        result = await provider.complete(_llm_request())

    call_args = mock_client.post.call_args
    url = call_args[0][0]
    assert "localhost:11434" in url
    assert result.cost_estimate_usd == 0.0
    assert result.provider_id == "ollama"


async def test_provider_health_check_success() -> None:
    api_response = _mock_response({"models": []}, status_code=200)
    mock_client = _mock_async_client(api_response)

    with patch("expose.llm.providers.ollama.httpx.AsyncClient", return_value=mock_client):
        provider = OllamaProvider()
        health = await provider.health_check()

    assert health.healthy is True
    assert health.provider_id == "ollama"
    assert health.latency_ms is not None
    assert health.error_message is None


async def test_provider_health_check_failure() -> None:
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("expose.llm.providers.anthropic.httpx.AsyncClient", return_value=mock_client):
        provider = AnthropicProvider(api_key="sk-test")
        health = await provider.health_check()

    assert health.healthy is False
    assert health.error_message is not None
    assert health.provider_id == "anthropic"


async def test_each_provider_has_correct_id() -> None:
    assert AnthropicProvider(api_key="x").provider_id == "anthropic"
    assert OpenAIProvider(api_key="x").provider_id == "openai"
    assert GeminiProvider(api_key="x").provider_id == "gemini"
    assert OllamaProvider().provider_id == "ollama"
