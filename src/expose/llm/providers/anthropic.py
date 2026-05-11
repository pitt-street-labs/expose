"""Anthropic provider adapter (per ADR-005)."""

from __future__ import annotations

import time

import httpx

from expose.llm.client import LLMProvider
from expose.llm.models import LLMHealthCheck, LLMRequest, LLMResponse

_INPUT_COST_PER_MTOK = 3.0
_OUTPUT_COST_PER_MTOK = 15.0
_API_BASE = "https://api.anthropic.com"
_DEFAULT_MODEL = "claude-sonnet-4-6"
_SERVER_ERROR_THRESHOLD = 500


class AnthropicProvider(LLMProvider):
    """Anthropic Messages API adapter."""

    provider_id = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        model: str = _DEFAULT_MODEL,
        api_base: str = _API_BASE,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._api_base = api_base

    async def complete(self, request: LLMRequest) -> LLMResponse:
        model = request.model or self._model
        headers = {
            "x-api-key": self._api_key,
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        body: dict[str, object] = {
            "model": model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "messages": [{"role": "user", "content": request.prompt}],
        }
        if request.system_prompt:
            body["system"] = request.system_prompt

        start = time.monotonic()
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._api_base}/v1/messages",
                headers=headers,
                json=body,
                timeout=60.0,
            )
            resp.raise_for_status()
        latency_ms = (time.monotonic() - start) * 1000

        data = resp.json()
        content = data["content"][0]["text"]
        usage = data["usage"]
        input_tokens: int = usage["input_tokens"]
        output_tokens: int = usage["output_tokens"]
        cost = (
            input_tokens * _INPUT_COST_PER_MTOK / 1_000_000
            + output_tokens * _OUTPUT_COST_PER_MTOK / 1_000_000
        )

        return LLMResponse(
            content=content,
            model=model,
            provider_id=self.provider_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            cost_estimate_usd=cost,
        )

    async def health_check(self) -> LLMHealthCheck:
        start = time.monotonic()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self._api_base}/v1/messages",
                    headers={"x-api-key": self._api_key},
                    timeout=10.0,
                )
            latency_ms = (time.monotonic() - start) * 1000
            return LLMHealthCheck(
                provider_id=self.provider_id,
                healthy=resp.status_code < _SERVER_ERROR_THRESHOLD,
                latency_ms=latency_ms,
            )
        except httpx.HTTPError as exc:
            latency_ms = (time.monotonic() - start) * 1000
            return LLMHealthCheck(
                provider_id=self.provider_id,
                healthy=False,
                latency_ms=latency_ms,
                error_message=str(exc),
            )


__all__ = ["AnthropicProvider"]
