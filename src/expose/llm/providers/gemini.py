"""Gemini provider adapter (per ADR-005)."""

from __future__ import annotations

import time

import httpx

from expose.llm.client import LLMProvider
from expose.llm.models import LLMHealthCheck, LLMRequest, LLMResponse

_INPUT_COST_PER_MTOK = 0.075
_OUTPUT_COST_PER_MTOK = 0.30
_API_BASE = "https://generativelanguage.googleapis.com"
_DEFAULT_MODEL = "gemini-2.5-flash"
_SERVER_ERROR_THRESHOLD = 500


class GeminiProvider(LLMProvider):
    """Google Gemini generateContent API adapter."""

    provider_id = "gemini"

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

    def _build_url(self, model: str) -> str:
        return f"{self._api_base}/v1beta/models/{model}:generateContent"

    async def complete(self, request: LLMRequest) -> LLMResponse:
        model = request.model or self._model
        url = self._build_url(model)

        parts: list[dict[str, str]] = []
        if request.system_prompt:
            parts.append({"text": request.system_prompt})
        parts.append({"text": request.prompt})

        body: dict[str, object] = {
            "contents": [{"parts": parts}],
            "generationConfig": {
                "maxOutputTokens": request.max_tokens,
                "temperature": request.temperature,
                "responseMimeType": "application/json",
            },
        }

        start = time.monotonic()
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url,
                params={"key": self._api_key},
                json=body,
                timeout=60.0,
            )
            resp.raise_for_status()
        latency_ms = (time.monotonic() - start) * 1000

        data = resp.json()
        content: str = data["candidates"][0]["content"]["parts"][0]["text"]
        usage = data.get("usageMetadata", {})
        input_tokens: int = usage.get("promptTokenCount", 0)
        output_tokens: int = usage.get("candidatesTokenCount", 0)
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
                    f"{self._api_base}/v1beta/models",
                    params={"key": self._api_key},
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


__all__ = ["GeminiProvider"]
