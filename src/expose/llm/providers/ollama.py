"""Ollama provider adapter (per ADR-005)."""

from __future__ import annotations

import time

import httpx

from expose.llm.client import LLMProvider
from expose.llm.models import LLMHealthCheck, LLMRequest, LLMResponse

_DEFAULT_MODEL = "qwen2.5:7b"
_DEFAULT_ENDPOINT = "http://localhost:11434"
_SERVER_ERROR_THRESHOLD = 500


class OllamaProvider(LLMProvider):
    """Local Ollama generate API adapter. Cost is always $0."""

    provider_id = "ollama"

    def __init__(
        self,
        *,
        model: str = _DEFAULT_MODEL,
        endpoint: str = _DEFAULT_ENDPOINT,
    ) -> None:
        self._model = model
        self._endpoint = endpoint

    async def complete(self, request: LLMRequest) -> LLMResponse:
        model = request.model or self._model

        system_content = request.system_prompt or ""
        body: dict[str, object] = {
            "model": model,
            "prompt": request.prompt,
            "system": system_content,
            "stream": False,
            "format": "json",
        }

        start = time.monotonic()
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._endpoint}/api/generate",
                json=body,
                timeout=120.0,
            )
            resp.raise_for_status()
        latency_ms = (time.monotonic() - start) * 1000

        data = resp.json()
        content: str = data["response"]
        input_tokens: int = data.get("prompt_eval_count", 0)
        output_tokens: int = data.get("eval_count", 0)

        return LLMResponse(
            content=content,
            model=model,
            provider_id=self.provider_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            cost_estimate_usd=0.0,
        )

    async def health_check(self) -> LLMHealthCheck:
        start = time.monotonic()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self._endpoint}/api/tags",
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


__all__ = ["OllamaProvider"]
