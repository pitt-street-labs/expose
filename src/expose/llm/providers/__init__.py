"""LLM provider adapters (per ADR-005).

Each provider is a thin ``httpx``-based adapter implementing :class:`LLMProvider`.
No vendor SDKs are imported; all calls go through ``httpx.AsyncClient``.
"""

from __future__ import annotations

import os

from expose.llm.client import LLMProvider
from expose.llm.providers.anthropic import AnthropicProvider
from expose.llm.providers.gemini import GeminiProvider
from expose.llm.providers.ollama import OllamaProvider
from expose.llm.providers.openai import OpenAIProvider

# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------

# Recognised provider identifiers — must match ``llm_provider`` config values.
_PROVIDER_MAP: dict[str, type] = {
    "ollama": OllamaProvider,
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
}


def create_llm_provider(
    provider_id: str,
    *,
    model: str | None = None,
    endpoint: str | None = None,
) -> LLMProvider:
    """Construct an :class:`LLMProvider` instance from a provider identifier.

    Parameters
    ----------
    provider_id:
        One of ``"ollama"``, ``"anthropic"``, ``"openai"``, ``"gemini"``.
    model:
        Override the default model for the provider.  When ``None`` the
        provider's built-in default is used.
    endpoint:
        Override the base URL / endpoint.  For Ollama this defaults to
        ``http://localhost:11434`` and can also be set via the
        ``EXPOSE_OLLAMA_ENDPOINT`` environment variable.

    Raises
    ------
    ValueError
        If *provider_id* is not a recognised provider name.
    """
    if provider_id not in _PROVIDER_MAP:
        msg = (
            f"Unknown LLM provider: {provider_id!r}. "
            f"Must be one of {sorted(_PROVIDER_MAP)}."
        )
        raise ValueError(msg)

    if provider_id == "ollama":
        kwargs: dict[str, str] = {}
        if model:
            kwargs["model"] = model
        resolved_endpoint = endpoint or os.environ.get(
            "EXPOSE_OLLAMA_ENDPOINT", "http://localhost:11434"
        )
        kwargs["endpoint"] = resolved_endpoint
        return OllamaProvider(**kwargs)

    # Cloud providers take api_key + optional model override.
    # API keys are sourced from environment variables using the
    # EXPOSE_<PROVIDER>_API_KEY convention.
    env_key = f"EXPOSE_{provider_id.upper()}_API_KEY"
    api_key = os.environ.get(env_key, "")

    cls = _PROVIDER_MAP[provider_id]
    kwargs_cloud: dict[str, str] = {"api_key": api_key}
    if model:
        kwargs_cloud["model"] = model
    return cls(**kwargs_cloud)  # type: ignore[return-value]


__all__ = [
    "AnthropicProvider",
    "GeminiProvider",
    "OllamaProvider",
    "OpenAIProvider",
    "create_llm_provider",
]
