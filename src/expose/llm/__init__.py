"""LLM integration layer for EXPOSE (per ADR-005).

Multi-provider abstraction with safety wrapper. All LLM calls go through
:class:`SafeLLMClient`, which enforces sanitization integrity, structured-output
validation, per-call audit logging, per-run cost ceiling, retry logic, and
optional tie-breaker escalation.

Sub-packages:

- ``expose.llm.client`` — :class:`LLMProvider` ABC + :class:`SafeLLMClient` wrapper.
- ``expose.llm.models`` — request/response Pydantic types.
- ``expose.llm.providers`` — four provider adapters (Anthropic, OpenAI, Gemini, Ollama).
"""

from expose.llm.client import LLMProvider, SafeLLMClient
from expose.llm.models import (
    CostCeilingExceededError,
    CostTracker,
    EnrichmentRequest,
    EnrichmentResult,
    LLMHealthCheck,
    LLMRequest,
    LLMResponse,
    TiebreakerPolicy,
    TiebreakerResolution,
)

__all__ = [
    "CostCeilingExceededError",
    "CostTracker",
    "EnrichmentRequest",
    "EnrichmentResult",
    "LLMHealthCheck",
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "SafeLLMClient",
    "TiebreakerPolicy",
    "TiebreakerResolution",
]
