"""Stage 4c -- Multimodal screenshot/banner vision analysis.

Provides structured-output analysis of captured screenshots and text
banners using multimodal LLM capabilities.  The VisionAnalyzer identifies
login portals, default pages, technology indicators, and security
misconfigurations that header analysis alone cannot detect.

Per ADR-005, the LLM never invents observations -- it reasons over
captured visual/textual data and produces structured outputs validated
against Pydantic schemas.
"""

from __future__ import annotations

import base64
import json
from typing import TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from expose.llm.client import SafeLLMClient
from expose.llm.models import EnrichmentRequest, EnrichmentResult
from expose.observability.logging import get_logger
from expose.sanitization.canonicalize import wrap_for_llm_prompt

_logger = get_logger("expose.pipeline.vision")

_T = TypeVar("_T", bound=BaseModel)

# Valid page types returned by the LLM analysis.
_VALID_PAGE_TYPES = frozenset({
    "login",
    "default",
    "application",
    "error",
    "parked",
    "unknown",
})

# Valid indicator types for security findings.
_VALID_INDICATOR_TYPES = frozenset({
    "default_credentials_hint",
    "version_disclosure",
    "debug_mode",
    "missing_tls_indicator",
    "admin_panel",
})

# Valid severity levels for security indicators.
_VALID_SEVERITIES = frozenset({"info", "low", "medium", "high"})


# ---------------------------------------------------------------------------
# Response schemas (Pydantic -- structured-output validation)
# ---------------------------------------------------------------------------


class SecurityIndicator(BaseModel):
    """A single security-relevant finding from screenshot/banner analysis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    indicator_type: str  # one of _VALID_INDICATOR_TYPES
    detail: str
    severity: str = "info"  # one of _VALID_SEVERITIES


class ScreenshotAnalysis(BaseModel):
    """LLM output for screenshot/banner analysis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    page_type: str  # one of _VALID_PAGE_TYPES
    technologies_detected: list[str] = Field(default_factory=list)
    security_indicators: list[SecurityIndicator] = Field(default_factory=list)
    visual_confidence: float = Field(ge=0.0, le=1.0)
    description: str = ""


# ---------------------------------------------------------------------------
# Vision analyzer
# ---------------------------------------------------------------------------


class VisionAnalyzer:
    """Analyzes screenshots and banners using multimodal LLM capabilities.

    The analyzer is stateless across calls -- each ``analyze_screenshot``
    invocation is independent.  The ``SafeLLMClient`` handles cost-ceiling
    tracking, retries, and audit logging internally.

    When ``llm_client`` is ``None`` the analyzer degrades gracefully: every
    call returns ``None``, making vision analysis purely opt-in.
    """

    def __init__(self, llm_client: SafeLLMClient | None = None) -> None:
        self._client = llm_client

    async def analyze_screenshot(
        self,
        *,
        screenshot_data: bytes | None = None,
        banner_text: str | None = None,
        url: str,
        headers: dict[str, str] | None = None,
        tenant_id: UUID,
        run_id: UUID,
    ) -> ScreenshotAnalysis | None:
        """Analyze a screenshot or banner for security-relevant indicators.

        Accepts any combination of inputs:

        - ``screenshot_data``: raw screenshot bytes (PNG/JPEG).
        - ``banner_text``: text banner captured from the service.
        - ``headers``: HTTP response headers for additional context.

        At least one of ``screenshot_data`` or ``banner_text`` must be
        provided (along with ``url``).  If neither is available, returns
        ``None`` since there is nothing to analyze.

        Returns a validated ``ScreenshotAnalysis`` or ``None`` on failure
        (graceful degradation -- never crashes the pipeline).
        """
        if self._client is None:
            return None

        # Nothing to analyze if no visual or textual data is provided.
        if screenshot_data is None and banner_text is None and headers is None:
            return None

        prompt = self._build_prompt(
            screenshot_data=screenshot_data,
            banner_text=banner_text,
            url=url,
            headers=headers,
        )

        return await self._call_llm(
            prompt=prompt,
            enrichment_type="screenshot_analysis",
            response_schema=ScreenshotAnalysis,
            tenant_id=tenant_id,
            run_id=run_id,
        )

    def _build_prompt(
        self,
        *,
        screenshot_data: bytes | None,
        banner_text: str | None,
        url: str,
        headers: dict[str, str] | None,
    ) -> str:
        """Assemble the analysis prompt from available data sources."""
        context_parts: list[str] = [f"URL: {url}"]

        if screenshot_data is not None:
            # Encode screenshot as base64 for inclusion in the prompt.
            # The LLM provider adapter handles multimodal presentation.
            b64 = base64.b64encode(screenshot_data).decode("ascii")
            context_parts.append(f"Screenshot (base64): {b64}")

        if banner_text is not None:
            context_parts.append(f"Banner text:\n{banner_text}")

        if headers:
            # Exclude internal underscore-prefixed keys (pipeline metadata).
            public_headers = {
                k: v for k, v in headers.items() if not k.startswith("_")
            }
            if public_headers:
                context_parts.append(
                    f"HTTP response headers: {json.dumps(public_headers, default=str)}"
                )

        raw_context = "\n".join(context_parts)
        wrapped = wrap_for_llm_prompt(raw_context, source="screenshot_analysis")

        return (
            "Analyze this web page screenshot, banner, and/or HTTP headers to "
            "identify the page type, technologies, and security-relevant "
            "indicators.  Return a JSON object with fields: "
            "page_type (one of: login, default, application, error, parked, "
            "unknown), technologies_detected (list of strings), "
            "security_indicators (list of objects with indicator_type, detail, "
            "severity), visual_confidence (float 0-1), "
            "description (string).\n\n"
            "For security_indicators, each object must have: "
            "indicator_type (one of: default_credentials_hint, "
            "version_disclosure, debug_mode, missing_tls_indicator, "
            "admin_panel), detail (string describing the finding), "
            "severity (one of: info, low, medium, high).\n\n"
            f"{wrapped}"
        )

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
        pipeline -- the analysis pass simply produces no output.
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
                "vision.llm_error",
                enrichment_type=enrichment_type,
                tenant_id=str(tenant_id),
                run_id=str(run_id),
                exc_info=True,
            )
            return None

        if not result.success:
            _logger.info(
                "vision.validation_failed",
                enrichment_type=enrichment_type,
                errors=result.validation_errors,
            )
            return None

        # result.parsed_response is a plain dict -- re-validate through the
        # target schema to get a typed Pydantic model.
        return response_schema.model_validate(result.parsed_response)


__all__ = [
    "ScreenshotAnalysis",
    "SecurityIndicator",
    "VisionAnalyzer",
]
