"""Tests for Stage 4c multimodal screenshot/banner vision analysis."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from pydantic import ValidationError

from expose.llm.client import SafeLLMClient
from expose.llm.models import EnrichmentRequest, EnrichmentResult, LLMResponse
from expose.pipeline.vision import (
    ScreenshotAnalysis,
    SecurityIndicator,
    VisionAnalyzer,
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


def _sample_analysis_dict(**overrides: object) -> dict:
    """Return a valid ScreenshotAnalysis dict, with optional overrides."""
    base: dict = {
        "page_type": "login",
        "technologies_detected": ["Apache", "PHP"],
        "security_indicators": [
            {
                "indicator_type": "default_credentials_hint",
                "detail": "Default admin/admin credentials shown on page.",
                "severity": "high",
            }
        ],
        "visual_confidence": 0.85,
        "description": "Login page with default credential warning.",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# 1. No client -> None
# ---------------------------------------------------------------------------


async def test_vision_analyzer_no_client() -> None:
    """When no LLM client is configured, analyze_screenshot returns None."""
    analyzer = VisionAnalyzer(llm_client=None)
    result = await analyzer.analyze_screenshot(
        screenshot_data=b"\x89PNG",
        url="https://example.com",
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )
    assert result is None


# ---------------------------------------------------------------------------
# 2. Screenshot analysis with mock LLM client
# ---------------------------------------------------------------------------


async def test_analyze_screenshot_with_mock_client() -> None:
    """Mock LLM client returns parsed ScreenshotAnalysis."""
    parsed = _sample_analysis_dict()
    client = _mock_client(_make_enrichment_result(parsed))
    analyzer = VisionAnalyzer(llm_client=client)

    result = await analyzer.analyze_screenshot(
        screenshot_data=b"\x89PNG\r\n\x1a\n",
        url="https://login.example.com",
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    assert result is not None
    assert result.page_type == "login"
    assert "Apache" in result.technologies_detected
    assert "PHP" in result.technologies_detected
    assert len(result.security_indicators) == 1
    assert result.security_indicators[0].indicator_type == "default_credentials_hint"
    assert result.security_indicators[0].severity == "high"
    assert result.visual_confidence == pytest.approx(0.85)
    assert result.description != ""

    # Verify the client was called with correct enrichment type.
    call_args = client.enrich.call_args
    request: EnrichmentRequest = call_args.args[0]
    assert request.enrichment_type == "screenshot_analysis"


# ---------------------------------------------------------------------------
# 3. ScreenshotAnalysis model validation -- visual_confidence bounds
# ---------------------------------------------------------------------------


def test_screenshot_analysis_confidence_bounds() -> None:
    """visual_confidence must be between 0.0 and 1.0."""
    # Valid bounds
    low = ScreenshotAnalysis(page_type="unknown", visual_confidence=0.0)
    assert low.visual_confidence == 0.0

    high = ScreenshotAnalysis(page_type="unknown", visual_confidence=1.0)
    assert high.visual_confidence == 1.0

    # Out of bounds
    with pytest.raises(ValidationError):
        ScreenshotAnalysis(page_type="unknown", visual_confidence=-0.1)

    with pytest.raises(ValidationError):
        ScreenshotAnalysis(page_type="unknown", visual_confidence=1.1)


# ---------------------------------------------------------------------------
# 4. ScreenshotAnalysis and SecurityIndicator are frozen
# ---------------------------------------------------------------------------


def test_models_frozen() -> None:
    """All vision response models are frozen (immutable)."""
    analysis = ScreenshotAnalysis(
        page_type="login",
        visual_confidence=0.8,
        description="test",
    )
    with pytest.raises(ValidationError):
        analysis.page_type = "default"  # type: ignore[misc]

    indicator = SecurityIndicator(
        indicator_type="version_disclosure",
        detail="Apache/2.4.41 visible",
    )
    with pytest.raises(ValidationError):
        indicator.severity = "high"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 5. SecurityIndicator model validation
# ---------------------------------------------------------------------------


def test_security_indicator_defaults() -> None:
    """SecurityIndicator has sensible defaults."""
    indicator = SecurityIndicator(
        indicator_type="debug_mode",
        detail="Debug toolbar visible in page footer.",
    )
    assert indicator.severity == "info"
    assert indicator.detail == "Debug toolbar visible in page footer."


def test_security_indicator_extra_fields_forbidden() -> None:
    """Extra fields are rejected by ConfigDict(extra='forbid')."""
    with pytest.raises(ValidationError):
        SecurityIndicator(
            indicator_type="debug_mode",
            detail="test",
            unexpected_field="boom",  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# 6. Banner-only analysis (no screenshot bytes)
# ---------------------------------------------------------------------------


async def test_banner_only_analysis() -> None:
    """Analysis works with only banner text, no screenshot data."""
    parsed = _sample_analysis_dict(page_type="default")
    client = _mock_client(_make_enrichment_result(parsed))
    analyzer = VisionAnalyzer(llm_client=client)

    result = await analyzer.analyze_screenshot(
        banner_text="Apache/2.4.41 (Ubuntu) Server at example.com Port 80",
        url="https://example.com",
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    assert result is not None
    assert result.page_type == "default"

    # Verify prompt contains banner text.
    call_args = client.enrich.call_args
    request: EnrichmentRequest = call_args.args[0]
    assert "Banner text:" in request.entity_context


# ---------------------------------------------------------------------------
# 7. Headers-only analysis
# ---------------------------------------------------------------------------


async def test_headers_only_analysis() -> None:
    """Analysis works with only HTTP headers, no screenshot or banner."""
    parsed = _sample_analysis_dict(
        page_type="application",
        security_indicators=[],
        visual_confidence=0.4,
    )
    client = _mock_client(_make_enrichment_result(parsed))
    analyzer = VisionAnalyzer(llm_client=client)

    result = await analyzer.analyze_screenshot(
        url="https://app.example.com",
        headers={"Server": "nginx/1.25", "X-Powered-By": "Express"},
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    assert result is not None
    assert result.page_type == "application"
    assert result.visual_confidence == pytest.approx(0.4)

    # Verify prompt contains headers.
    call_args = client.enrich.call_args
    request: EnrichmentRequest = call_args.args[0]
    assert "HTTP response headers:" in request.entity_context
    assert "nginx/1.25" in request.entity_context


# ---------------------------------------------------------------------------
# 8. LLM failure returns None (graceful degradation)
# ---------------------------------------------------------------------------


async def test_graceful_on_llm_error() -> None:
    """If the LLM raises an exception, analysis returns None without crashing."""
    client = AsyncMock(spec=SafeLLMClient)
    client.enrich = AsyncMock(side_effect=RuntimeError("LLM provider down"))
    analyzer = VisionAnalyzer(llm_client=client)

    result = await analyzer.analyze_screenshot(
        screenshot_data=b"\x89PNG",
        url="https://error.example.com",
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    # Should degrade gracefully -- None, no exception raised.
    assert result is None


# ---------------------------------------------------------------------------
# 9. LLM returns unsuccessful result -> None
# ---------------------------------------------------------------------------


async def test_unsuccessful_llm_result() -> None:
    """When SafeLLMClient returns success=False, analysis returns None."""
    failed_result = EnrichmentResult(
        success=False,
        validation_errors=["Schema validation error: ..."],
    )
    client = _mock_client(failed_result)
    analyzer = VisionAnalyzer(llm_client=client)

    result = await analyzer.analyze_screenshot(
        screenshot_data=b"\x89PNG",
        url="https://fail.example.com",
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    assert result is None


# ---------------------------------------------------------------------------
# 10. No data provided -> None
# ---------------------------------------------------------------------------


async def test_no_data_returns_none() -> None:
    """When no screenshot, banner, or headers are provided, returns None."""
    parsed = _sample_analysis_dict()
    client = _mock_client(_make_enrichment_result(parsed))
    analyzer = VisionAnalyzer(llm_client=client)

    result = await analyzer.analyze_screenshot(
        url="https://empty.example.com",
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    assert result is None
    # LLM should not have been called.
    client.enrich.assert_not_called()


# ---------------------------------------------------------------------------
# 11. Multiple security indicators in one analysis
# ---------------------------------------------------------------------------


async def test_multiple_security_indicators() -> None:
    """Analysis correctly parses multiple security indicators."""
    indicators = [
        {
            "indicator_type": "version_disclosure",
            "detail": "Apache/2.4.41 visible in banner.",
            "severity": "low",
        },
        {
            "indicator_type": "default_credentials_hint",
            "detail": "Login form pre-filled with admin/admin.",
            "severity": "high",
        },
        {
            "indicator_type": "debug_mode",
            "detail": "PHP error_reporting enabled, stack traces visible.",
            "severity": "medium",
        },
    ]
    parsed = _sample_analysis_dict(security_indicators=indicators)
    client = _mock_client(_make_enrichment_result(parsed))
    analyzer = VisionAnalyzer(llm_client=client)

    result = await analyzer.analyze_screenshot(
        screenshot_data=b"\x89PNG",
        banner_text="Apache/2.4.41 (Ubuntu)",
        url="https://vuln.example.com",
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    assert result is not None
    assert len(result.security_indicators) == 3
    types = [si.indicator_type for si in result.security_indicators]
    assert "version_disclosure" in types
    assert "default_credentials_hint" in types
    assert "debug_mode" in types

    severities = [si.severity for si in result.security_indicators]
    assert "low" in severities
    assert "high" in severities
    assert "medium" in severities


# ---------------------------------------------------------------------------
# 12. Prompt wraps content in <external_observation> tags
# ---------------------------------------------------------------------------


async def test_prompt_uses_observation_tags() -> None:
    """Verify the entity context sent to the LLM uses <external_observation> wrapping."""
    parsed = _sample_analysis_dict()
    client = _mock_client(_make_enrichment_result(parsed))
    analyzer = VisionAnalyzer(llm_client=client)

    await analyzer.analyze_screenshot(
        banner_text="nginx default page",
        url="https://tagged.example.com",
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    call_args = client.enrich.call_args
    request: EnrichmentRequest = call_args.args[0]
    assert "<external_observation" in request.entity_context
    assert "</external_observation>" in request.entity_context
    assert "screenshot_analysis" in request.entity_context


# ---------------------------------------------------------------------------
# 13. ScreenshotAnalysis extra fields forbidden
# ---------------------------------------------------------------------------


def test_screenshot_analysis_extra_fields_forbidden() -> None:
    """Extra fields are rejected by ConfigDict(extra='forbid')."""
    with pytest.raises(ValidationError):
        ScreenshotAnalysis(
            page_type="login",
            visual_confidence=0.5,
            rogue_field="should fail",  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# 14. Empty screenshot bytes handled
# ---------------------------------------------------------------------------


async def test_empty_screenshot_bytes() -> None:
    """Empty bytes (b'') are still passed to the LLM -- the client decides."""
    parsed = _sample_analysis_dict(page_type="unknown", visual_confidence=0.1)
    client = _mock_client(_make_enrichment_result(parsed))
    analyzer = VisionAnalyzer(llm_client=client)

    result = await analyzer.analyze_screenshot(
        screenshot_data=b"",
        url="https://empty-bytes.example.com",
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    assert result is not None
    assert result.page_type == "unknown"
    assert result.visual_confidence == pytest.approx(0.1)
    # Client should have been called (empty bytes are still "data provided").
    client.enrich.assert_called_once()


# ---------------------------------------------------------------------------
# 15. Screenshot + banner + headers combined
# ---------------------------------------------------------------------------


async def test_combined_inputs() -> None:
    """All three inputs (screenshot, banner, headers) are included in prompt."""
    parsed = _sample_analysis_dict(page_type="application")
    client = _mock_client(_make_enrichment_result(parsed))
    analyzer = VisionAnalyzer(llm_client=client)

    result = await analyzer.analyze_screenshot(
        screenshot_data=b"\x89PNG\r\n",
        banner_text="Welcome to ExampleApp v2.1",
        url="https://app.example.com",
        headers={"Server": "gunicorn", "X-Frame-Options": "DENY"},
        tenant_id=_TENANT_ID,
        run_id=_RUN_ID,
    )

    assert result is not None
    assert result.page_type == "application"

    # All three data sources should appear in the prompt.
    call_args = client.enrich.call_args
    request: EnrichmentRequest = call_args.args[0]
    assert "Screenshot (base64):" in request.entity_context
    assert "Banner text:" in request.entity_context
    assert "HTTP response headers:" in request.entity_context
    assert "gunicorn" in request.entity_context
