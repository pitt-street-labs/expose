"""Tests for the multi-signal environment classifier.

Covers DNS pattern detection, HTTP signal extraction, TLS certificate analysis,
content signals, security posture signals, multi-signal correlation logic,
model validation (frozen, bounds), risk factor generation, and edge cases.
"""

from __future__ import annotations

import pytest

from expose.pipeline.environment_classifier import (
    EnvironmentClassification,
    EnvironmentClassifier,
    EnvironmentLabel,
    EnvironmentSignal,
    SignalCategory,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _http_obs(**payload_fields: object) -> dict[str, object]:
    """Build a minimal HTTP fingerprint observation dict."""
    sp: dict[str, object] = {
        "url": "https://example.com",
        "status_code": 200,
        "server_header": None,
        "content_type": "text/html",
        "title": None,
        "headers": {},
        "redirect_chain": [],
        "banner": "",
    }
    sp.update(payload_fields)
    return {"_collector_id": "active-http-fingerprint", "structured_payload": sp}


def _tls_obs(**payload_fields: object) -> dict[str, object]:
    """Build a minimal TLS handshake observation dict."""
    sp: dict[str, object] = {
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cert_subject_cn": "example.com",
        "cert_issuer_cn": "R3",
        "cert_issuer_org": "Let's Encrypt",
        "cert_serial": "abcdef",
        "cert_not_before": "2026-01-01T00:00:00Z",
        "cert_not_after": "2026-04-01T00:00:00Z",
        "cert_sans": ["example.com"],
        "cert_fingerprint_sha256": "aabbccdd",
        "jarm_fingerprint": None,
    }
    sp.update(payload_fields)
    return {"_collector_id": "active-tls-handshake", "structured_payload": sp}


def _classify(
    entity: str = "example.com",
    observations: list[dict[str, object]] | None = None,
) -> EnvironmentClassification:
    """Shorthand for running the classifier."""
    classifier = EnvironmentClassifier()
    return classifier.classify(
        entity_identifier=entity,
        observations=observations or [],
    )


# ===========================================================================
# DNS pattern tests
# ===========================================================================


class TestDnsPatterns:
    """DNS subdomain prefix and hostname suffix detection."""

    def test_dev_prefix_maps_to_development(self) -> None:
        result = _classify("dev.example.com")
        assert result.predicted_environment == EnvironmentLabel.DEVELOPMENT
        assert any(
            s.category == SignalCategory.DNS_PATTERN
            and s.suggested_environment == EnvironmentLabel.DEVELOPMENT
            for s in result.signals
        )

    def test_staging_prefix_maps_to_staging(self) -> None:
        result = _classify("staging.example.com")
        assert result.predicted_environment == EnvironmentLabel.STAGING

    def test_qa_prefix_maps_to_qa(self) -> None:
        result = _classify("qa.example.com")
        assert result.predicted_environment == EnvironmentLabel.QA

    def test_uat_prefix_maps_to_qa(self) -> None:
        result = _classify("uat.example.com")
        assert result.predicted_environment == EnvironmentLabel.QA

    def test_test_suffix_maps_to_test(self) -> None:
        result = _classify("api-test.example.com")
        assert result.predicted_environment == EnvironmentLabel.TEST
        assert any(
            s.signal_name == "hostname_suffix" for s in result.signals
        )

    def test_dev_suffix_maps_to_development(self) -> None:
        result = _classify("api-dev.example.com")
        assert result.predicted_environment == EnvironmentLabel.DEVELOPMENT

    def test_www_produces_no_signal(self) -> None:
        result = _classify("www.example.com")
        assert result.predicted_environment == EnvironmentLabel.UNKNOWN
        assert result.confidence == 0.0
        assert result.signals == []

    def test_api_produces_no_signal(self) -> None:
        result = _classify("api.example.com")
        assert result.predicted_environment == EnvironmentLabel.UNKNOWN
        assert result.signals == []

    def test_stg_prefix_maps_to_staging(self) -> None:
        result = _classify("stg.example.com")
        assert result.predicted_environment == EnvironmentLabel.STAGING

    def test_preprod_prefix_maps_to_staging(self) -> None:
        result = _classify("preprod.example.com")
        assert result.predicted_environment == EnvironmentLabel.STAGING

    def test_beta_prefix_maps_to_staging(self) -> None:
        result = _classify("beta.example.com")
        assert result.predicted_environment == EnvironmentLabel.STAGING

    def test_sandbox_prefix_maps_to_staging(self) -> None:
        result = _classify("sandbox.example.com")
        assert result.predicted_environment == EnvironmentLabel.STAGING

    def test_test_prefix_maps_to_test(self) -> None:
        result = _classify("test.example.com")
        assert result.predicted_environment == EnvironmentLabel.TEST


# ===========================================================================
# HTTP signal tests
# ===========================================================================


class TestHttpSignals:
    """HTTP response header and body signal detection."""

    def test_debug_header_produces_development_signal(self) -> None:
        obs = _http_obs(headers={"x-debug-token": "abc123"})
        result = _classify("app.example.com", [obs])
        debug_signals = [
            s for s in result.signals
            if s.signal_name == "debug_header"
        ]
        assert len(debug_signals) == 1
        assert debug_signals[0].suggested_environment == EnvironmentLabel.DEVELOPMENT
        assert debug_signals[0].confidence == 0.7

    def test_cors_wildcard_produces_non_production_signal(self) -> None:
        obs = _http_obs(headers={"access-control-allow-origin": "*"})
        result = _classify("app.example.com", [obs])
        cors_signals = [
            s for s in result.signals
            if s.signal_name == "cors_wildcard"
        ]
        assert len(cors_signals) == 1
        assert cors_signals[0].confidence == 0.3

    def test_normal_headers_produce_no_http_signal(self) -> None:
        obs = _http_obs(
            headers={
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
            },
            server_header="nginx/1.24",
        )
        result = _classify("app.example.com", [obs])
        http_signals = [
            s for s in result.signals
            if s.category == SignalCategory.HTTP_RESPONSE
        ]
        assert http_signals == []

    def test_stack_trace_produces_development_signal(self) -> None:
        obs = _http_obs(banner="Traceback (most recent call last):\n  File ...")
        result = _classify("app.example.com", [obs])
        trace_signals = [
            s for s in result.signals
            if s.signal_name == "stack_trace_in_body"
        ]
        assert len(trace_signals) == 1
        assert trace_signals[0].suggested_environment == EnvironmentLabel.DEVELOPMENT

    def test_server_header_with_debug_keyword(self) -> None:
        obs = _http_obs(server_header="WebServer/debug")
        result = _classify("app.example.com", [obs])
        dev_signals = [
            s for s in result.signals
            if s.signal_name == "server_header_dev"
        ]
        assert len(dev_signals) == 1


# ===========================================================================
# TLS signal tests
# ===========================================================================


class TestTlsSignals:
    """TLS certificate signal detection."""

    def test_self_signed_cert_produces_signal(self) -> None:
        obs = _tls_obs(
            cert_subject_cn="mysite.local",
            cert_issuer_cn="mysite.local",
            cert_issuer_org="",
        )
        result = _classify("app.example.com", [obs])
        self_signed = [
            s for s in result.signals
            if s.signal_name == "self_signed_cert"
        ]
        assert len(self_signed) == 1
        assert self_signed[0].confidence == 0.7

    def test_le_staging_issuer_produces_staging_signal(self) -> None:
        obs = _tls_obs(
            cert_issuer_cn="Fake LE Intermediate X1",
            cert_issuer_org="(STAGING) Let's Encrypt",
        )
        result = _classify("app.example.com", [obs])
        le_signals = [
            s for s in result.signals
            if s.signal_name == "le_staging_cert"
        ]
        assert len(le_signals) == 1
        assert le_signals[0].suggested_environment == EnvironmentLabel.STAGING
        assert le_signals[0].confidence == 0.9

    def test_short_validity_produces_test_signal(self) -> None:
        obs = _tls_obs(
            cert_not_before="2026-05-01T00:00:00Z",
            cert_not_after="2026-05-04T00:00:00Z",  # 3 days
        )
        result = _classify("app.example.com", [obs])
        short_signals = [
            s for s in result.signals
            if s.signal_name == "short_validity_cert"
        ]
        assert len(short_signals) == 1
        assert short_signals[0].suggested_environment == EnvironmentLabel.TEST
        assert short_signals[0].confidence == 0.6

    def test_internal_ca_produces_signal(self) -> None:
        obs = _tls_obs(
            cert_subject_cn="app.internal.corp",
            cert_issuer_cn="Corp Internal CA",
            cert_issuer_org="Acme Internal PKI",
        )
        result = _classify("app.example.com", [obs])
        internal_ca = [
            s for s in result.signals
            if s.signal_name == "internal_ca"
        ]
        assert len(internal_ca) == 1
        assert internal_ca[0].confidence == 0.5

    def test_public_ca_produces_no_tls_signal(self) -> None:
        obs = _tls_obs(
            cert_subject_cn="example.com",
            cert_issuer_cn="R3",
            cert_issuer_org="Let's Encrypt",
            cert_not_before="2026-01-01T00:00:00Z",
            cert_not_after="2026-04-01T00:00:00Z",
        )
        result = _classify("app.example.com", [obs])
        tls_signals = [
            s for s in result.signals
            if s.category == SignalCategory.TLS_CERTIFICATE
        ]
        assert tls_signals == []


# ===========================================================================
# Multi-signal correlation tests
# ===========================================================================


class TestCorrelation:
    """Multi-signal aggregation and confidence scaling."""

    def test_dns_dev_plus_debug_headers_high_confidence(self) -> None:
        """DNS 'dev.' prefix + debug headers → DEVELOPMENT, high confidence."""
        obs = _http_obs(headers={"x-debug-token": "tok123"})
        result = _classify("dev.example.com", [obs])
        assert result.predicted_environment == EnvironmentLabel.DEVELOPMENT
        assert result.categories_matched >= 2
        assert result.confidence > 0.4

    def test_dns_staging_plus_self_signed_cert(self) -> None:
        """DNS 'staging.' + self-signed cert → STAGING, high confidence."""
        tls = _tls_obs(
            cert_subject_cn="staging.example.com",
            cert_issuer_cn="staging.example.com",
            cert_issuer_org="",
        )
        result = _classify("staging.example.com", [tls])
        assert result.predicted_environment == EnvironmentLabel.STAGING
        assert result.categories_matched >= 2
        assert result.confidence > 0.4

    def test_single_dns_signal_lower_confidence(self) -> None:
        """Only one category (DNS) → confidence capped at 0.5."""
        result = _classify("dev.example.com")
        assert result.confidence <= 0.5

    def test_no_signals_produces_unknown(self) -> None:
        """No signals at all → UNKNOWN with 0.0 confidence."""
        result = _classify("www.example.com")
        assert result.predicted_environment == EnvironmentLabel.UNKNOWN
        assert result.confidence == 0.0
        assert result.categories_matched == 0

    def test_three_categories_high_confidence(self) -> None:
        """3+ distinct categories → confidence can reach up to 0.9."""
        http = _http_obs(
            headers={"x-debug-token": "abc"},
            banner="Traceback (most recent call last):",
        )
        tls = _tls_obs(
            cert_subject_cn="dev.example.com",
            cert_issuer_cn="dev.example.com",
            cert_issuer_org="",
        )
        result = _classify("dev.example.com", [http, tls])
        assert result.categories_matched >= 3
        assert result.confidence >= 0.5

    def test_is_non_production_true_for_non_prod_labels(self) -> None:
        """is_non_production is True for DEVELOPMENT, STAGING, QA, TEST."""
        for prefix, _expected_env in [
            ("dev", EnvironmentLabel.DEVELOPMENT),
            ("staging", EnvironmentLabel.STAGING),
            ("qa", EnvironmentLabel.QA),
            ("test", EnvironmentLabel.TEST),
        ]:
            result = _classify(f"{prefix}.example.com")
            assert result.is_non_production is True, (
                f"Expected is_non_production=True for {prefix}.example.com "
                f"(got {result.predicted_environment})"
            )

    def test_is_non_production_false_for_unknown(self) -> None:
        """is_non_production is False when environment is UNKNOWN."""
        result = _classify("www.example.com")
        assert result.is_non_production is False


# ===========================================================================
# Model validation tests
# ===========================================================================


class TestModelValidation:
    """Pydantic model constraints: frozen, extra=forbid, field bounds."""

    def test_classification_is_frozen(self) -> None:
        result = _classify("dev.example.com")
        with pytest.raises(Exception):  # noqa: B017
            result.confidence = 0.99  # type: ignore[misc]

    def test_signal_is_frozen(self) -> None:
        sig = EnvironmentSignal(
            category=SignalCategory.DNS_PATTERN,
            signal_name="test",
            matched_value="dev",
            suggested_environment=EnvironmentLabel.DEVELOPMENT,
            confidence=0.8,
        )
        with pytest.raises(Exception):  # noqa: B017
            sig.confidence = 0.5  # type: ignore[misc]

    def test_signal_confidence_bounds_upper(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            EnvironmentSignal(
                category=SignalCategory.DNS_PATTERN,
                signal_name="test",
                matched_value="dev",
                suggested_environment=EnvironmentLabel.DEVELOPMENT,
                confidence=1.5,
            )

    def test_signal_confidence_bounds_lower(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            EnvironmentSignal(
                category=SignalCategory.DNS_PATTERN,
                signal_name="test",
                matched_value="dev",
                suggested_environment=EnvironmentLabel.DEVELOPMENT,
                confidence=-0.1,
            )

    def test_signal_rejects_extra_fields(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            EnvironmentSignal(
                category=SignalCategory.DNS_PATTERN,
                signal_name="test",
                matched_value="dev",
                suggested_environment=EnvironmentLabel.DEVELOPMENT,
                confidence=0.5,
                bogus="nope",  # type: ignore[call-arg]
            )

    def test_classification_rejects_empty_entity(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            EnvironmentClassification(
                entity_identifier="",
                predicted_environment=EnvironmentLabel.UNKNOWN,
                confidence=0.0,
                signals=[],
                is_non_production=False,
                categories_matched=0,
            )

    def test_signal_rejects_empty_signal_name(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            EnvironmentSignal(
                category=SignalCategory.DNS_PATTERN,
                signal_name="",
                matched_value="dev",
                suggested_environment=EnvironmentLabel.DEVELOPMENT,
                confidence=0.5,
            )


# ===========================================================================
# Risk factor tests
# ===========================================================================


class TestRiskFactors:
    """Risk factor generation from detected signals."""

    def test_debug_headers_produce_debug_risk(self) -> None:
        obs = _http_obs(headers={"x-debug-token": "tok"})
        result = _classify("dev.example.com", [obs])
        assert "Debug mode enabled" in result.risk_factors

    def test_self_signed_cert_produces_cert_risk(self) -> None:
        tls = _tls_obs(
            cert_subject_cn="self.local",
            cert_issuer_cn="self.local",
            cert_issuer_org="",
        )
        result = _classify("dev.example.com", [tls])
        assert "Self-signed certificate" in result.risk_factors

    def test_stack_traces_produce_risk(self) -> None:
        obs = _http_obs(banner="Traceback (most recent call last):")
        result = _classify("dev.example.com", [obs])
        assert "Stack traces visible" in result.risk_factors

    def test_swagger_produces_risk(self) -> None:
        obs = _http_obs(banner="<html><title>Swagger UI</title></html>")
        result = _classify("dev.example.com", [obs])
        assert "Swagger/API docs exposed" in result.risk_factors

    def test_no_signals_no_risk_factors(self) -> None:
        result = _classify("www.example.com")
        assert result.risk_factors == []


# ===========================================================================
# Enum value tests
# ===========================================================================


class TestEnumValues:
    """Enum string values match expected constants."""

    def test_environment_label_values(self) -> None:
        expected = {"production", "staging", "qa", "development", "test", "unknown"}
        actual = {e.value for e in EnvironmentLabel}
        assert actual == expected

    def test_signal_category_values(self) -> None:
        expected = {
            "dns_pattern", "http_response", "tls_certificate",
            "infrastructure", "content", "security_posture",
        }
        actual = {c.value for c in SignalCategory}
        assert actual == expected


# ===========================================================================
# Content signal tests
# ===========================================================================


class TestContentSignals:
    """Content-based signal detection (default pages, Swagger)."""

    def test_nginx_default_page(self) -> None:
        obs = _http_obs(title="Welcome to nginx!")
        result = _classify("app.example.com", [obs])
        content_signals = [
            s for s in result.signals
            if s.signal_name == "default_page"
        ]
        assert len(content_signals) == 1

    def test_apache_default_page(self) -> None:
        obs = _http_obs(banner="Apache2 Ubuntu Default Page")
        result = _classify("app.example.com", [obs])
        content_signals = [
            s for s in result.signals
            if s.signal_name == "default_page"
        ]
        assert len(content_signals) == 1


# ===========================================================================
# Security posture tests
# ===========================================================================


class TestSecurityPosture:
    """Security posture signal detection (missing headers, no TLS)."""

    def test_missing_hsts_produces_signal(self) -> None:
        obs = _http_obs(headers={})
        result = _classify("app.example.com", [obs])
        hsts_signals = [
            s for s in result.signals
            if s.signal_name == "missing_hsts"
        ]
        assert len(hsts_signals) == 1

    def test_http_url_produces_no_tls_signal(self) -> None:
        obs = _http_obs(url="http://app.example.com", headers={})
        result = _classify("app.example.com", [obs])
        no_tls = [
            s for s in result.signals
            if s.signal_name == "no_tls"
        ]
        assert len(no_tls) == 1
        assert no_tls[0].confidence == 0.4
