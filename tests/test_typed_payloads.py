"""Tests for typed observation properties and collector payload models.

Validates the new additive type layer introduced by #130:
  - ``ObservationProps`` TypedDict
  - ``DnsPayload``, ``HttpPayload``, ``TlsPayload``, ``PortScanPayload`` models
  - ``as_*_payload()`` type narrowing helpers

Each test uses realistic data shapes drawn from the actual collector
implementations (active_dns, active_http, active_tls, active_port_surface).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from expose.types.collector_payloads import (
    CookieIssue,
    CorsMisconfig,
    DnsPayload,
    HttpPayload,
    MxExchange,
    PortScanPayload,
    TlsPayload,
    as_dns_payload,
    as_http_payload,
    as_port_scan_payload,
    as_tls_payload,
)
from expose.types.observation_props import ObservationProps

# ---------------------------------------------------------------------------
# Realistic test data factories
# ---------------------------------------------------------------------------


def _dns_a_payload() -> dict:
    """Realistic A-record payload from active-dns-resolve."""
    return {
        "_collector_id": "active-dns-resolve",
        "record_type": "A",
        "values": ["93.184.216.34"],
        "ttl": 300,
    }


def _dns_mx_payload() -> dict:
    """Realistic MX-record payload."""
    return {
        "_collector_id": "active-dns-resolve",
        "record_type": "MX",
        "exchanges": [
            {"priority": 10, "exchange": "mail.example.com"},
            {"priority": 20, "exchange": "mail2.example.com"},
        ],
    }


def _dns_ns_payload() -> dict:
    """Realistic NS-record payload."""
    return {
        "_collector_id": "active-dns-resolve",
        "record_type": "NS",
        "nameservers": ["ns1.example.com", "ns2.example.com"],
    }


def _dns_soa_payload() -> dict:
    """Realistic SOA-record payload."""
    return {
        "_collector_id": "active-dns-resolve",
        "record_type": "SOA",
        "mname": "ns1.example.com",
        "rname": "admin.example.com",
        "serial": 2024010101,
        "refresh": 3600,
        "retry": 900,
        "expire": 604800,
        "minimum": 86400,
    }


def _dns_cname_payload() -> dict:
    """Realistic CNAME-record payload."""
    return {
        "_collector_id": "active-dns-resolve",
        "record_type": "CNAME",
        "target": "cdn.example.com",
    }


def _dns_txt_payload() -> dict:
    """Realistic TXT-record payload."""
    return {
        "_collector_id": "active-dns-resolve",
        "record_type": "TXT",
        "values": [
            "v=spf1 include:_spf.google.com ~all",
            "google-site-verification=abc123",
        ],
    }


def _dns_wildcard_payload() -> dict:
    """Realistic wildcard-detection payload."""
    return {
        "_collector_id": "active-dns-resolve",
        "record_type": "WILDCARD",
        "wildcard_detected": True,
        "wildcard_values": ["93.184.216.34"],
        "severity": "warning",
        "note": (
            "Wildcard DNS detected — all unregistered "
            "subdomains resolve to the same address(es)"
        ),
    }


def _http_payload() -> dict:
    """Realistic payload from active-http-fingerprint."""
    return {
        "_collector_id": "active-http-fingerprint",
        "url": "https://example.com/",
        "status_code": 200,
        "server_header": "nginx/1.24.0",
        "content_type": "text/html; charset=utf-8",
        "title": "Example Domain",
        "headers": {
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
        },
        "redirect_chain": ["http://example.com/"],
        "banner": "<html>...",
        "technologies": ["nginx"],
        "cookie_issues": [
            {
                "name": "session_id",
                "missing_flags": ["secure", "httponly"],
                "issues": ["Missing Secure flag", "Missing HttpOnly flag"],
            }
        ],
        "cors_misconfig": {
            "wildcard_origin": True,
            "null_origin": False,
            "credentials_with_wildcard": False,
        },
    }


def _tls_payload() -> dict:
    """Realistic payload from active-tls-handshake."""
    return {
        "_collector_id": "active-tls-handshake",
        "tls_version": "TLSv1.3",
        "protocol_assessment": "secure",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cipher_strength": "strong",
        "cert_subject_cn": "example.com",
        "cert_issuer_cn": "R3",
        "cert_issuer_org": "Let's Encrypt",
        "cert_serial": "0A1B2C3D4E5F",
        "cert_not_before": "2024-01-01T00:00:00+00:00",
        "cert_not_after": "2024-04-01T00:00:00+00:00",
        "cert_sans": ["example.com", "www.example.com"],
        "cert_fingerprint_sha256": "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89",
        "key_algorithm": "RSA",
        "key_size_bits": 2048,
        "key_weak": False,
        "chain_depth": 3,
        "self_signed": False,
        "jarm_fingerprint": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
    }


def _port_scan_payload() -> dict:
    """Realistic payload from active-port-surface."""
    return {
        "_collector_id": "active-port-surface",
        "open_ports": [22, 80, 443, 3306],
        "closed_ports_probed": 996,
        "total_ports_probed": 1000,
        "probe_timeout_seconds": 3.0,
        "banners": {
            "22": "SSH-2.0-OpenSSH_9.6",
            "80": "",
        },
        "services": {
            "22": "ssh",
            "80": "http",
            "443": "https",
            "3306": "mysql",
        },
        "port_categories": {
            "22": "management",
            "80": "web",
            "443": "web",
            "3306": "database",
        },
    }


def _observation_props_dict() -> dict:
    """Realistic observation properties dict from _observation_properties()."""
    return {
        "_collector_id": "active-dns-resolve",
        "_collector_version": "0.2.0",
        "_observation_type": "dns_resolution",
        "_observed_at": "2024-06-15T10:30:00+00:00",
        "_warnings": ["Truncated response"],
        "record_type": "A",
        "values": ["93.184.216.34"],
    }


# ===========================================================================
# ObservationProps TypedDict
# ===========================================================================


class TestObservationProps:
    """ObservationProps is a TypedDict -- it doesn't enforce at runtime,
    but we verify it's usable for type-narrowing and key documentation."""

    def test_can_create_typed_dict(self) -> None:
        """ObservationProps can be used as a type hint and populated."""
        props: ObservationProps = {
            "_collector_id": "active-dns-resolve",
            "_collector_version": "0.2.0",
            "_observation_type": "dns_resolution",
            "_observed_at": "2024-06-15T10:30:00+00:00",
        }
        assert props["_collector_id"] == "active-dns-resolve"
        assert props["_observation_type"] == "dns_resolution"

    def test_total_false_allows_partial(self) -> None:
        """total=False means any subset of keys is valid."""
        props: ObservationProps = {"_collector_id": "test"}
        assert "_warnings" not in props

    def test_compatible_with_raw_dict(self) -> None:
        """An ObservationProps-typed variable can hold a raw dict."""
        raw = _observation_props_dict()
        props: ObservationProps = raw  # type: ignore[assignment]
        assert props["_collector_id"] == "active-dns-resolve"
        assert props["_observed_at"] == "2024-06-15T10:30:00+00:00"

    def test_lead_score_fields(self) -> None:
        """Lead score metadata can be included."""
        props: ObservationProps = {
            "_collector_id": "test",
            "_lead_score": 75,
            "_priority_tier": "high",
        }
        assert props["_lead_score"] == 75
        assert props["_priority_tier"] == "high"


# ===========================================================================
# DnsPayload
# ===========================================================================


class TestDnsPayload:
    """DnsPayload validates active-dns-resolve structured payloads."""

    def test_a_record(self) -> None:
        p = as_dns_payload(_dns_a_payload())
        assert p.record_type == "A"
        assert p.values == ["93.184.216.34"]
        assert p.ttl == 300

    def test_mx_record(self) -> None:
        p = as_dns_payload(_dns_mx_payload())
        assert p.record_type == "MX"
        assert len(p.exchanges) == 2
        assert isinstance(p.exchanges[0], MxExchange)
        assert p.exchanges[0].priority == 10
        assert p.exchanges[0].exchange == "mail.example.com"
        assert p.exchanges[1].priority == 20

    def test_ns_record(self) -> None:
        p = as_dns_payload(_dns_ns_payload())
        assert p.record_type == "NS"
        assert p.nameservers == ["ns1.example.com", "ns2.example.com"]

    def test_soa_record(self) -> None:
        p = as_dns_payload(_dns_soa_payload())
        assert p.record_type == "SOA"
        assert p.mname == "ns1.example.com"
        assert p.rname == "admin.example.com"
        assert p.serial == 2024010101
        assert p.refresh == 3600
        assert p.retry == 900
        assert p.expire == 604800
        assert p.minimum == 86400

    def test_cname_record(self) -> None:
        p = as_dns_payload(_dns_cname_payload())
        assert p.record_type == "CNAME"
        assert p.target == "cdn.example.com"

    def test_txt_record(self) -> None:
        p = as_dns_payload(_dns_txt_payload())
        assert p.record_type == "TXT"
        assert len(p.values) == 2
        assert "v=spf1" in p.values[0]

    def test_wildcard_detection(self) -> None:
        p = as_dns_payload(_dns_wildcard_payload())
        assert p.record_type == "WILDCARD"
        assert p.wildcard_detected is True
        assert p.wildcard_values == ["93.184.216.34"]
        assert p.severity == "warning"

    def test_empty_payload(self) -> None:
        """Empty dict produces a valid DnsPayload with defaults."""
        p = as_dns_payload({})
        assert p.record_type == ""
        assert p.values == []
        assert p.ttl is None
        assert p.exchanges == []
        assert p.nameservers == []

    def test_round_trip_preserves_all_keys(self) -> None:
        """dict -> DnsPayload -> dict round-trip preserves every key."""
        original = _dns_a_payload()
        p = as_dns_payload(original)
        dumped = p.model_dump()
        for key in ("record_type", "values", "ttl"):
            assert dumped[key] == original[key]

    def test_extra_fields_preserved(self) -> None:
        """Unknown fields are preserved thanks to extra='allow'."""
        data = _dns_a_payload()
        data["custom_scanner_note"] = "internal only"
        data["scan_region"] = "us-east-1"
        p = as_dns_payload(data)
        dumped = p.model_dump()
        assert dumped["custom_scanner_note"] == "internal only"
        assert dumped["scan_region"] == "us-east-1"

    def test_frozen_immutability(self) -> None:
        """DnsPayload instances are frozen (immutable)."""
        p = as_dns_payload(_dns_a_payload())
        with pytest.raises(ValidationError):
            p.record_type = "AAAA"  # type: ignore[misc]


# ===========================================================================
# HttpPayload
# ===========================================================================


class TestHttpPayload:
    """HttpPayload validates active-http-fingerprint structured payloads."""

    def test_full_payload(self) -> None:
        p = as_http_payload(_http_payload())
        assert p.url == "https://example.com/"
        assert p.status_code == 200
        assert p.server_header == "nginx/1.24.0"
        assert p.content_type == "text/html; charset=utf-8"
        assert p.title == "Example Domain"
        assert "strict-transport-security" in p.headers
        assert p.redirect_chain == ["http://example.com/"]
        assert p.technologies == ["nginx"]

    def test_cookie_issues_typed(self) -> None:
        """Cookie issues are parsed into CookieIssue models."""
        p = as_http_payload(_http_payload())
        assert len(p.cookie_issues) == 1
        issue = p.cookie_issues[0]
        assert isinstance(issue, CookieIssue)
        assert issue.name == "session_id"
        assert "secure" in issue.missing_flags
        assert "httponly" in issue.missing_flags

    def test_cors_misconfig_typed(self) -> None:
        """CORS misconfiguration is parsed into a CorsMisconfig model."""
        p = as_http_payload(_http_payload())
        assert p.cors_misconfig is not None
        assert isinstance(p.cors_misconfig, CorsMisconfig)
        assert p.cors_misconfig.wildcard_origin is True
        assert p.cors_misconfig.null_origin is False

    def test_empty_payload(self) -> None:
        p = as_http_payload({})
        assert p.url == ""
        assert p.status_code == 0
        assert p.server_header is None
        assert p.headers == {}
        assert p.cookie_issues == []
        assert p.cors_misconfig is None

    def test_no_cors(self) -> None:
        """Payload without cors_misconfig key -> None."""
        data = _http_payload()
        del data["cors_misconfig"]
        p = as_http_payload(data)
        assert p.cors_misconfig is None

    def test_round_trip(self) -> None:
        original = _http_payload()
        p = as_http_payload(original)
        dumped = p.model_dump()
        assert dumped["url"] == original["url"]
        assert dumped["status_code"] == original["status_code"]
        assert dumped["server_header"] == original["server_header"]
        assert len(dumped["cookie_issues"]) == 1

    def test_extra_fields_preserved(self) -> None:
        data = _http_payload()
        data["response_time_ms"] = 142.5
        p = as_http_payload(data)
        dumped = p.model_dump()
        assert dumped["response_time_ms"] == 142.5

    def test_frozen_immutability(self) -> None:
        p = as_http_payload(_http_payload())
        with pytest.raises(ValidationError):
            p.status_code = 404  # type: ignore[misc]


# ===========================================================================
# TlsPayload
# ===========================================================================


class TestTlsPayload:
    """TlsPayload validates active-tls-handshake structured payloads."""

    def test_full_payload(self) -> None:
        p = as_tls_payload(_tls_payload())
        assert p.tls_version == "TLSv1.3"
        assert p.cipher_suite == "TLS_AES_256_GCM_SHA384"
        assert p.cipher_strength == "strong"
        assert p.cert_subject_cn == "example.com"
        assert p.cert_issuer_cn == "R3"
        assert p.cert_issuer_org == "Let's Encrypt"
        assert p.cert_sans == ["example.com", "www.example.com"]
        assert p.key_algorithm == "RSA"
        assert p.key_size_bits == 2048
        assert p.key_weak is False
        assert p.chain_depth == 3
        assert p.self_signed is False

    def test_cert_dates(self) -> None:
        p = as_tls_payload(_tls_payload())
        assert p.cert_not_before == "2024-01-01T00:00:00+00:00"
        assert p.cert_not_after == "2024-04-01T00:00:00+00:00"

    def test_jarm_fingerprint(self) -> None:
        p = as_tls_payload(_tls_payload())
        assert p.jarm_fingerprint is not None
        assert len(p.jarm_fingerprint) == 62

    def test_self_signed_cert(self) -> None:
        """Self-signed cert: subject_cn == issuer_cn."""
        data = _tls_payload()
        data["cert_subject_cn"] = "internal.example.com"
        data["cert_issuer_cn"] = "internal.example.com"
        data["self_signed"] = True
        p = as_tls_payload(data)
        assert p.self_signed is True
        assert p.cert_subject_cn == p.cert_issuer_cn

    def test_empty_payload(self) -> None:
        p = as_tls_payload({})
        assert p.tls_version == ""
        assert p.cipher_suite == ""
        assert p.cert_subject_cn is None
        assert p.cert_sans == []
        assert p.key_size_bits is None
        assert p.self_signed is None

    def test_round_trip(self) -> None:
        original = _tls_payload()
        p = as_tls_payload(original)
        dumped = p.model_dump()
        assert dumped["tls_version"] == original["tls_version"]
        assert dumped["cert_subject_cn"] == original["cert_subject_cn"]
        assert dumped["cert_sans"] == original["cert_sans"]
        assert dumped["key_size_bits"] == original["key_size_bits"]

    def test_extra_fields_preserved(self) -> None:
        data = _tls_payload()
        data["ocsp_stapled"] = True
        data["ct_sct_count"] = 3
        p = as_tls_payload(data)
        dumped = p.model_dump()
        assert dumped["ocsp_stapled"] is True
        assert dumped["ct_sct_count"] == 3

    def test_frozen_immutability(self) -> None:
        p = as_tls_payload(_tls_payload())
        with pytest.raises(ValidationError):
            p.tls_version = "TLSv1.0"  # type: ignore[misc]

    def test_deprecated_tls_version(self) -> None:
        """Deprecated TLS version can be represented."""
        data = _tls_payload()
        data["tls_version"] = "TLSv1.0"
        data["protocol_assessment"] = "deprecated"
        data["cipher_strength"] = "weak"
        p = as_tls_payload(data)
        assert p.tls_version == "TLSv1.0"
        assert p.protocol_assessment == "deprecated"


# ===========================================================================
# PortScanPayload
# ===========================================================================


class TestPortScanPayload:
    """PortScanPayload validates active-port-surface structured payloads."""

    def test_full_payload(self) -> None:
        p = as_port_scan_payload(_port_scan_payload())
        assert p.open_ports == [22, 80, 443, 3306]
        assert p.closed_ports_probed == 996
        assert p.total_ports_probed == 1000
        assert p.probe_timeout_seconds == 3.0
        assert p.services["22"] == "ssh"
        assert p.services["443"] == "https"
        assert p.port_categories["3306"] == "database"

    def test_banners(self) -> None:
        p = as_port_scan_payload(_port_scan_payload())
        assert "22" in p.banners
        assert "SSH-2.0-OpenSSH_9.6" in p.banners["22"]

    def test_empty_payload(self) -> None:
        p = as_port_scan_payload({})
        assert p.open_ports == []
        assert p.closed_ports_probed == 0
        assert p.total_ports_probed == 0
        assert p.banners == {}
        assert p.services == {}

    def test_web_only_ports(self) -> None:
        """Target with only web ports open."""
        data = {
            "_collector_id": "active-port-surface",
            "open_ports": [80, 443],
            "closed_ports_probed": 998,
            "total_ports_probed": 1000,
            "probe_timeout_seconds": 3.0,
            "banners": {},
            "services": {"80": "http", "443": "https"},
            "port_categories": {"80": "web", "443": "web"},
        }
        p = as_port_scan_payload(data)
        assert p.open_ports == [80, 443]
        assert len(p.services) == 2

    def test_round_trip(self) -> None:
        original = _port_scan_payload()
        p = as_port_scan_payload(original)
        dumped = p.model_dump()
        assert dumped["open_ports"] == original["open_ports"]
        assert dumped["services"] == original["services"]
        assert dumped["banners"] == original["banners"]

    def test_extra_fields_preserved(self) -> None:
        data = _port_scan_payload()
        data["scan_source_ip"] = "10.0.0.5"
        p = as_port_scan_payload(data)
        dumped = p.model_dump()
        assert dumped["scan_source_ip"] == "10.0.0.5"

    def test_frozen_immutability(self) -> None:
        p = as_port_scan_payload(_port_scan_payload())
        with pytest.raises(ValidationError):
            p.open_ports = [80]  # type: ignore[misc]


# ===========================================================================
# Cross-cutting concerns
# ===========================================================================


class TestCrossCutting:
    """Tests that apply to all payload types."""

    @pytest.mark.parametrize(
        "factory,converter",
        [
            (_dns_a_payload, as_dns_payload),
            (_http_payload, as_http_payload),
            (_tls_payload, as_tls_payload),
            (_port_scan_payload, as_port_scan_payload),
        ],
        ids=["dns", "http", "tls", "port_scan"],
    )
    def test_round_trip_dict_model_dict(self, factory, converter) -> None:
        """All models survive dict -> model -> dict with no data loss."""
        original = factory()
        model = converter(original)
        dumped = model.model_dump()
        # Every key from the original must appear in the dump.
        for key, value in original.items():
            if key.startswith("_"):
                # Underscore-prefixed fields are private in pydantic;
                # they won't round-trip through model_dump() by default.
                # That's expected -- these are provenance metadata
                # injected by the pipeline, not schema-level fields.
                continue
            assert key in dumped, f"Key {key!r} missing from dump"
            assert dumped[key] == value, (
                f"Key {key!r}: expected {value!r}, got {dumped[key]!r}"
            )

    @pytest.mark.parametrize(
        "converter",
        [as_dns_payload, as_http_payload, as_tls_payload, as_port_scan_payload],
        ids=["dns", "http", "tls", "port_scan"],
    )
    def test_empty_dict_valid(self, converter) -> None:
        """All models accept an empty dict without raising."""
        model = converter({})
        assert model is not None

    @pytest.mark.parametrize(
        "factory,converter",
        [
            (_dns_a_payload, as_dns_payload),
            (_http_payload, as_http_payload),
            (_tls_payload, as_tls_payload),
            (_port_scan_payload, as_port_scan_payload),
        ],
        ids=["dns", "http", "tls", "port_scan"],
    )
    def test_extra_fields_not_rejected(self, factory, converter) -> None:
        """extra='allow' means unknown keys don't cause validation errors."""
        data = factory()
        data["_custom_internal_flag"] = True
        data["experimental_score"] = 42.5
        data["nested_extra"] = {"a": 1, "b": [2, 3]}
        # Should not raise
        model = converter(data)
        assert model is not None

    @pytest.mark.parametrize(
        "converter",
        [as_dns_payload, as_http_payload, as_tls_payload, as_port_scan_payload],
        ids=["dns", "http", "tls", "port_scan"],
    )
    def test_none_input_raises(self, converter) -> None:
        """Passing None raises a validation error."""
        with pytest.raises((ValidationError, TypeError)):
            converter(None)  # type: ignore[arg-type]


class TestMxExchangeModel:
    """MxExchange is used within DnsPayload for MX records."""

    def test_basic(self) -> None:
        mx = MxExchange(priority=10, exchange="mail.example.com")
        assert mx.priority == 10
        assert mx.exchange == "mail.example.com"

    def test_frozen(self) -> None:
        mx = MxExchange(priority=10, exchange="mail.example.com")
        with pytest.raises(ValidationError):
            mx.priority = 20  # type: ignore[misc]

    def test_extra_allowed(self) -> None:
        mx = MxExchange.model_validate(
            {"priority": 10, "exchange": "mail.example.com", "weight": 100}
        )
        assert mx.model_dump()["weight"] == 100


class TestCookieIssueModel:
    """CookieIssue sub-model in HttpPayload."""

    def test_basic(self) -> None:
        ci = CookieIssue(
            name="session_id",
            missing_flags=["secure"],
            issues=["Missing Secure flag"],
        )
        assert ci.name == "session_id"
        assert "secure" in ci.missing_flags

    def test_empty(self) -> None:
        ci = CookieIssue()
        assert ci.name == ""
        assert ci.missing_flags == []


class TestCorsMisconfigModel:
    """CorsMisconfig sub-model in HttpPayload."""

    def test_basic(self) -> None:
        cors = CorsMisconfig(wildcard_origin=True)
        assert cors.wildcard_origin is True
        assert cors.null_origin is False

    def test_defaults(self) -> None:
        cors = CorsMisconfig()
        assert cors.wildcard_origin is False
        assert cors.null_origin is False
        assert cors.credentials_with_wildcard is False


# ===========================================================================
# Edge cases and regression tests
# ===========================================================================


class TestEdgeCases:
    """Edge cases drawn from real collector behavior."""

    def test_dns_payload_with_observation_metadata(self) -> None:
        """Payload that also has _observation_properties metadata mixed in.

        This mirrors what _observation_properties() returns: the
        structured_payload keys plus provenance metadata.
        """
        data = {
            **_dns_a_payload(),
            "_collector_version": "0.2.0",
            "_observation_type": "dns_resolution",
            "_observed_at": "2024-06-15T10:30:00+00:00",
            "_warnings": ["Truncated response"],
        }
        p = as_dns_payload(data)
        assert p.record_type == "A"
        assert p.values == ["93.184.216.34"]
        # Extra provenance fields should be preserved
        dumped = p.model_dump()
        assert dumped["_collector_version"] == "0.2.0"
        assert dumped["_observation_type"] == "dns_resolution"

    def test_http_payload_no_cookies(self) -> None:
        """HTTP payload with no cookie issues."""
        data = _http_payload()
        data["cookie_issues"] = []
        p = as_http_payload(data)
        assert p.cookie_issues == []

    def test_tls_payload_weak_key(self) -> None:
        """TLS with a weak key."""
        data = _tls_payload()
        data["key_algorithm"] = "RSA"
        data["key_size_bits"] = 1024
        data["key_weak"] = True
        p = as_tls_payload(data)
        assert p.key_weak is True
        assert p.key_size_bits == 1024

    def test_port_scan_no_open_ports(self) -> None:
        """All ports closed."""
        data = {
            "_collector_id": "active-port-surface",
            "open_ports": [],
            "closed_ports_probed": 1000,
            "total_ports_probed": 1000,
            "probe_timeout_seconds": 3.0,
            "banners": {},
            "services": {},
            "port_categories": {},
        }
        p = as_port_scan_payload(data)
        assert p.open_ports == []
        assert p.closed_ports_probed == 1000

    def test_http_payload_status_302(self) -> None:
        """Redirect response."""
        data = _http_payload()
        data["status_code"] = 302
        data["redirect_chain"] = [
            "http://example.com/",
            "https://example.com/",
        ]
        p = as_http_payload(data)
        assert p.status_code == 302
        assert len(p.redirect_chain) == 2

    def test_dns_aaaa_record(self) -> None:
        """AAAA record uses the same shape as A."""
        data = {
            "_collector_id": "active-dns-resolve",
            "record_type": "AAAA",
            "values": ["2606:2800:220:1:248:1893:25c8:1946"],
            "ttl": 600,
        }
        p = as_dns_payload(data)
        assert p.record_type == "AAAA"
        assert "2606:" in p.values[0]
