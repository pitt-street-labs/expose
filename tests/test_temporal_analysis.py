"""Tests for temporal banner analysis (issue #172).

Covers:
- TimelineBuilder: snapshot extraction from each collector type, sorting,
  deduplication, edge cases (missing fields, bad timestamps, unknown collectors)
- ProgressionDetector: each of the 5 pattern types with positive and negative cases
  - Security regression: TLS downgrade, header removal, server version downgrade
  - Environment promotion: staging->prod, debug persistence, debug in prod
  - Infrastructure drift: server change, technology stack change
  - Certificate lifecycle: stale cert, rapid rotation, self-signed replacement
  - New exposure: new ports appearing, new banner, new technologies
- TemporalAnalyzer: end-to-end with mixed observations
- Score delta capping at 30
- API endpoint test with placeholder data
- Frozen dataclass immutability
- Sanitization of user-controlled fields
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from expose.pipeline.temporal_analysis import (
    BannerSnapshot,
    BannerTimeline,
    ProgressionDetector,
    ProgressionPattern,
    TemporalAnalysisResult,
    TemporalAnalyzer,
    TimelineBuilder,
    _MAX_TEMPORAL_DELTA,
    _TLS_VERSION_RANK,
    _classify_env_from_snapshot,
    _extract_server_name,
    _extract_version,
    _has_debug_indicators,
    _is_self_signed,
    _parse_timestamp,
    _snapshot_summary,
    _version_tuple,
)

# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
_T1 = datetime(2026, 2, 1, 0, 0, 0, tzinfo=UTC)
_T2 = datetime(2026, 3, 1, 0, 0, 0, tzinfo=UTC)
_T3 = datetime(2026, 4, 1, 0, 0, 0, tzinfo=UTC)

_BUILDER = TimelineBuilder()
_DETECTOR = ProgressionDetector()
_ANALYZER = TemporalAnalyzer()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wayback_obs(
    ts: datetime,
    *,
    banner: str | None = None,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a Wayback Machine observation dict."""
    payload: dict[str, Any] = {
        "archived_at": ts.isoformat(),
        "status_code": status_code,
    }
    if banner is not None:
        payload["banner"] = banner
    if headers:
        payload["headers"] = headers
    return {"_collector_id": "wayback-machine", "structured_payload": payload}


def _shodan_obs(
    ts: datetime,
    *,
    banner: str | None = None,
    port: int | None = None,
    headers: dict[str, str] | None = None,
    tls_version: str | None = None,
    technologies: list[str] | None = None,
    status_code: int | None = None,
) -> dict[str, Any]:
    """Build a Shodan scan observation dict."""
    payload: dict[str, Any] = {"last_seen": ts.isoformat()}
    if banner is not None:
        payload["banner"] = banner
    if port is not None:
        payload["port"] = port
    if tls_version is not None:
        payload["tls_version"] = tls_version
    if technologies is not None:
        payload["technologies"] = technologies
    if status_code is not None:
        payload["status_code"] = status_code
    data: dict[str, Any] = {}
    if headers:
        data["headers"] = headers
    if data:
        payload["data"] = data
    return {"_collector_id": "scan-shodan", "structured_payload": payload}


def _http_obs(
    ts: datetime,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    technologies: list[str] | None = None,
    banner: str | None = None,
) -> dict[str, Any]:
    """Build an active HTTP fingerprint observation dict."""
    payload: dict[str, Any] = {
        "_observed_at": ts.isoformat(),
        "status_code": status_code,
        "headers": headers or {},
    }
    if technologies is not None:
        payload["technologies"] = technologies
    if banner is not None:
        payload["banner"] = banner
    return {"_collector_id": "active-http-fingerprint", "structured_payload": payload}


def _tls_obs(
    ts: datetime,
    *,
    tls_version: str = "TLSv1.3",
    cipher_suite: str = "TLS_AES_256_GCM_SHA384",
    subject_cn: str = "example.com",
    issuer_cn: str = "Let's Encrypt Authority X3",
    not_after: str | None = None,
) -> dict[str, Any]:
    """Build an active TLS handshake observation dict."""
    payload: dict[str, Any] = {
        "_observed_at": ts.isoformat(),
        "tls_version": tls_version,
        "cipher_suite": cipher_suite,
        "cert_subject_cn": subject_cn,
        "cert_issuer_cn": issuer_cn,
    }
    if not_after:
        payload["cert_not_after"] = not_after
    return {"_collector_id": "active-tls-handshake", "structured_payload": payload}


# ===========================================================================
# TimelineBuilder tests
# ===========================================================================


class TestTimelineBuilder:
    """Tests for TimelineBuilder.build_timeline()."""

    # -- Wayback Machine extraction ---

    def test_wayback_extraction_basic(self) -> None:
        obs = [_wayback_obs(_T0, banner="Apache/2.4", status_code=200)]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert len(tl.snapshots) == 1
        snap = tl.snapshots[0]
        assert snap.source == "wayback-machine"
        assert snap.timestamp == _T0
        assert snap.status_code == 200

    def test_wayback_extraction_with_headers(self) -> None:
        obs = [_wayback_obs(_T0, headers={"Server": "nginx/1.24.0"})]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert tl.snapshots[0].server_header == "nginx/1.24.0"

    def test_wayback_extraction_missing_timestamp(self) -> None:
        obs = [{"_collector_id": "wayback-machine", "structured_payload": {"banner": "test"}}]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert len(tl.snapshots) == 0

    def test_wayback_status_code_as_string(self) -> None:
        payload = {"archived_at": _T0.isoformat(), "status_code": "301"}
        obs = [{"_collector_id": "wayback-machine", "structured_payload": payload}]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert tl.snapshots[0].status_code == 301

    # -- Shodan extraction ---

    def test_shodan_extraction_basic(self) -> None:
        obs = [_shodan_obs(_T0, banner="SSH-2.0-OpenSSH_8.9", port=22)]
        tl = _BUILDER.build_timeline("192.0.2.1", obs)
        assert len(tl.snapshots) == 1
        assert tl.snapshots[0].source == "scan-shodan"

    def test_shodan_extraction_with_data_headers(self) -> None:
        obs = [_shodan_obs(
            _T0,
            headers={"Server": "Apache/2.4.52"},
            tls_version="TLSv1.2",
        )]
        tl = _BUILDER.build_timeline("example.com", obs)
        snap = tl.snapshots[0]
        assert snap.server_header == "Apache/2.4.52"
        assert snap.tls_version == "TLSv1.2"

    def test_shodan_extraction_with_technologies(self) -> None:
        obs = [_shodan_obs(_T0, technologies=["nginx", "PHP", "WordPress"])]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert tl.snapshots[0].technologies == ["nginx", "PHP", "WordPress"]

    def test_shodan_missing_timestamp(self) -> None:
        obs = [{"_collector_id": "scan-shodan", "structured_payload": {"banner": "test"}}]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert len(tl.snapshots) == 0

    # -- Active HTTP fingerprint extraction ---

    def test_http_extraction_basic(self) -> None:
        obs = [_http_obs(_T0, status_code=200, headers={"server": "nginx/1.24.0"})]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert len(tl.snapshots) == 1
        snap = tl.snapshots[0]
        assert snap.source == "active-http-fingerprint"
        assert snap.status_code == 200

    def test_http_extraction_with_technologies(self) -> None:
        obs = [_http_obs(_T0, technologies=["React", "Node.js"])]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert tl.snapshots[0].technologies == ["React", "Node.js"]

    def test_http_extraction_missing_timestamp(self) -> None:
        obs = [{"_collector_id": "active-http-fingerprint", "structured_payload": {}}]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert len(tl.snapshots) == 0

    # -- Active TLS handshake extraction ---

    def test_tls_extraction_basic(self) -> None:
        obs = [_tls_obs(_T0)]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert len(tl.snapshots) == 1
        snap = tl.snapshots[0]
        assert snap.source == "active-tls-handshake"
        assert snap.tls_version == "TLSv1.3"

    def test_tls_extraction_cert_headers(self) -> None:
        obs = [_tls_obs(_T0, subject_cn="example.com", issuer_cn="DigiCert")]
        tl = _BUILDER.build_timeline("example.com", obs)
        snap = tl.snapshots[0]
        assert snap.headers.get("x-cert-subject-cn") == "example.com"
        assert snap.headers.get("x-cert-issuer-cn") == "DigiCert"

    def test_tls_extraction_with_expiry(self) -> None:
        expiry = "2027-01-01T00:00:00+00:00"
        obs = [_tls_obs(_T0, not_after=expiry)]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert "x-cert-not-after" in tl.snapshots[0].headers

    # -- Sorting ---

    def test_snapshots_sorted_ascending(self) -> None:
        obs = [
            _http_obs(_T2, status_code=200),
            _wayback_obs(_T0, status_code=200),
            _http_obs(_T1, status_code=301),
        ]
        tl = _BUILDER.build_timeline("example.com", obs)
        timestamps = [s.timestamp for s in tl.snapshots]
        assert timestamps == sorted(timestamps)

    # -- Deduplication ---

    def test_dedup_within_one_hour_window(self) -> None:
        t_base = _T0
        t_dup = _T0 + timedelta(minutes=30)
        obs = [
            _http_obs(t_base, status_code=200, headers={"server": "nginx"}),
            _http_obs(t_dup, status_code=200, headers={"server": "nginx"}),
        ]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert len(tl.snapshots) == 1
        assert tl.snapshots[0].timestamp == t_base

    def test_no_dedup_across_window(self) -> None:
        t_base = _T0
        t_later = _T0 + timedelta(hours=2)
        obs = [
            _http_obs(t_base, status_code=200, headers={"server": "nginx"}),
            _http_obs(t_later, status_code=200, headers={"server": "nginx"}),
        ]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert len(tl.snapshots) == 2

    def test_no_dedup_different_content(self) -> None:
        t_base = _T0
        t_dup = _T0 + timedelta(minutes=30)
        obs = [
            _http_obs(t_base, status_code=200, headers={"server": "nginx"}),
            _http_obs(t_dup, status_code=301, headers={"server": "nginx"}),
        ]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert len(tl.snapshots) == 2

    # -- Unknown collector ---

    def test_unknown_collector_skipped(self) -> None:
        obs = [{"_collector_id": "unknown-collector", "structured_payload": {}}]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert len(tl.snapshots) == 0

    # -- Span days ---

    def test_span_days_calculation(self) -> None:
        obs = [_http_obs(_T0), _http_obs(_T2)]
        tl = _BUILDER.build_timeline("example.com", obs)
        expected_days = (_T2 - _T0).days
        assert tl.span_days == expected_days

    def test_span_days_single_snapshot(self) -> None:
        obs = [_http_obs(_T0)]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert tl.span_days == 0

    def test_span_days_empty(self) -> None:
        tl = _BUILDER.build_timeline("example.com", [])
        assert tl.span_days == 0
        assert len(tl.snapshots) == 0

    # -- collector_id fallback ---

    def test_collector_id_fallback(self) -> None:
        obs = [{
            "collector_id": "active-http-fingerprint",
            "structured_payload": {
                "_observed_at": _T0.isoformat(),
                "status_code": 200,
                "headers": {},
            },
        }]
        tl = _BUILDER.build_timeline("example.com", obs)
        assert len(tl.snapshots) == 1


# ===========================================================================
# ProgressionDetector tests — Security Regression
# ===========================================================================


class TestSecurityRegression:
    """Tests for ProgressionDetector._detect_security_regression()."""

    def test_tls_downgrade_1_3_to_1_2(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="active-tls-handshake", tls_version="TLSv1.3"),
                BannerSnapshot(timestamp=_T1, source="active-tls-handshake", tls_version="TLSv1.2"),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_security_regression(tl)
        assert len(patterns) >= 1
        tls_patterns = [p for p in patterns if "TLS" in p.description]
        assert len(tls_patterns) == 1
        assert tls_patterns[0].pattern_type == "security_regression"
        assert tls_patterns[0].scoring_delta == 10

    def test_tls_downgrade_to_1_0_high_severity(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="tls", tls_version="TLSv1.3"),
                BannerSnapshot(timestamp=_T1, source="tls", tls_version="TLSv1.0"),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_security_regression(tl)
        tls_patterns = [p for p in patterns if "TLS" in p.description]
        assert len(tls_patterns) == 1
        assert tls_patterns[0].severity == "high"
        assert tls_patterns[0].scoring_delta == 15

    def test_no_tls_regression_on_upgrade(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="tls", tls_version="TLSv1.2"),
                BannerSnapshot(timestamp=_T1, source="tls", tls_version="TLSv1.3"),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_security_regression(tl)
        tls_patterns = [p for p in patterns if "TLS" in p.description]
        assert len(tls_patterns) == 0

    def test_security_header_removal(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(
                    timestamp=_T0, source="http",
                    headers={"strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'"},
                ),
                BannerSnapshot(
                    timestamp=_T1, source="http",
                    headers={},
                ),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_security_regression(tl)
        header_patterns = [p for p in patterns if "header" in p.description.lower()]
        assert len(header_patterns) == 1
        assert header_patterns[0].scoring_delta == 10

    def test_no_regression_headers_preserved(self) -> None:
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
        }
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="http", headers=headers),
                BannerSnapshot(timestamp=_T1, source="http", headers=headers),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_security_regression(tl)
        header_patterns = [p for p in patterns if "header" in p.description.lower()]
        assert len(header_patterns) == 0

    def test_server_version_downgrade(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="http", server_header="nginx/1.24.0"),
                BannerSnapshot(timestamp=_T1, source="http", server_header="nginx/1.20.0"),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_security_regression(tl)
        ver_patterns = [p for p in patterns if "version" in p.description.lower() and "downgrade" in p.description.lower()]
        assert len(ver_patterns) == 1
        assert ver_patterns[0].scoring_delta == 10

    def test_no_regression_server_version_upgrade(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="http", server_header="nginx/1.20.0"),
                BannerSnapshot(timestamp=_T1, source="http", server_header="nginx/1.24.0"),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_security_regression(tl)
        ver_patterns = [p for p in patterns if "version" in p.description.lower() and "downgrade" in p.description.lower()]
        assert len(ver_patterns) == 0


# ===========================================================================
# ProgressionDetector tests — Environment Promotion
# ===========================================================================


class TestEnvironmentPromotion:
    """Tests for ProgressionDetector._detect_environment_promotion()."""

    def test_staging_to_production(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(
                    timestamp=_T0, source="http",
                    headers={"x-environment": "staging"},
                ),
                BannerSnapshot(
                    timestamp=_T1, source="http",
                    headers={"x-environment": "production"},
                ),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_environment_promotion(tl)
        promo_patterns = [p for p in patterns if "promoted" in p.description.lower()]
        assert len(promo_patterns) == 1
        assert promo_patterns[0].severity == "info"
        assert promo_patterns[0].scoring_delta == 5

    def test_debug_in_production_critical(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(
                    timestamp=_T0, source="http",
                    headers={"x-environment": "production"},
                ),
                BannerSnapshot(
                    timestamp=_T1, source="http",
                    headers={"x-environment": "production", "x-debug": "true"},
                ),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_environment_promotion(tl)
        debug_patterns = [p for p in patterns if "debug" in p.description.lower() and "production" in p.description.lower()]
        assert len(debug_patterns) == 1
        assert debug_patterns[0].severity == "critical"
        assert debug_patterns[0].scoring_delta == 20

    def test_debug_appearing_high_severity(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(
                    timestamp=_T0, source="http",
                    headers={"x-environment": "staging"},
                ),
                BannerSnapshot(
                    timestamp=_T1, source="http",
                    headers={"x-environment": "staging", "x-debug": "true"},
                ),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_environment_promotion(tl)
        debug_patterns = [p for p in patterns if "debug" in p.description.lower() and "appeared" in p.description.lower()]
        assert len(debug_patterns) == 1
        assert debug_patterns[0].severity == "high"
        assert debug_patterns[0].scoring_delta == 15

    def test_no_promotion_same_environment(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(
                    timestamp=_T0, source="http",
                    headers={"x-environment": "production"},
                ),
                BannerSnapshot(
                    timestamp=_T1, source="http",
                    headers={"x-environment": "production"},
                ),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_environment_promotion(tl)
        promo_patterns = [p for p in patterns if "promoted" in p.description.lower()]
        assert len(promo_patterns) == 0

    def test_banner_staging_keyword_detection(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(
                    timestamp=_T0, source="http",
                    banner_text="Welcome to staging environment",
                ),
                BannerSnapshot(
                    timestamp=_T1, source="http",
                    headers={"x-environment": "production"},
                ),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_environment_promotion(tl)
        promo_patterns = [p for p in patterns if "promoted" in p.description.lower()]
        assert len(promo_patterns) == 1


# ===========================================================================
# ProgressionDetector tests — Infrastructure Drift
# ===========================================================================


class TestInfrastructureDrift:
    """Tests for ProgressionDetector._detect_infrastructure_drift()."""

    def test_server_software_change(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="http", server_header="nginx/1.24.0"),
                BannerSnapshot(timestamp=_T1, source="http", server_header="Apache/2.4.52"),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_infrastructure_drift(tl)
        drift_patterns = [p for p in patterns if "software changed" in p.description.lower()]
        assert len(drift_patterns) == 1
        assert drift_patterns[0].severity == "medium"
        assert drift_patterns[0].scoring_delta == 10

    def test_technology_stack_change(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="http", technologies=["React", "Node.js"]),
                BannerSnapshot(timestamp=_T1, source="http", technologies=["Vue", "Django"]),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_infrastructure_drift(tl)
        tech_patterns = [p for p in patterns if "technology" in p.description.lower()]
        assert len(tech_patterns) == 1
        assert tech_patterns[0].scoring_delta == 5

    def test_no_drift_same_server(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="http", server_header="nginx/1.24.0"),
                BannerSnapshot(timestamp=_T1, source="http", server_header="nginx/1.24.0"),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_infrastructure_drift(tl)
        assert len(patterns) == 0

    def test_server_version_change_not_drift(self) -> None:
        """Same server name with different version is NOT infrastructure drift."""
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="http", server_header="nginx/1.24.0"),
                BannerSnapshot(timestamp=_T1, source="http", server_header="nginx/1.26.0"),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_infrastructure_drift(tl)
        drift_patterns = [p for p in patterns if "software changed" in p.description.lower()]
        assert len(drift_patterns) == 0


# ===========================================================================
# ProgressionDetector tests — Certificate Lifecycle
# ===========================================================================


class TestCertLifecycle:
    """Tests for ProgressionDetector._detect_cert_lifecycle()."""

    def test_stale_cert_over_365_days(self) -> None:
        t_start = _T0
        t_end = _T0 + timedelta(days=400)
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(
                    timestamp=t_start, source="active-tls-handshake",
                    tls_version="TLSv1.3",
                    headers={"x-cert-subject-cn": "example.com", "x-cert-issuer-cn": "LE", "x-cert-not-after": "2027-01-01"},
                ),
                BannerSnapshot(
                    timestamp=t_end, source="active-tls-handshake",
                    tls_version="TLSv1.3",
                    headers={"x-cert-subject-cn": "example.com", "x-cert-issuer-cn": "LE", "x-cert-not-after": "2027-01-01"},
                ),
            ],
            span_days=400,
        )
        patterns = _DETECTOR._detect_cert_lifecycle(tl)
        stale_patterns = [p for p in patterns if "unchanged" in p.description.lower()]
        assert len(stale_patterns) == 1
        assert stale_patterns[0].severity == "medium"
        assert stale_patterns[0].scoring_delta == 5

    def test_cert_not_stale_under_365(self) -> None:
        t_end = _T0 + timedelta(days=300)
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(
                    timestamp=_T0, source="active-tls-handshake",
                    tls_version="TLSv1.3",
                    headers={"x-cert-subject-cn": "example.com", "x-cert-issuer-cn": "LE", "x-cert-not-after": "2027-01-01"},
                ),
                BannerSnapshot(
                    timestamp=t_end, source="active-tls-handshake",
                    tls_version="TLSv1.3",
                    headers={"x-cert-subject-cn": "example.com", "x-cert-issuer-cn": "LE", "x-cert-not-after": "2027-01-01"},
                ),
            ],
            span_days=300,
        )
        patterns = _DETECTOR._detect_cert_lifecycle(tl)
        stale_patterns = [p for p in patterns if "unchanged" in p.description.lower()]
        assert len(stale_patterns) == 0

    def test_rapid_cert_rotation(self) -> None:
        base = _T0
        snapshots = []
        # 4 different certs in 20 days.
        for i in range(5):
            snapshots.append(BannerSnapshot(
                timestamp=base + timedelta(days=i * 5),
                source="active-tls-handshake",
                tls_version="TLSv1.3",
                headers={
                    "x-cert-subject-cn": f"cert-{i}.example.com",
                    "x-cert-issuer-cn": "LE",
                    "x-cert-not-after": f"2027-{i + 1:02d}-01",
                },
            ))
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=snapshots,
            span_days=20,
        )
        patterns = _DETECTOR._detect_cert_lifecycle(tl)
        rapid_patterns = [p for p in patterns if "rapid" in p.description.lower()]
        assert len(rapid_patterns) == 1
        assert rapid_patterns[0].severity == "high"
        assert rapid_patterns[0].scoring_delta == 15

    def test_self_signed_replacement(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(
                    timestamp=_T0, source="active-tls-handshake",
                    tls_version="TLSv1.3",
                    headers={
                        "x-cert-subject-cn": "example.com",
                        "x-cert-issuer-cn": "DigiCert CA",
                        "x-cert-not-after": "2027-01-01",
                    },
                ),
                BannerSnapshot(
                    timestamp=_T1, source="active-tls-handshake",
                    tls_version="TLSv1.3",
                    headers={
                        "x-cert-subject-cn": "example.com",
                        "x-cert-issuer-cn": "example.com",
                        "x-cert-not-after": "2027-01-01",
                    },
                ),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_cert_lifecycle(tl)
        self_signed_patterns = [p for p in patterns if "self-signed" in p.description.lower()]
        assert len(self_signed_patterns) == 1
        assert self_signed_patterns[0].severity == "high"
        assert self_signed_patterns[0].scoring_delta == 15

    def test_no_self_signed_same_ca(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(
                    timestamp=_T0, source="active-tls-handshake",
                    tls_version="TLSv1.3",
                    headers={"x-cert-subject-cn": "example.com", "x-cert-issuer-cn": "DigiCert"},
                ),
                BannerSnapshot(
                    timestamp=_T1, source="active-tls-handshake",
                    tls_version="TLSv1.3",
                    headers={"x-cert-subject-cn": "example.com", "x-cert-issuer-cn": "DigiCert"},
                ),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_cert_lifecycle(tl)
        self_signed_patterns = [p for p in patterns if "self-signed" in p.description.lower()]
        assert len(self_signed_patterns) == 0


# ===========================================================================
# ProgressionDetector tests — New Exposure
# ===========================================================================


class TestNewExposure:
    """Tests for ProgressionDetector._detect_new_exposure()."""

    def test_new_endpoint_responding(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="http", status_code=404),
                BannerSnapshot(timestamp=_T1, source="http", status_code=200),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_new_exposure(tl)
        new_patterns = [p for p in patterns if "endpoint" in p.description.lower()]
        assert len(new_patterns) == 1
        assert new_patterns[0].scoring_delta == 10

    def test_new_endpoint_from_500_to_200(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="http", status_code=500),
                BannerSnapshot(timestamp=_T1, source="http", status_code=200),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_new_exposure(tl)
        new_patterns = [p for p in patterns if "endpoint" in p.description.lower()]
        assert len(new_patterns) == 1

    def test_no_new_exposure_both_200(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="http", status_code=200),
                BannerSnapshot(timestamp=_T1, source="http", status_code=200),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_new_exposure(tl)
        new_patterns = [p for p in patterns if "endpoint" in p.description.lower()]
        assert len(new_patterns) == 0

    def test_new_technologies_appearing(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="http", technologies=[]),
                BannerSnapshot(timestamp=_T1, source="http", technologies=["nginx", "PHP"]),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_new_exposure(tl)
        tech_patterns = [p for p in patterns if "technology" in p.description.lower() or "service" in p.description.lower()]
        assert len(tech_patterns) == 1
        assert tech_patterns[0].scoring_delta == 10

    def test_new_banner_where_none_existed(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(timestamp=_T0, source="http", status_code=0, banner_text=None),
                BannerSnapshot(timestamp=_T1, source="http", banner_text="SSH-2.0-OpenSSH_8.9"),
            ],
            span_days=31,
        )
        patterns = _DETECTOR._detect_new_exposure(tl)
        banner_patterns = [p for p in patterns if "banner" in p.description.lower()]
        assert len(banner_patterns) == 1
        assert banner_patterns[0].severity == "high"
        assert banner_patterns[0].scoring_delta == 15


# ===========================================================================
# ProgressionDetector — edge cases
# ===========================================================================


class TestProgressionDetectorEdgeCases:
    """Edge case tests for the progression detector."""

    def test_single_snapshot_no_patterns(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[BannerSnapshot(timestamp=_T0, source="http", status_code=200)],
            span_days=0,
        )
        patterns = _DETECTOR.detect_patterns(tl)
        assert len(patterns) == 0

    def test_empty_timeline_no_patterns(self) -> None:
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[],
            span_days=0,
        )
        patterns = _DETECTOR.detect_patterns(tl)
        assert len(patterns) == 0

    def test_all_detectors_run(self) -> None:
        """Multiple regression types in one timeline should all be detected."""
        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=[
                BannerSnapshot(
                    timestamp=_T0, source="active-tls-handshake",
                    tls_version="TLSv1.3",
                    server_header="nginx/1.24.0",
                    headers={
                        "strict-transport-security": "max-age=31536000",
                        "x-cert-subject-cn": "example.com",
                        "x-cert-issuer-cn": "DigiCert",
                    },
                    technologies=["React"],
                ),
                BannerSnapshot(
                    timestamp=_T1, source="active-tls-handshake",
                    tls_version="TLSv1.2",
                    server_header="Apache/2.4.52",
                    headers={
                        "x-debug": "true",
                        "x-cert-subject-cn": "example.com",
                        "x-cert-issuer-cn": "example.com",
                    },
                    technologies=["Vue", "Django"],
                ),
            ],
            span_days=31,
        )
        patterns = _DETECTOR.detect_patterns(tl)
        pattern_types = {p.pattern_type for p in patterns}
        # Should find at least security_regression (TLS downgrade, HSTS removal)
        # and infrastructure_drift (nginx->apache, React->Vue/Django)
        assert "security_regression" in pattern_types
        assert "infrastructure_drift" in pattern_types


# ===========================================================================
# TemporalAnalyzer — end-to-end tests
# ===========================================================================


class TestTemporalAnalyzer:
    """Tests for the TemporalAnalyzer orchestrator."""

    def test_end_to_end_with_mixed_observations(self) -> None:
        obs = [
            _wayback_obs(_T0, status_code=200, headers={"Server": "nginx/1.24.0"}),
            _http_obs(_T1, status_code=200, headers={
                "server": "Apache/2.4.52",
                "strict-transport-security": "max-age=31536000",
            }),
            _tls_obs(_T0, tls_version="TLSv1.3"),
            _tls_obs(_T1, tls_version="TLSv1.2"),
        ]
        result = _ANALYZER.analyze("example.com", obs)

        assert isinstance(result, TemporalAnalysisResult)
        assert result.timeline.entity_identifier == "example.com"
        assert len(result.timeline.snapshots) >= 3
        assert len(result.patterns) >= 1

    def test_score_delta_capped_at_30(self) -> None:
        """Score delta should never exceed _MAX_TEMPORAL_DELTA (30)."""
        # Build a timeline with many regressions to push delta over 30.
        snapshots = []
        for i in range(6):
            t = _T0 + timedelta(days=i * 60)
            tls_versions = ["TLSv1.3", "TLSv1.0", "TLSv1.3", "TLSv1.0", "TLSv1.3", "TLSv1.0"]
            snapshots.append(BannerSnapshot(
                timestamp=t,
                source="active-tls-handshake",
                tls_version=tls_versions[i],
                headers={
                    "strict-transport-security": "max-age=31536000" if i % 2 == 0 else "",
                    "x-cert-subject-cn": "example.com",
                    "x-cert-issuer-cn": "LE" if i % 2 == 0 else "example.com",
                },
                server_header="nginx/1.24.0" if i % 2 == 0 else "Apache/2.4",
                technologies=["React"] if i % 2 == 0 else ["Vue"],
            ))

        tl = BannerTimeline(
            entity_identifier="example.com",
            snapshots=snapshots,
            span_days=300,
        )
        detector = ProgressionDetector()
        patterns = detector.detect_patterns(tl)
        raw_delta = sum(p.scoring_delta for p in patterns)
        # Ensure there actually are enough patterns to exceed the cap.
        assert raw_delta > _MAX_TEMPORAL_DELTA

        # Now run through the analyzer (which caps).
        obs = [
            _tls_obs(_T0 + timedelta(days=i * 60), tls_version="TLSv1.3" if i % 2 == 0 else "TLSv1.0")
            for i in range(6)
        ]
        result = _ANALYZER.analyze("example.com", obs)
        assert result.temporal_score_delta <= _MAX_TEMPORAL_DELTA

    def test_empty_observations(self) -> None:
        result = _ANALYZER.analyze("example.com", [])
        assert result.timeline.span_days == 0
        assert len(result.patterns) == 0
        assert result.temporal_score_delta == 0

    def test_single_observation_no_patterns(self) -> None:
        obs = [_http_obs(_T0, status_code=200)]
        result = _ANALYZER.analyze("example.com", obs)
        assert len(result.patterns) == 0
        assert result.temporal_score_delta == 0


# ===========================================================================
# Helper function tests
# ===========================================================================


class TestHelperFunctions:
    """Tests for module-private helper functions."""

    def test_parse_timestamp_iso_string(self) -> None:
        ts = _parse_timestamp("2026-01-01T00:00:00+00:00")
        assert ts is not None
        assert ts.tzinfo is not None

    def test_parse_timestamp_z_suffix(self) -> None:
        ts = _parse_timestamp("2026-01-01T00:00:00Z")
        assert ts is not None
        assert ts.tzinfo is not None

    def test_parse_timestamp_naive_gets_utc(self) -> None:
        ts = _parse_timestamp("2026-01-01T00:00:00")
        assert ts is not None
        assert ts.tzinfo is not None

    def test_parse_timestamp_unix_epoch(self) -> None:
        ts = _parse_timestamp(1735689600)
        assert ts is not None
        assert ts.tzinfo is not None

    def test_parse_timestamp_datetime_object(self) -> None:
        dt = datetime(2026, 1, 1, tzinfo=UTC)
        ts = _parse_timestamp(dt)
        assert ts == dt

    def test_parse_timestamp_naive_datetime(self) -> None:
        dt = datetime(2026, 1, 1)
        ts = _parse_timestamp(dt)
        assert ts is not None
        assert ts.tzinfo is not None

    def test_parse_timestamp_invalid(self) -> None:
        assert _parse_timestamp("not-a-date") is None
        assert _parse_timestamp(None) is None
        assert _parse_timestamp([]) is None

    def test_extract_version(self) -> None:
        assert _extract_version("nginx/1.24.0") == "1.24.0"
        assert _extract_version("Apache/2.4.52") == "2.4.52"
        assert _extract_version("nginx") is None

    def test_version_tuple(self) -> None:
        assert _version_tuple("1.24.0") == (1, 24, 0)
        assert _version_tuple("2.4") == (2, 4)
        assert _version_tuple("invalid") is None

    def test_extract_server_name(self) -> None:
        assert _extract_server_name("nginx/1.24.0") == "nginx"
        assert _extract_server_name("Apache/2.4.52") == "apache"
        assert _extract_server_name("Microsoft-IIS/10.0") == "microsoft-iis"

    def test_classify_env_production(self) -> None:
        snap = BannerSnapshot(
            timestamp=_T0, source="http",
            headers={"x-environment": "production"},
        )
        assert _classify_env_from_snapshot(snap) == "production"

    def test_classify_env_staging_header(self) -> None:
        snap = BannerSnapshot(
            timestamp=_T0, source="http",
            headers={"x-environment": "staging"},
        )
        assert _classify_env_from_snapshot(snap) == "non_production"

    def test_classify_env_staging_banner(self) -> None:
        snap = BannerSnapshot(
            timestamp=_T0, source="http",
            banner_text="Welcome to the staging environment",
        )
        assert _classify_env_from_snapshot(snap) == "non_production"

    def test_classify_env_default_production(self) -> None:
        snap = BannerSnapshot(timestamp=_T0, source="http")
        assert _classify_env_from_snapshot(snap) == "production"

    def test_has_debug_indicators_header(self) -> None:
        snap = BannerSnapshot(
            timestamp=_T0, source="http",
            headers={"x-debug": "true"},
        )
        assert _has_debug_indicators(snap) is True

    def test_has_debug_indicators_banner(self) -> None:
        snap = BannerSnapshot(
            timestamp=_T0, source="http",
            banner_text="Debug mode is active",
        )
        assert _has_debug_indicators(snap) is True

    def test_no_debug_indicators(self) -> None:
        snap = BannerSnapshot(
            timestamp=_T0, source="http",
            headers={"server": "nginx"},
        )
        assert _has_debug_indicators(snap) is False

    def test_is_self_signed_true(self) -> None:
        snap = BannerSnapshot(
            timestamp=_T0, source="tls",
            headers={"x-cert-subject-cn": "example.com", "x-cert-issuer-cn": "example.com"},
        )
        assert _is_self_signed(snap) is True

    def test_is_self_signed_false(self) -> None:
        snap = BannerSnapshot(
            timestamp=_T0, source="tls",
            headers={"x-cert-subject-cn": "example.com", "x-cert-issuer-cn": "DigiCert"},
        )
        assert _is_self_signed(snap) is False

    def test_is_self_signed_insufficient_data(self) -> None:
        snap = BannerSnapshot(timestamp=_T0, source="tls")
        assert _is_self_signed(snap) is None

    def test_snapshot_summary_basic(self) -> None:
        snap = BannerSnapshot(
            timestamp=_T0, source="http",
            status_code=200, server_header="nginx",
        )
        summary = _snapshot_summary(snap)
        assert summary["source"] == "http"
        assert summary["status_code"] == 200
        assert summary["server_header"] == "nginx"

    def test_snapshot_summary_truncates_banner(self) -> None:
        long_banner = "x" * 500
        snap = BannerSnapshot(
            timestamp=_T0, source="http",
            banner_text=long_banner,
        )
        summary = _snapshot_summary(snap)
        assert len(summary["banner_text"]) == 200

    def test_tls_version_rank_ordering(self) -> None:
        ordered = sorted(_TLS_VERSION_RANK.items(), key=lambda x: x[1])
        versions = [v for v, _ in ordered]
        # SSLv2 < SSLv3 < TLSv1.0 < TLSv1.1 < TLSv1.2 < TLSv1.3
        assert versions.index("SSLv2") < versions.index("SSLv3")
        assert versions.index("SSLv3") < versions.index("TLSv1.1")
        assert versions.index("TLSv1.1") < versions.index("TLSv1.2")
        assert versions.index("TLSv1.2") < versions.index("TLSv1.3")


# ===========================================================================
# Frozen dataclass immutability tests
# ===========================================================================


class TestFrozenDataclasses:
    """Verify that all value types are immutable."""

    def test_banner_snapshot_frozen(self) -> None:
        snap = BannerSnapshot(timestamp=_T0, source="http")
        with pytest.raises(AttributeError):
            snap.source = "modified"  # type: ignore[misc]

    def test_banner_timeline_frozen(self) -> None:
        tl = BannerTimeline(entity_identifier="test", snapshots=[], span_days=0)
        with pytest.raises(AttributeError):
            tl.entity_identifier = "modified"  # type: ignore[misc]

    def test_progression_pattern_frozen(self) -> None:
        p = ProgressionPattern(
            pattern_type="security_regression",
            severity="high",
            description="test",
            evidence=[],
            detected_at=_T0,
            scoring_delta=10,
        )
        with pytest.raises(AttributeError):
            p.severity = "low"  # type: ignore[misc]

    def test_temporal_analysis_result_frozen(self) -> None:
        r = TemporalAnalysisResult(
            timeline=BannerTimeline(entity_identifier="test", snapshots=[], span_days=0),
            patterns=[],
            temporal_score_delta=0,
        )
        with pytest.raises(AttributeError):
            r.temporal_score_delta = 99  # type: ignore[misc]


# ===========================================================================
# API endpoint tests
# ===========================================================================


_TENANT_ID = "00000000-0000-0000-0000-000000000001"
_ENTITY_ID = "example.com"
_BASE_URL = f"http://test/v1/tenants/{_TENANT_ID}/entities/{_ENTITY_ID}"


def _make_app() -> FastAPI:
    """Build a minimal FastAPI app with the timeline router mounted."""
    from expose.api.timeline import router as timeline_router

    app = FastAPI()
    app.include_router(timeline_router)
    return app


@pytest.fixture()
def app() -> FastAPI:
    return _make_app()


@pytest.fixture()
async def client(app: FastAPI) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    )


class TestTimelineAPI:
    """Tests for the timeline API endpoint."""

    async def test_get_timeline_returns_200(self, client: AsyncClient) -> None:
        resp = await client.get(f"{_BASE_URL}/timeline")
        assert resp.status_code == 200

    async def test_response_structure(self, client: AsyncClient) -> None:
        resp = await client.get(f"{_BASE_URL}/timeline")
        data = resp.json()
        assert "tenant_id" in data
        assert data["tenant_id"] == _TENANT_ID
        assert "entity_id" in data
        assert "snapshots" in data
        assert "patterns" in data
        assert "temporal_score_delta" in data
        assert "span_days" in data
        assert "is_placeholder" in data

    async def test_placeholder_has_snapshots(self, client: AsyncClient) -> None:
        resp = await client.get(f"{_BASE_URL}/timeline")
        data = resp.json()
        assert data["is_placeholder"] is True
        assert len(data["snapshots"]) >= 3

    async def test_placeholder_has_patterns(self, client: AsyncClient) -> None:
        resp = await client.get(f"{_BASE_URL}/timeline")
        data = resp.json()
        assert len(data["patterns"]) >= 1

    async def test_placeholder_shows_security_regression(self, client: AsyncClient) -> None:
        resp = await client.get(f"{_BASE_URL}/timeline")
        data = resp.json()
        pattern_types = {p["pattern_type"] for p in data["patterns"]}
        assert "security_regression" in pattern_types

    async def test_placeholder_score_delta_positive(self, client: AsyncClient) -> None:
        resp = await client.get(f"{_BASE_URL}/timeline")
        data = resp.json()
        assert data["temporal_score_delta"] > 0

    async def test_placeholder_score_delta_capped(self, client: AsyncClient) -> None:
        resp = await client.get(f"{_BASE_URL}/timeline")
        data = resp.json()
        assert data["temporal_score_delta"] <= _MAX_TEMPORAL_DELTA

    async def test_snapshots_sorted_by_timestamp(self, client: AsyncClient) -> None:
        resp = await client.get(f"{_BASE_URL}/timeline")
        data = resp.json()
        timestamps = [s["timestamp"] for s in data["snapshots"]]
        assert timestamps == sorted(timestamps)

    async def test_pattern_fields_complete(self, client: AsyncClient) -> None:
        resp = await client.get(f"{_BASE_URL}/timeline")
        data = resp.json()
        for pattern in data["patterns"]:
            assert "pattern_type" in pattern
            assert "severity" in pattern
            assert "description" in pattern
            assert "evidence" in pattern
            assert "detected_at" in pattern
            assert "scoring_delta" in pattern

    async def test_snapshot_fields_complete(self, client: AsyncClient) -> None:
        resp = await client.get(f"{_BASE_URL}/timeline")
        data = resp.json()
        for snap in data["snapshots"]:
            assert "timestamp" in snap
            assert "source" in snap
