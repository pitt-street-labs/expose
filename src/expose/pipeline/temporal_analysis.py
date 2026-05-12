"""Temporal banner analysis — adapter shim.

This module previously contained the full temporal banner progression
detection engine (1048 lines, 5 pattern types).  The implementation has
been relocated to the commercial Threat Context module at
``expose.modules.threat_context.temporal_analysis``.

When the commercial module is installed, all classes, constants, and
helper functions are re-exported transparently — callers do not need to
change their imports.

When the commercial module is **not** installed (open-core distribution),
this adapter provides stub classes and functions that preserve the public
API surface but return empty / default results.
"""

from __future__ import annotations

try:
    # --- Commercial module available: re-export everything -------------------
    from expose.modules.threat_context.temporal_analysis import (  # noqa: F401
        BannerSnapshot,
        BannerTimeline,
        ProgressionDetector,
        ProgressionPattern,
        TemporalAnalysisResult,
        TemporalAnalyzer,
        TimelineBuilder,
        VALID_PATTERN_TYPES,
        VALID_SEVERITIES,
        _DEDUP_WINDOW_SECONDS,
        _MAX_TEMPORAL_DELTA,
        _TLS_VERSION_RANK,
        _SECURITY_HEADERS,
        _DEBUG_KEYWORDS,
        _STAGING_KEYWORDS,
        _sanitize,
        _sanitize_headers,
        _parse_timestamp,
        _snapshot_summary,
        _extract_version,
        _version_tuple,
        _extract_server_name,
        _classify_env_from_snapshot,
        _has_debug_indicators,
        _cert_identity,
        _is_self_signed,
    )

except ImportError:
    # --- Stubs for open-core distribution ------------------------------------
    from dataclasses import dataclass, field
    from datetime import UTC, datetime, timedelta
    from typing import Any

    # === Value types (frozen) =================================================

    @dataclass(frozen=True)
    class BannerSnapshot:  # type: ignore[no-redef]
        """A single point-in-time capture of banner/response data (stub)."""

        timestamp: datetime
        source: str
        banner_text: str | None = None
        headers: dict[str, str] = field(default_factory=dict)
        status_code: int | None = None
        tls_version: str | None = None
        server_header: str | None = None
        technologies: list[str] = field(default_factory=list)

    @dataclass(frozen=True)
    class BannerTimeline:  # type: ignore[no-redef]
        """An ordered sequence of banner snapshots for a single entity (stub)."""

        entity_identifier: str
        snapshots: list[BannerSnapshot]
        span_days: int

    @dataclass(frozen=True)
    class ProgressionPattern:  # type: ignore[no-redef]
        """A detected change pattern across the timeline (stub)."""

        pattern_type: str
        severity: str
        description: str
        evidence: list[dict[str, Any]]
        detected_at: datetime
        scoring_delta: int

    @dataclass(frozen=True)
    class TemporalAnalysisResult:  # type: ignore[no-redef]
        """Aggregate result of running all temporal detectors (stub)."""

        timeline: BannerTimeline
        patterns: list[ProgressionPattern]
        temporal_score_delta: int

    # === Constants ============================================================

    VALID_PATTERN_TYPES = frozenset({  # type: ignore[no-redef]
        "security_regression",
        "environment_promotion",
        "infrastructure_drift",
        "cert_lifecycle",
        "new_exposure",
    })

    VALID_SEVERITIES = frozenset({  # type: ignore[no-redef]
        "critical",
        "high",
        "medium",
        "low",
        "info",
    })

    _DEDUP_WINDOW_SECONDS = 3600
    _MAX_TEMPORAL_DELTA = 30

    _TLS_VERSION_RANK: dict[str, int] = {
        "SSLv2": 0,
        "SSLv3": 1,
        "TLSv1": 2,
        "TLSv1.0": 2,
        "TLSv1.1": 3,
        "TLSv1.2": 4,
        "TLSv1.3": 5,
    }

    _SECURITY_HEADERS = frozenset({
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "x-xss-protection",
    })

    _DEBUG_KEYWORDS = frozenset({
        "debug",
        "x-debug",
        "x-debug-token",
        "x-debug-mode",
    })

    _STAGING_KEYWORDS = frozenset({
        "staging",
        "dev",
        "development",
        "test",
        "sandbox",
        "preview",
        "canary",
        "internal",
        "preprod",
        "pre-prod",
        "uat",
    })

    # === Stub helper functions ================================================

    def _sanitize(value: str | None) -> str | None:
        """Stub: return value unchanged."""
        return value

    def _sanitize_headers(raw: dict[str, str]) -> dict[str, str]:
        """Stub: lowercase keys, pass values through."""
        return {k.lower(): v for k, v in raw.items()}

    def _parse_timestamp(value: Any) -> datetime | None:
        """Stub: minimal timestamp parsing."""
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=UTC)
            return value
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(value, tz=UTC)
            except (ValueError, OSError, OverflowError):
                return None
        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt
            except (ValueError, TypeError):
                pass
        return None

    def _snapshot_summary(snap: BannerSnapshot) -> dict[str, Any]:
        """Stub: build a serializable summary dict."""
        summary: dict[str, Any] = {
            "timestamp": snap.timestamp.isoformat(),
            "source": snap.source,
        }
        if snap.status_code is not None:
            summary["status_code"] = snap.status_code
        if snap.server_header:
            summary["server_header"] = snap.server_header
        if snap.tls_version:
            summary["tls_version"] = snap.tls_version
        if snap.banner_text:
            summary["banner_text"] = snap.banner_text[:200]
        if snap.technologies:
            summary["technologies"] = snap.technologies
        return summary

    def _extract_version(server_header: str) -> str | None:
        """Stub: extract version from server header."""
        import re
        match = re.search(r"/([\d]+(?:\.[\d]+)*)", server_header)
        return match.group(1) if match else None

    def _version_tuple(version_str: str) -> tuple[int, ...] | None:
        """Stub: parse version string into comparable tuple."""
        try:
            return tuple(int(p) for p in version_str.split("."))
        except (ValueError, AttributeError):
            return None

    def _extract_server_name(server_header: str) -> str:
        """Stub: extract server name before the slash."""
        return server_header.split("/")[0].strip().lower()

    def _classify_env_from_snapshot(snap: BannerSnapshot) -> str:
        """Stub: always returns 'production'."""
        return "production"

    def _has_debug_indicators(snap: BannerSnapshot) -> bool:
        """Stub: always returns False."""
        return False

    def _cert_identity(snap: BannerSnapshot) -> str | None:
        """Stub: returns None (no cert analysis)."""
        return None

    def _is_self_signed(snap: BannerSnapshot) -> bool | None:
        """Stub: returns None (insufficient data)."""
        return None

    # === Stub classes =========================================================

    class TimelineBuilder:  # type: ignore[no-redef]
        """Stub: builds empty timelines (commercial module not installed)."""

        def build_timeline(
            self,
            entity_identifier: str,
            observations: list[dict[str, Any]],
        ) -> BannerTimeline:
            """Return an empty timeline — no progression detection available."""
            return BannerTimeline(
                entity_identifier=entity_identifier,
                snapshots=[],
                span_days=0,
            )

    class ProgressionDetector:  # type: ignore[no-redef]
        """Stub: returns no patterns (commercial module not installed)."""

        def detect_patterns(self, timeline: BannerTimeline) -> list[ProgressionPattern]:
            """Return empty list — no progression detection available."""
            return []

    class TemporalAnalyzer:  # type: ignore[no-redef]
        """Stub: returns empty results (commercial module not installed)."""

        def __init__(self) -> None:
            self._builder = TimelineBuilder()
            self._detector = ProgressionDetector()

        def analyze(
            self,
            entity_identifier: str,
            observations: list[dict[str, Any]],
        ) -> TemporalAnalysisResult:
            """Return empty result — no progression detection available."""
            timeline = self._builder.build_timeline(entity_identifier, observations)
            return TemporalAnalysisResult(
                timeline=timeline,
                patterns=[],
                temporal_score_delta=0,
            )


__all__ = [
    "BannerSnapshot",
    "BannerTimeline",
    "ProgressionDetector",
    "ProgressionPattern",
    "TemporalAnalysisResult",
    "TemporalAnalyzer",
    "TimelineBuilder",
]
