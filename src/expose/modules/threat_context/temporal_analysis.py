"""Temporal banner analysis — detect progression patterns in historical banner data.

Combines historical banner/response data from Wayback Machine and Shodan with
fresh active captures, then detects progression patterns and security posture
changes over time.  This is a pure E1 (deterministic) module — no I/O, no LLM
calls, no database access.  The API endpoint (``expose.api.timeline``) handles
DB access; the analysis classes take observation dicts.

Implements issue #172.

Detection categories:

- **Security regression** — TLS downgrade, security header removal, server
  version downgrade.
- **Environment promotion** — staging-to-prod transitions, debug mode
  persistence after promotion.
- **Infrastructure drift** — server software or technology stack changes.
- **Certificate lifecycle** — stale certs, rapid rotation, self-signed
  replacement.
- **New exposure** — ports/services appearing that were absent in earlier
  snapshots.
"""

from __future__ import annotations

# Copyright 2026 Korlogos / Pitt Street Labs. All rights reserved.
# This file is part of EXPOSE Commercial Modules and is NOT covered by the
# Apache 2.0 license that governs the core engine. Unauthorized copying,
# distribution, or use of this file is strictly prohibited. Contact
# licensing@korlogos.com for commercial licensing terms.

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from expose.sanitization.text import SanitizationFieldKind, sanitize_field

# === Value types (frozen) =====================================================


@dataclass(frozen=True)
class BannerSnapshot:
    """A single point-in-time capture of banner/response data.

    Represents one observation from any source — Wayback Machine, Shodan,
    or a live active scan.  All string fields are sanitized on construction
    via the factory methods in :class:`TimelineBuilder`.
    """

    timestamp: datetime
    source: str
    banner_text: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    status_code: int | None = None
    tls_version: str | None = None
    server_header: str | None = None
    technologies: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class BannerTimeline:
    """An ordered sequence of banner snapshots for a single entity.

    Snapshots are sorted by timestamp ascending.  ``span_days`` is the
    calendar-day gap between the first and last snapshot (0 for a single
    snapshot).
    """

    entity_identifier: str
    snapshots: list[BannerSnapshot]
    span_days: int


@dataclass(frozen=True)
class ProgressionPattern:
    """A detected change pattern across the timeline.

    ``pattern_type`` uses a closed vocabulary of string constants rather
    than an ``Enum`` to keep the module's JSON-serialization surface minimal
    (FastAPI serializes strings natively).

    ``evidence`` carries before/after snapshots as dicts for easy
    serialization.  ``scoring_delta`` is the lead-score contribution
    (positive = riskier).
    """

    pattern_type: str  # security_regression | environment_promotion | infrastructure_drift | cert_lifecycle | new_exposure
    severity: str  # critical | high | medium | low | info
    description: str
    evidence: list[dict[str, Any]]
    detected_at: datetime
    scoring_delta: int


@dataclass(frozen=True)
class TemporalAnalysisResult:
    """Aggregate result of running all temporal detectors on one entity.

    ``temporal_score_delta`` is the sum of all pattern deltas, capped at 30
    to avoid dominating the composite lead score.
    """

    timeline: BannerTimeline
    patterns: list[ProgressionPattern]
    temporal_score_delta: int


# === Constants ================================================================

VALID_PATTERN_TYPES = frozenset({
    "security_regression",
    "environment_promotion",
    "infrastructure_drift",
    "cert_lifecycle",
    "new_exposure",
})

VALID_SEVERITIES = frozenset({
    "critical",
    "high",
    "medium",
    "low",
    "info",
})

# Deduplication window — snapshots within this many seconds of each other
# with near-identical content are collapsed to one.
_DEDUP_WINDOW_SECONDS = 3600  # 1 hour

# Maximum temporal score delta contribution.
_MAX_TEMPORAL_DELTA = 30

# TLS version ordering for downgrade detection (higher is better).
_TLS_VERSION_RANK: dict[str, int] = {
    "SSLv2": 0,
    "SSLv3": 1,
    "TLSv1": 2,
    "TLSv1.0": 2,
    "TLSv1.1": 3,
    "TLSv1.2": 4,
    "TLSv1.3": 5,
}

# Security headers whose removal constitutes a regression.
_SECURITY_HEADERS = frozenset({
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
})

# Keywords indicating non-production / debug environments.
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


# === Sanitization helper =====================================================


def _sanitize(value: str | None) -> str | None:
    """Sanitize a user-controlled string field, returning None for empty."""
    if value is None:
        return None
    result = sanitize_field(value, SanitizationFieldKind.GENERIC)
    return result.value if result.value else None


def _sanitize_headers(raw: dict[str, str]) -> dict[str, str]:
    """Sanitize header names and values, lowercasing keys for comparison."""
    out: dict[str, str] = {}
    for k, v in raw.items():
        clean_k = sanitize_field(k.lower(), SanitizationFieldKind.GENERIC).value
        clean_v = sanitize_field(v, SanitizationFieldKind.HTTP_SERVER_HEADER).value
        if clean_k:
            out[clean_k] = clean_v
    return out


# === TimelineBuilder ==========================================================


class TimelineBuilder:
    """Builds a :class:`BannerTimeline` from raw observation dicts.

    Each observation carries a ``_collector_id`` (or ``collector_id``) that
    determines how fields are extracted.  Unknown collector IDs are silently
    skipped — the pipeline may carry observations from collectors irrelevant
    to temporal analysis.
    """

    def build_timeline(
        self,
        entity_identifier: str,
        observations: list[dict[str, Any]],
    ) -> BannerTimeline:
        """Build a sorted, deduplicated timeline from observations.

        Parameters
        ----------
        entity_identifier:
            Canonical entity identifier (domain, IP, etc.).
        observations:
            Raw observation dicts from the pipeline.  Each must carry a
            ``_collector_id`` or ``collector_id`` field.

        Returns
        -------
        BannerTimeline
            Sorted ascending by timestamp, near-duplicates collapsed.
        """
        snapshots: list[BannerSnapshot] = []

        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            snapshot = self._extract_snapshot(cid, obs)
            if snapshot is not None:
                snapshots.append(snapshot)

        # Sort ascending by timestamp.
        snapshots.sort(key=lambda s: s.timestamp)

        # Deduplicate near-identical snapshots within the 1-hour window.
        snapshots = self._deduplicate(snapshots)

        span_days = 0
        if len(snapshots) >= 2:
            delta = snapshots[-1].timestamp - snapshots[0].timestamp
            span_days = delta.days

        return BannerTimeline(
            entity_identifier=entity_identifier,
            snapshots=snapshots,
            span_days=span_days,
        )

    def _extract_snapshot(
        self,
        collector_id: str,
        obs: dict[str, Any],
    ) -> BannerSnapshot | None:
        """Extract a BannerSnapshot from a single observation dict."""
        payload = obs.get("structured_payload", obs)

        if collector_id == "wayback-machine":
            return self._extract_wayback(payload)
        if collector_id == "scan-shodan":
            return self._extract_shodan(payload)
        if collector_id == "active-http-fingerprint":
            return self._extract_http_fingerprint(payload)
        if collector_id == "active-tls-handshake":
            return self._extract_tls_handshake(payload)

        return None

    # -- Per-collector extractors -----------------------------------------------

    @staticmethod
    def _extract_wayback(payload: dict[str, Any]) -> BannerSnapshot | None:
        """Extract snapshot from a Wayback Machine observation."""
        ts_raw = payload.get("archived_at")
        if ts_raw is None:
            return None
        ts = _parse_timestamp(ts_raw)
        if ts is None:
            return None

        banner = _sanitize(payload.get("banner"))
        status_code = payload.get("status_code")
        if isinstance(status_code, str):
            try:
                status_code = int(status_code)
            except (ValueError, TypeError):
                status_code = None

        headers_raw = payload.get("headers", {})
        headers = _sanitize_headers(headers_raw) if isinstance(headers_raw, dict) else {}
        server_header = headers.get("server")

        return BannerSnapshot(
            timestamp=ts,
            source="wayback-machine",
            banner_text=banner,
            headers=headers,
            status_code=status_code,
            server_header=server_header,
        )

    @staticmethod
    def _extract_shodan(payload: dict[str, Any]) -> BannerSnapshot | None:
        """Extract snapshot from a Shodan scan observation."""
        ts_raw = payload.get("last_seen")
        if ts_raw is None:
            return None
        ts = _parse_timestamp(ts_raw)
        if ts is None:
            return None

        banner = _sanitize(payload.get("banner"))
        port = payload.get("port")

        # Shodan nests headers inside a 'data' sub-dict in some cases.
        data = payload.get("data", {})
        if isinstance(data, dict):
            headers_raw = data.get("headers", {})
        else:
            headers_raw = {}
        headers = _sanitize_headers(headers_raw) if isinstance(headers_raw, dict) else {}

        server_header = headers.get("server")
        tls_version = payload.get("tls_version") or data.get("tls_version") if isinstance(data, dict) else None

        technologies: list[str] = []
        raw_tech = payload.get("technologies", [])
        if isinstance(raw_tech, list):
            technologies = [str(t) for t in raw_tech if t]

        return BannerSnapshot(
            timestamp=ts,
            source="scan-shodan",
            banner_text=banner,
            headers=headers,
            status_code=payload.get("status_code"),
            tls_version=_sanitize(tls_version) if isinstance(tls_version, str) else None,
            server_header=server_header,
            technologies=technologies,
        )

    @staticmethod
    def _extract_http_fingerprint(payload: dict[str, Any]) -> BannerSnapshot | None:
        """Extract snapshot from an active HTTP fingerprint observation."""
        ts_raw = payload.get("_observed_at")
        if ts_raw is None:
            return None
        ts = _parse_timestamp(ts_raw)
        if ts is None:
            return None

        headers_raw = payload.get("headers", {})
        headers = _sanitize_headers(headers_raw) if isinstance(headers_raw, dict) else {}

        server_header = headers.get("server")
        status_code = payload.get("status_code")

        technologies: list[str] = []
        raw_tech = payload.get("technologies", [])
        if isinstance(raw_tech, list):
            technologies = [str(t) for t in raw_tech if t]

        banner = _sanitize(payload.get("banner"))

        return BannerSnapshot(
            timestamp=ts,
            source="active-http-fingerprint",
            banner_text=banner,
            headers=headers,
            status_code=status_code,
            server_header=server_header,
            technologies=technologies,
        )

    @staticmethod
    def _extract_tls_handshake(payload: dict[str, Any]) -> BannerSnapshot | None:
        """Extract snapshot from an active TLS handshake observation."""
        ts_raw = payload.get("_observed_at")
        if ts_raw is None:
            return None
        ts = _parse_timestamp(ts_raw)
        if ts is None:
            return None

        tls_version = _sanitize(payload.get("tls_version"))
        cipher_suite = payload.get("cipher_suite")

        # Build a synthetic banner from TLS metadata.
        parts: list[str] = []
        if tls_version:
            parts.append(f"TLS: {tls_version}")
        if cipher_suite:
            parts.append(f"Cipher: {cipher_suite}")
        cert_subject = payload.get("cert_subject_cn")
        cert_issuer = payload.get("cert_issuer_cn")
        cert_not_after = payload.get("cert_not_after")
        if cert_subject:
            parts.append(f"Subject: {cert_subject}")
        if cert_issuer:
            parts.append(f"Issuer: {cert_issuer}")
        if cert_not_after:
            parts.append(f"Expires: {cert_not_after}")

        banner = " | ".join(parts) if parts else None

        headers: dict[str, str] = {}
        if cert_subject:
            headers["x-cert-subject-cn"] = str(cert_subject)
        if cert_issuer:
            headers["x-cert-issuer-cn"] = str(cert_issuer)
        if cert_not_after:
            headers["x-cert-not-after"] = str(cert_not_after)

        return BannerSnapshot(
            timestamp=ts,
            source="active-tls-handshake",
            banner_text=banner,
            headers=headers,
            tls_version=tls_version,
        )

    # -- Deduplication ----------------------------------------------------------

    @staticmethod
    def _deduplicate(snapshots: list[BannerSnapshot]) -> list[BannerSnapshot]:
        """Collapse near-identical snapshots within the dedup window.

        Two snapshots are "near-identical" if they share the same source,
        status_code, server_header, tls_version, and banner_text and their
        timestamps are within ``_DEDUP_WINDOW_SECONDS`` of each other.
        The earlier snapshot is kept.
        """
        if len(snapshots) <= 1:
            return snapshots

        result: list[BannerSnapshot] = [snapshots[0]]

        for snap in snapshots[1:]:
            prev = result[-1]
            time_gap = (snap.timestamp - prev.timestamp).total_seconds()
            if (
                time_gap <= _DEDUP_WINDOW_SECONDS
                and snap.source == prev.source
                and snap.status_code == prev.status_code
                and snap.server_header == prev.server_header
                and snap.tls_version == prev.tls_version
                and snap.banner_text == prev.banner_text
            ):
                # Skip duplicate — keep the earlier one.
                continue
            result.append(snap)

        return result


# === ProgressionDetector ======================================================


class ProgressionDetector:
    """Detects progression patterns in a banner timeline.

    All detection methods are stateless — they read the timeline and return
    patterns without side effects.  Each method is responsible for one
    pattern type and returns zero or more :class:`ProgressionPattern`
    instances.
    """

    def detect_patterns(self, timeline: BannerTimeline) -> list[ProgressionPattern]:
        """Run all detectors on the timeline and return patterns found.

        The order of returned patterns is deterministic (detectors run in
        fixed order, each appends in chronological order).
        """
        if len(timeline.snapshots) < 2:
            return []

        patterns: list[ProgressionPattern] = []
        patterns.extend(self._detect_security_regression(timeline))
        patterns.extend(self._detect_environment_promotion(timeline))
        patterns.extend(self._detect_infrastructure_drift(timeline))
        patterns.extend(self._detect_cert_lifecycle(timeline))
        patterns.extend(self._detect_new_exposure(timeline))
        return patterns

    # -- Security Regression ----------------------------------------------------

    def _detect_security_regression(
        self,
        timeline: BannerTimeline,
    ) -> list[ProgressionPattern]:
        """Detect TLS downgrades, security header removal, server version downgrades."""
        patterns: list[ProgressionPattern] = []

        for i in range(1, len(timeline.snapshots)):
            prev = timeline.snapshots[i - 1]
            curr = timeline.snapshots[i]

            # TLS version downgrade.
            if prev.tls_version and curr.tls_version:
                prev_rank = _TLS_VERSION_RANK.get(prev.tls_version, -1)
                curr_rank = _TLS_VERSION_RANK.get(curr.tls_version, -1)
                if prev_rank > curr_rank >= 0:
                    patterns.append(ProgressionPattern(
                        pattern_type="security_regression",
                        severity="high" if curr_rank <= 2 else "medium",
                        description=(
                            f"TLS version downgraded from {prev.tls_version} "
                            f"to {curr.tls_version}"
                        ),
                        evidence=[
                            {"before": _snapshot_summary(prev)},
                            {"after": _snapshot_summary(curr)},
                        ],
                        detected_at=curr.timestamp,
                        scoring_delta=15 if curr_rank <= 2 else 10,
                    ))

            # Security header removal.
            prev_sec_headers = {
                k for k in prev.headers if k.lower() in _SECURITY_HEADERS
            }
            curr_sec_headers = {
                k for k in curr.headers if k.lower() in _SECURITY_HEADERS
            }
            removed = prev_sec_headers - curr_sec_headers
            if removed:
                patterns.append(ProgressionPattern(
                    pattern_type="security_regression",
                    severity="medium",
                    description=(
                        f"Security header(s) removed: {', '.join(sorted(removed))}"
                    ),
                    evidence=[
                        {"before": _snapshot_summary(prev)},
                        {"after": _snapshot_summary(curr)},
                    ],
                    detected_at=curr.timestamp,
                    scoring_delta=10,
                ))

            # Server header version downgrade.
            if prev.server_header and curr.server_header:
                prev_ver = _extract_version(prev.server_header)
                curr_ver = _extract_version(curr.server_header)
                if prev_ver and curr_ver and prev_ver != curr_ver:
                    # Simple lexicographic comparison — works for major.minor.patch.
                    prev_parts = _version_tuple(prev_ver)
                    curr_parts = _version_tuple(curr_ver)
                    if prev_parts and curr_parts and curr_parts < prev_parts:
                        # Same server family — not a software change.
                        prev_name = _extract_server_name(prev.server_header)
                        curr_name = _extract_server_name(curr.server_header)
                        if prev_name == curr_name:
                            patterns.append(ProgressionPattern(
                                pattern_type="security_regression",
                                severity="low",
                                description=(
                                    f"Server version downgraded: "
                                    f"{prev.server_header} -> {curr.server_header}"
                                ),
                                evidence=[
                                    {"before": _snapshot_summary(prev)},
                                    {"after": _snapshot_summary(curr)},
                                ],
                                detected_at=curr.timestamp,
                                scoring_delta=10,
                            ))

        return patterns

    # -- Environment Promotion --------------------------------------------------

    def _detect_environment_promotion(
        self,
        timeline: BannerTimeline,
    ) -> list[ProgressionPattern]:
        """Detect staging->production transitions and debug persistence."""
        patterns: list[ProgressionPattern] = []

        for i in range(1, len(timeline.snapshots)):
            prev = timeline.snapshots[i - 1]
            curr = timeline.snapshots[i]

            prev_env = _classify_env_from_snapshot(prev)
            curr_env = _classify_env_from_snapshot(curr)

            # Staging/dev -> production transition.
            if prev_env == "non_production" and curr_env == "production":
                patterns.append(ProgressionPattern(
                    pattern_type="environment_promotion",
                    severity="info",
                    description="Environment promoted from non-production to production",
                    evidence=[
                        {"before": _snapshot_summary(prev)},
                        {"after": _snapshot_summary(curr)},
                    ],
                    detected_at=curr.timestamp,
                    scoring_delta=5,
                ))

            # Debug mode persisting (or appearing) in what looks like production.
            curr_has_debug = _has_debug_indicators(curr)
            prev_has_debug = _has_debug_indicators(prev)

            if curr_has_debug and curr_env == "production":
                patterns.append(ProgressionPattern(
                    pattern_type="environment_promotion",
                    severity="critical",
                    description="Debug mode detected in production environment",
                    evidence=[
                        {"before": _snapshot_summary(prev)},
                        {"after": _snapshot_summary(curr)},
                    ],
                    detected_at=curr.timestamp,
                    scoring_delta=20,
                ))
            elif curr_has_debug and not prev_has_debug:
                patterns.append(ProgressionPattern(
                    pattern_type="environment_promotion",
                    severity="high",
                    description="Debug mode appeared between snapshots",
                    evidence=[
                        {"before": _snapshot_summary(prev)},
                        {"after": _snapshot_summary(curr)},
                    ],
                    detected_at=curr.timestamp,
                    scoring_delta=15,
                ))

        return patterns

    # -- Infrastructure Drift ---------------------------------------------------

    def _detect_infrastructure_drift(
        self,
        timeline: BannerTimeline,
    ) -> list[ProgressionPattern]:
        """Detect server software changes and technology stack shifts."""
        patterns: list[ProgressionPattern] = []

        for i in range(1, len(timeline.snapshots)):
            prev = timeline.snapshots[i - 1]
            curr = timeline.snapshots[i]

            # Server software change (nginx -> apache, etc.).
            if prev.server_header and curr.server_header:
                prev_name = _extract_server_name(prev.server_header)
                curr_name = _extract_server_name(curr.server_header)
                if prev_name and curr_name and prev_name != curr_name:
                    patterns.append(ProgressionPattern(
                        pattern_type="infrastructure_drift",
                        severity="medium",
                        description=(
                            f"Server software changed: {prev_name} -> {curr_name}"
                        ),
                        evidence=[
                            {"before": _snapshot_summary(prev)},
                            {"after": _snapshot_summary(curr)},
                        ],
                        detected_at=curr.timestamp,
                        scoring_delta=10,
                    ))

            # Technology stack change via headers.
            if prev.technologies and curr.technologies:
                prev_set = set(prev.technologies)
                curr_set = set(curr.technologies)
                added = curr_set - prev_set
                removed = prev_set - curr_set
                if added or removed:
                    desc_parts: list[str] = []
                    if added:
                        desc_parts.append(f"added: {', '.join(sorted(added))}")
                    if removed:
                        desc_parts.append(f"removed: {', '.join(sorted(removed))}")
                    patterns.append(ProgressionPattern(
                        pattern_type="infrastructure_drift",
                        severity="low",
                        description=f"Technology stack changed: {'; '.join(desc_parts)}",
                        evidence=[
                            {"before": _snapshot_summary(prev)},
                            {"after": _snapshot_summary(curr)},
                        ],
                        detected_at=curr.timestamp,
                        scoring_delta=5,
                    ))

        return patterns

    # -- Certificate Lifecycle --------------------------------------------------

    def _detect_cert_lifecycle(
        self,
        timeline: BannerTimeline,
    ) -> list[ProgressionPattern]:
        """Detect stale certs, rapid rotation, self-signed replacement."""
        patterns: list[ProgressionPattern] = []

        # Collect TLS snapshots for cert analysis.
        tls_snapshots = [
            s for s in timeline.snapshots
            if s.source == "active-tls-handshake" or s.tls_version is not None
        ]

        if len(tls_snapshots) < 2:
            return patterns

        # Check for stale cert (same cert across >365 days).
        first_cert = _cert_identity(tls_snapshots[0])
        last_cert = _cert_identity(tls_snapshots[-1])
        if first_cert and first_cert == last_cert:
            span = (tls_snapshots[-1].timestamp - tls_snapshots[0].timestamp).days
            if span > 365:
                patterns.append(ProgressionPattern(
                    pattern_type="cert_lifecycle",
                    severity="medium",
                    description=(
                        f"Certificate unchanged for {span} days "
                        f"(>{365} day threshold)"
                    ),
                    evidence=[
                        {"first_seen": _snapshot_summary(tls_snapshots[0])},
                        {"last_seen": _snapshot_summary(tls_snapshots[-1])},
                    ],
                    detected_at=tls_snapshots[-1].timestamp,
                    scoring_delta=5,
                ))

        # Check for rapid cert rotation (>3 changes in 30 days).
        cert_changes: list[BannerSnapshot] = []
        for j in range(1, len(tls_snapshots)):
            prev_cert = _cert_identity(tls_snapshots[j - 1])
            curr_cert = _cert_identity(tls_snapshots[j])
            if prev_cert != curr_cert and prev_cert and curr_cert:
                cert_changes.append(tls_snapshots[j])

        if len(cert_changes) >= 3:
            # Check if 3+ changes happened within any 30-day window.
            for k in range(len(cert_changes) - 2):
                window = (cert_changes[k + 2].timestamp - cert_changes[k].timestamp).days
                if window <= 30:
                    patterns.append(ProgressionPattern(
                        pattern_type="cert_lifecycle",
                        severity="high",
                        description=(
                            f"Rapid certificate rotation: {len(cert_changes)} "
                            f"changes detected, 3+ within {window} days"
                        ),
                        evidence=[
                            {"change_at": _snapshot_summary(c)} for c in cert_changes[:5]
                        ],
                        detected_at=cert_changes[k + 2].timestamp,
                        scoring_delta=15,
                    ))
                    break  # One pattern per timeline for this detector.

        # Self-signed replacing CA-signed.
        for j in range(1, len(tls_snapshots)):
            prev_snap = tls_snapshots[j - 1]
            curr_snap = tls_snapshots[j]
            prev_self = _is_self_signed(prev_snap)
            curr_self = _is_self_signed(curr_snap)
            if prev_self is False and curr_self is True:
                patterns.append(ProgressionPattern(
                    pattern_type="cert_lifecycle",
                    severity="high",
                    description=(
                        "Self-signed certificate replaced CA-signed certificate"
                    ),
                    evidence=[
                        {"before": _snapshot_summary(prev_snap)},
                        {"after": _snapshot_summary(curr_snap)},
                    ],
                    detected_at=curr_snap.timestamp,
                    scoring_delta=15,
                ))

        return patterns

    # -- New Exposure Detection -------------------------------------------------

    def _detect_new_exposure(
        self,
        timeline: BannerTimeline,
    ) -> list[ProgressionPattern]:
        """Detect new ports/services appearing in later snapshots."""
        patterns: list[ProgressionPattern] = []

        for i in range(1, len(timeline.snapshots)):
            prev = timeline.snapshots[i - 1]
            curr = timeline.snapshots[i]

            # New endpoint responding where it previously didn't.
            prev_down = (
                prev.status_code is not None
                and (prev.status_code == 404 or prev.status_code == 0 or prev.status_code >= 500)
            )
            curr_up = (
                curr.status_code is not None
                and 200 <= curr.status_code < 400
            )
            if prev_down and curr_up and curr.source == prev.source:
                patterns.append(ProgressionPattern(
                    pattern_type="new_exposure",
                    severity="medium",
                    description=(
                        f"New endpoint responding: HTTP {curr.status_code} "
                        f"(was HTTP {prev.status_code})"
                    ),
                    evidence=[
                        {"before": _snapshot_summary(prev)},
                        {"after": _snapshot_summary(curr)},
                    ],
                    detected_at=curr.timestamp,
                    scoring_delta=10,
                ))

            # New technologies appearing.
            if not prev.technologies and curr.technologies:
                patterns.append(ProgressionPattern(
                    pattern_type="new_exposure",
                    severity="medium",
                    description=(
                        f"New service/technology detected: "
                        f"{', '.join(curr.technologies)}"
                    ),
                    evidence=[
                        {"before": _snapshot_summary(prev)},
                        {"after": _snapshot_summary(curr)},
                    ],
                    detected_at=curr.timestamp,
                    scoring_delta=10,
                ))

            # Banner appeared where none existed.
            if prev.banner_text is None and curr.banner_text is not None:
                # Only flag if status codes also suggest a new service.
                if prev.status_code is None or prev.status_code == 0:
                    patterns.append(ProgressionPattern(
                        pattern_type="new_exposure",
                        severity="high",
                        description="New service banner detected where none existed",
                        evidence=[
                            {"before": _snapshot_summary(prev)},
                            {"after": _snapshot_summary(curr)},
                        ],
                        detected_at=curr.timestamp,
                        scoring_delta=15,
                    ))

        return patterns


# === TemporalAnalyzer (orchestrator) ==========================================


class TemporalAnalyzer:
    """Top-level orchestrator — builds timeline, runs detectors, returns result.

    This is the single entrypoint for consumers.  The API endpoint calls
    ``analyze()`` and returns the result directly.
    """

    def __init__(self) -> None:
        self._builder = TimelineBuilder()
        self._detector = ProgressionDetector()

    def analyze(
        self,
        entity_identifier: str,
        observations: list[dict[str, Any]],
    ) -> TemporalAnalysisResult:
        """Run temporal analysis end-to-end.

        Parameters
        ----------
        entity_identifier:
            Canonical entity identifier.
        observations:
            Raw observation dicts from the pipeline (all collectors mixed).

        Returns
        -------
        TemporalAnalysisResult
            Timeline, detected patterns, and capped score delta.
        """
        timeline = self._builder.build_timeline(entity_identifier, observations)
        patterns = self._detector.detect_patterns(timeline)

        raw_delta = sum(p.scoring_delta for p in patterns)
        capped_delta = min(raw_delta, _MAX_TEMPORAL_DELTA)

        return TemporalAnalysisResult(
            timeline=timeline,
            patterns=patterns,
            temporal_score_delta=capped_delta,
        )


# === Helper functions (module-private) ========================================


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp from various formats into a timezone-aware datetime."""
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
        # Try ISO 8601 first.
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except (ValueError, TypeError):
            pass

    return None


def _snapshot_summary(snap: BannerSnapshot) -> dict[str, Any]:
    """Build a serializable summary dict from a snapshot for evidence."""
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
        summary["banner_text"] = snap.banner_text[:200]  # Truncate for evidence readability.
    if snap.technologies:
        summary["technologies"] = snap.technologies
    sec_headers = {k: v for k, v in snap.headers.items() if k.lower() in _SECURITY_HEADERS}
    if sec_headers:
        summary["security_headers"] = sec_headers
    return summary


def _extract_version(server_header: str) -> str | None:
    """Extract a version string like '1.24.0' from 'nginx/1.24.0'."""
    import re  # noqa: PLC0415
    match = re.search(r"/([\d]+(?:\.[\d]+)*)", server_header)
    return match.group(1) if match else None


def _version_tuple(version_str: str) -> tuple[int, ...] | None:
    """Parse '1.24.0' into (1, 24, 0) for comparison."""
    try:
        return tuple(int(p) for p in version_str.split("."))
    except (ValueError, AttributeError):
        return None


def _extract_server_name(server_header: str) -> str:
    """Extract the server name (before the /) from a server header, lowercased."""
    name = server_header.split("/")[0].strip().lower()
    return name


def _classify_env_from_snapshot(snap: BannerSnapshot) -> str:
    """Classify a snapshot as 'production', 'non_production', or 'unknown'."""
    # Check headers for environment indicators.
    for header_name, header_value in snap.headers.items():
        name_lower = header_name.lower()
        value_lower = header_value.lower() if header_value else ""

        if name_lower in ("x-environment", "x-env"):
            if any(kw in value_lower for kw in _STAGING_KEYWORDS):
                return "non_production"
            if value_lower in ("production", "prod"):
                return "production"

    # Check banner for staging keywords.
    if snap.banner_text:
        banner_lower = snap.banner_text.lower()
        if any(kw in banner_lower for kw in _STAGING_KEYWORDS):
            return "non_production"

    # Check server header for environment keywords.
    if snap.server_header:
        sh_lower = snap.server_header.lower()
        if any(kw in sh_lower for kw in _STAGING_KEYWORDS):
            return "non_production"

    return "production"


def _has_debug_indicators(snap: BannerSnapshot) -> bool:
    """Check if a snapshot has debug-mode indicators."""
    for header_name in snap.headers:
        if header_name.lower() in _DEBUG_KEYWORDS:
            return True

    if snap.banner_text:
        banner_lower = snap.banner_text.lower()
        if "debug" in banner_lower or "stack trace" in banner_lower:
            return True

    return False


def _cert_identity(snap: BannerSnapshot) -> str | None:
    """Build a cert identity string from a snapshot's TLS metadata.

    Returns a composite of subject CN + issuer CN + expiry that uniquely
    identifies a certificate (within the precision available from headers).
    """
    subject = snap.headers.get("x-cert-subject-cn", "")
    issuer = snap.headers.get("x-cert-issuer-cn", "")
    expiry = snap.headers.get("x-cert-not-after", "")
    if not subject and not issuer:
        return None
    return f"{subject}|{issuer}|{expiry}"


def _is_self_signed(snap: BannerSnapshot) -> bool | None:
    """Determine if a snapshot's cert is self-signed.

    Returns True if subject == issuer (and both are non-empty), False if
    they differ, None if insufficient data.
    """
    subject = snap.headers.get("x-cert-subject-cn", "")
    issuer = snap.headers.get("x-cert-issuer-cn", "")
    if not subject or not issuer:
        return None
    return subject == issuer


__all__ = [
    "BannerSnapshot",
    "BannerTimeline",
    "ProgressionDetector",
    "ProgressionPattern",
    "TemporalAnalysisResult",
    "TemporalAnalyzer",
    "TimelineBuilder",
]
