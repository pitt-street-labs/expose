"""Multi-signal environment classification for discovered endpoints.

Classifies endpoints as production / staging / QA / development / test based
on correlated signals from DNS patterns, HTTP responses, TLS certificates,
content analysis, and security posture.  No single signal is definitive;
confidence increases when multiple *categories* of signal agree.

This module is pure — no LLM calls, no external I/O, no side effects.  All
detection logic is deterministic and operates on structured observation dicts.
"""

from __future__ import annotations

import re
from collections import Counter
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# === Enums ====================================================================


class EnvironmentLabel(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    QA = "qa"
    DEVELOPMENT = "development"
    TEST = "test"
    UNKNOWN = "unknown"


class SignalCategory(StrEnum):
    DNS_PATTERN = "dns_pattern"
    HTTP_RESPONSE = "http_response"
    TLS_CERTIFICATE = "tls_certificate"
    INFRASTRUCTURE = "infrastructure"
    CONTENT = "content"
    SECURITY_POSTURE = "security_posture"


# === Models ===================================================================


class EnvironmentSignal(BaseModel):
    """A single signal contributing to the environment classification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: SignalCategory
    signal_name: str = Field(min_length=1)
    matched_value: str
    suggested_environment: EnvironmentLabel
    confidence: float = Field(ge=0.0, le=1.0)


class EnvironmentClassification(BaseModel):
    """Aggregated environment classification for a single entity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_identifier: str = Field(min_length=1)
    predicted_environment: EnvironmentLabel
    confidence: float = Field(ge=0.0, le=1.0)
    signals: list[EnvironmentSignal]
    is_non_production: bool
    risk_factors: list[str] = Field(default_factory=list)
    categories_matched: int = Field(ge=0)


# === DNS pattern tables =======================================================

# Subdomain prefixes that indicate a non-production environment.
_PREFIX_MAP: dict[str, EnvironmentLabel] = {
    "dev": EnvironmentLabel.DEVELOPMENT,
    "development": EnvironmentLabel.DEVELOPMENT,
    "test": EnvironmentLabel.TEST,
    "qa": EnvironmentLabel.QA,
    "uat": EnvironmentLabel.QA,
    "staging": EnvironmentLabel.STAGING,
    "stg": EnvironmentLabel.STAGING,
    "preprod": EnvironmentLabel.STAGING,
    "demo": EnvironmentLabel.STAGING,
    "sandbox": EnvironmentLabel.STAGING,
    "preview": EnvironmentLabel.STAGING,
    "beta": EnvironmentLabel.STAGING,
    "canary": EnvironmentLabel.STAGING,
}

# Hostname suffix patterns (e.g. ``api-dev.example.com``).
_SUFFIX_MAP: dict[str, EnvironmentLabel] = {
    "-dev": EnvironmentLabel.DEVELOPMENT,
    "-development": EnvironmentLabel.DEVELOPMENT,
    "-test": EnvironmentLabel.TEST,
    "-qa": EnvironmentLabel.QA,
    "-staging": EnvironmentLabel.STAGING,
    "-uat": EnvironmentLabel.QA,
}

# Regex: ``<prefix>.rest-of-domain``  (prefix must be the leftmost label).
_PREFIX_RE = re.compile(
    r"^(" + "|".join(re.escape(p) for p in sorted(_PREFIX_MAP, key=len, reverse=True)) + r")\.",
    re.IGNORECASE,
)

# Regex: hostname part (before first dot) ends with one of the suffixes.
_SUFFIX_RE = re.compile(
    r"^([^.]+("
    + "|".join(re.escape(s) for s in sorted(_SUFFIX_MAP, key=len, reverse=True))
    + r"))\.",
    re.IGNORECASE,
)

# Default framework page patterns.
_DEFAULT_PAGE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"welcome\s+to\s+nginx", re.IGNORECASE), "nginx default page"),
    (re.compile(r"apache2?\s+.{0,30}(default|test)\s*page", re.IGNORECASE), "Apache default page"),
    (re.compile(r"it\s+works!", re.IGNORECASE), "Apache default page"),
    (re.compile(r"iis\s+windows\s+server", re.IGNORECASE), "IIS default page"),
    (re.compile(r"congratulations.*your.*application", re.IGNORECASE), "Framework welcome page"),
]

# Stack-trace patterns that indicate verbose error output.
_STACK_TRACE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"at\s+[\w.$]+\([\w.]+:\d+\)"),  # Java stack trace
    re.compile(r"Fatal error:.*in .* on line \d+", re.IGNORECASE),  # PHP
    re.compile(r"Error:\s+\w+Error", re.IGNORECASE),  # JS/Node
]

# Swagger/OpenAPI detection patterns in body content.
_SWAGGER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"swagger", re.IGNORECASE),
    re.compile(r"openapi", re.IGNORECASE),
    re.compile(r"api[-_\s]?doc", re.IGNORECASE),
]

# Risk-factor mapping: signal_name -> human-readable risk label.
# Known public CA organizations (lowercase, for heuristic matching).
_PUBLIC_CA_KEYWORDS: frozenset[str] = frozenset({
    "let's encrypt", "digicert", "comodo", "sectigo", "globalsign",
    "geotrust", "thawte", "godaddy", "entrust", "amazon",
    "google trust", "microsoft", "baltimore", "usertrust",
    "isrg", "buypass", "certum", "starfield", "zerossl",
})

# Risk-factor mapping: signal_name -> human-readable risk label.
_RISK_FACTOR_MAP: dict[str, str] = {
    "debug_header": "Debug mode enabled",
    "self_signed_cert": "Self-signed certificate",
    "stack_trace_in_body": "Stack traces visible",
    "swagger_exposed": "Swagger/API docs exposed",
    "missing_hsts": "Missing security headers",
    "missing_csp": "Missing security headers",
    "cors_wildcard": "Permissive CORS policy",
    "default_page": "Default credentials likely",
    "admin_no_auth": "Admin panel without authentication",
    "le_staging_cert": "Non-production TLS certificate",
    "short_validity_cert": "Short-lived certificate",
    "no_tls": "No TLS encryption",
    "internal_ca": "Internal/private CA certificate",
}


# === Classifier ===============================================================


class EnvironmentClassifier:
    """Classifies endpoints as production/staging/QA/dev/test via multi-signal correlation."""

    def classify(
        self,
        *,
        entity_identifier: str,
        observations: list[dict[str, Any]],
    ) -> EnvironmentClassification:
        """Classify an entity's environment based on all available observations.

        Parameters
        ----------
        entity_identifier:
            The canonical identifier of the entity (e.g. ``"dev.example.com"``).
        observations:
            Observation dicts from the current pipeline run.  Each dict is
            expected to carry a ``_collector_id`` key (or ``collector_id``).

        Returns
        -------
        EnvironmentClassification
            Aggregated classification with confidence, contributing signals,
            risk factors, and the number of distinct signal categories.
        """
        signals: list[EnvironmentSignal] = []

        # 1. DNS/subdomain pattern analysis
        signals.extend(self._check_dns_patterns(entity_identifier))

        # 2. HTTP response analysis
        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid == "active-http-fingerprint":
                signals.extend(self._check_http_signals(obs))

        # 3. TLS certificate analysis
        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid == "active-tls-handshake":
                signals.extend(self._check_tls_signals(obs))

        # 4. Content/application analysis
        for obs in observations:
            signals.extend(self._check_content_signals(obs))

        # 5. Security posture analysis
        signals.extend(self._check_security_posture(observations))

        # Correlate signals into a single classification.
        return self._correlate(entity_identifier, signals)

    # -- Signal extraction methods ---------------------------------------------

    def _check_dns_patterns(
        self,
        identifier: str,
    ) -> list[EnvironmentSignal]:
        """Check the entity identifier for DNS prefix/suffix patterns."""
        signals: list[EnvironmentSignal] = []

        # Prefix match: ``dev.example.com`` → DEVELOPMENT.
        prefix_match = _PREFIX_RE.search(identifier)
        if prefix_match:
            matched = prefix_match.group(1).lower()
            env = _PREFIX_MAP.get(matched)
            if env is not None:
                signals.append(EnvironmentSignal(
                    category=SignalCategory.DNS_PATTERN,
                    signal_name="subdomain_prefix",
                    matched_value=matched,
                    suggested_environment=env,
                    confidence=0.8,
                ))

        # Suffix match: ``api-dev.example.com`` → DEVELOPMENT.
        suffix_match = _SUFFIX_RE.search(identifier)
        if suffix_match:
            matched_suffix = suffix_match.group(2).lower()
            env = _SUFFIX_MAP.get(matched_suffix)
            if env is not None:
                signals.append(EnvironmentSignal(
                    category=SignalCategory.DNS_PATTERN,
                    signal_name="hostname_suffix",
                    matched_value=matched_suffix,
                    suggested_environment=env,
                    confidence=0.7,
                ))

        return signals

    def _check_http_signals(
        self,
        obs: dict[str, Any],
    ) -> list[EnvironmentSignal]:
        """Extract environment signals from HTTP response observations."""
        signals: list[EnvironmentSignal] = []
        payload = obs.get("structured_payload", obs)

        # Debug headers.
        headers: dict[str, str] = payload.get("headers", {})
        for hdr_name in ("x-debug-token", "x-debug-info"):
            val = headers.get(hdr_name)
            if val:
                signals.append(EnvironmentSignal(
                    category=SignalCategory.HTTP_RESPONSE,
                    signal_name="debug_header",
                    matched_value=f"{hdr_name}: {val}",
                    suggested_environment=EnvironmentLabel.DEVELOPMENT,
                    confidence=0.7,
                ))

        # Server header containing 'development' or 'debug'.
        server = payload.get("server_header") or ""
        if re.search(r"\b(development|debug)\b", server, re.IGNORECASE):
            signals.append(EnvironmentSignal(
                category=SignalCategory.HTTP_RESPONSE,
                signal_name="server_header_dev",
                matched_value=server,
                suggested_environment=EnvironmentLabel.DEVELOPMENT,
                confidence=0.6,
            ))

        # X-Robots-Tag: noindex.
        x_robots = headers.get("x-robots-tag", "")
        if "noindex" in x_robots.lower():
            signals.append(EnvironmentSignal(
                category=SignalCategory.HTTP_RESPONSE,
                signal_name="x_robots_noindex",
                matched_value=x_robots,
                suggested_environment=EnvironmentLabel.STAGING,
                confidence=0.4,
            ))

        # Stack traces in body.
        banner = payload.get("banner", "")
        for pattern in _STACK_TRACE_PATTERNS:
            if pattern.search(banner):
                signals.append(EnvironmentSignal(
                    category=SignalCategory.HTTP_RESPONSE,
                    signal_name="stack_trace_in_body",
                    matched_value="stack trace detected in response body",
                    suggested_environment=EnvironmentLabel.DEVELOPMENT,
                    confidence=0.7,
                ))
                break  # One signal per observation is sufficient.

        # CORS wildcard.
        acao = headers.get("access-control-allow-origin", "")
        if acao.strip() == "*":
            signals.append(EnvironmentSignal(
                category=SignalCategory.HTTP_RESPONSE,
                signal_name="cors_wildcard",
                matched_value="Access-Control-Allow-Origin: *",
                suggested_environment=EnvironmentLabel.STAGING,
                confidence=0.3,
            ))

        return signals

    def _check_tls_signals(
        self,
        obs: dict[str, Any],
    ) -> list[EnvironmentSignal]:
        """Extract environment signals from TLS handshake observations."""
        signals: list[EnvironmentSignal] = []
        payload = obs.get("structured_payload", obs)

        issuer_cn = payload.get("cert_issuer_cn") or ""
        issuer_org = payload.get("cert_issuer_org") or ""
        subject_cn = payload.get("cert_subject_cn") or ""

        # Self-signed certificate (subject CN == issuer CN and no real org).
        if subject_cn and issuer_cn and subject_cn == issuer_cn:
            signals.append(EnvironmentSignal(
                category=SignalCategory.TLS_CERTIFICATE,
                signal_name="self_signed_cert",
                matched_value=f"subject=issuer={subject_cn}",
                suggested_environment=EnvironmentLabel.DEVELOPMENT,
                confidence=0.7,
            ))

        # Let's Encrypt staging issuer ("Fake LE", "(STAGING)").
        combined_issuer = f"{issuer_cn} {issuer_org}".lower()
        if "fake le" in combined_issuer or "(staging)" in combined_issuer:
            signals.append(EnvironmentSignal(
                category=SignalCategory.TLS_CERTIFICATE,
                signal_name="le_staging_cert",
                matched_value=issuer_cn,
                suggested_environment=EnvironmentLabel.STAGING,
                confidence=0.9,
            ))

        # Very short validity (< 7 days).
        signals.extend(self._check_cert_validity(payload))

        # Internal/private CA issuer (heuristic: org not in known public CAs).
        signals.extend(self._check_internal_ca(issuer_org, subject_cn, signals))

        return signals

    def _check_cert_validity(
        self,
        payload: dict[str, Any],
    ) -> list[EnvironmentSignal]:
        """Check certificate validity period for short-lived test certs."""
        not_before = payload.get("cert_not_before")
        not_after = payload.get("cert_not_after")
        if not (not_before and not_after):
            return []

        try:
            from datetime import UTC, datetime  # noqa: PLC0415

            nb = datetime.fromisoformat(not_before.replace("Z", "+00:00")) if isinstance(not_before, str) else not_before
            na = datetime.fromisoformat(not_after.replace("Z", "+00:00")) if isinstance(not_after, str) else not_after

            if nb.tzinfo is None:
                nb = nb.replace(tzinfo=UTC)
            if na.tzinfo is None:
                na = na.replace(tzinfo=UTC)

            validity_days = (na - nb).days
            if 0 < validity_days < 7:  # noqa: PLR2004
                return [EnvironmentSignal(
                    category=SignalCategory.TLS_CERTIFICATE,
                    signal_name="short_validity_cert",
                    matched_value=f"{validity_days} day validity",
                    suggested_environment=EnvironmentLabel.TEST,
                    confidence=0.6,
                )]
        except (ValueError, TypeError, AttributeError):
            pass
        return []

    @staticmethod
    def _check_internal_ca(
        issuer_org: str,
        subject_cn: str,
        existing_signals: list[EnvironmentSignal],
    ) -> list[EnvironmentSignal]:
        """Check whether the issuer is an internal/private CA."""
        if not issuer_org:
            return []
        org_lower = issuer_org.lower()
        is_known_public = any(kw in org_lower for kw in _PUBLIC_CA_KEYWORDS)
        if is_known_public or issuer_org == subject_cn:
            return []
        # Only flag if we didn't already flag self-signed.
        already_self_signed = any(s.signal_name == "self_signed_cert" for s in existing_signals)
        if already_self_signed:
            return []
        return [EnvironmentSignal(
            category=SignalCategory.TLS_CERTIFICATE,
            signal_name="internal_ca",
            matched_value=issuer_org,
            suggested_environment=EnvironmentLabel.STAGING,
            confidence=0.5,
        )]

    def _check_content_signals(
        self,
        obs: dict[str, Any],
    ) -> list[EnvironmentSignal]:
        """Extract environment signals from page content."""
        signals: list[EnvironmentSignal] = []
        payload = obs.get("structured_payload", obs)

        title = payload.get("title") or ""
        banner = payload.get("banner") or ""
        combined_content = f"{title} {banner}"

        # Default framework pages.
        for pattern, desc in _DEFAULT_PAGE_PATTERNS:
            if pattern.search(combined_content):
                signals.append(EnvironmentSignal(
                    category=SignalCategory.CONTENT,
                    signal_name="default_page",
                    matched_value=desc,
                    suggested_environment=EnvironmentLabel.DEVELOPMENT,
                    confidence=0.6,
                ))
                break

        # Swagger/OpenAPI UI exposed.
        for pattern in _SWAGGER_PATTERNS:
            if pattern.search(combined_content):
                signals.append(EnvironmentSignal(
                    category=SignalCategory.CONTENT,
                    signal_name="swagger_exposed",
                    matched_value="Swagger/OpenAPI UI detected",
                    suggested_environment=EnvironmentLabel.DEVELOPMENT,
                    confidence=0.5,
                ))
                break

        return signals

    def _check_security_posture(
        self,
        observations: list[dict[str, Any]],
    ) -> list[EnvironmentSignal]:
        """Derive signals from the absence of security controls."""
        signals: list[EnvironmentSignal] = []

        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid != "active-http-fingerprint":
                continue

            payload = obs.get("structured_payload", obs)
            headers: dict[str, str] = payload.get("headers", {})
            url: str = payload.get("url", "")

            # Missing HSTS.
            if "strict-transport-security" not in headers:
                signals.append(EnvironmentSignal(
                    category=SignalCategory.SECURITY_POSTURE,
                    signal_name="missing_hsts",
                    matched_value="Strict-Transport-Security header absent",
                    suggested_environment=EnvironmentLabel.STAGING,
                    confidence=0.3,
                ))

            # Missing CSP.
            if "content-security-policy" not in headers:
                signals.append(EnvironmentSignal(
                    category=SignalCategory.SECURITY_POSTURE,
                    signal_name="missing_csp",
                    matched_value="Content-Security-Policy header absent",
                    suggested_environment=EnvironmentLabel.STAGING,
                    confidence=0.3,
                ))

            # HTTP (no TLS) on standard port.
            if url.startswith("http://"):
                signals.append(EnvironmentSignal(
                    category=SignalCategory.SECURITY_POSTURE,
                    signal_name="no_tls",
                    matched_value=url,
                    suggested_environment=EnvironmentLabel.STAGING,
                    confidence=0.4,
                ))

        return signals

    # -- Correlation logic -----------------------------------------------------

    def _correlate(
        self,
        entity_identifier: str,
        signals: list[EnvironmentSignal],
    ) -> EnvironmentClassification:
        """Aggregate signals into a single classification.

        Voting logic:
        - Weight each signal's vote by its confidence.
        - The environment with the highest weighted vote total wins.
        - Overall confidence is capped by the number of distinct categories.

        Confidence scaling by category count:
          - 0 categories → 0.0
          - 1 category  → max 0.5
          - 2 categories → max 0.7
          - 3+ categories → max 0.9
        """
        if not signals:
            return EnvironmentClassification(
                entity_identifier=entity_identifier,
                predicted_environment=EnvironmentLabel.UNKNOWN,
                confidence=0.0,
                signals=[],
                is_non_production=False,
                risk_factors=[],
                categories_matched=0,
            )

        # Count distinct categories.
        categories = {s.category for s in signals}
        categories_matched = len(categories)

        # Weighted vote: accumulate confidence per environment.
        votes: Counter[EnvironmentLabel] = Counter()
        for sig in signals:
            if sig.suggested_environment != EnvironmentLabel.UNKNOWN:
                votes[sig.suggested_environment] += sig.confidence

        # Pick winner.
        if votes:
            predicted = votes.most_common(1)[0][0]
            raw_confidence = votes[predicted] / sum(votes.values())
        else:
            predicted = EnvironmentLabel.UNKNOWN
            raw_confidence = 0.0

        # Cap confidence by category count.
        cap = {0: 0.0, 1: 0.5, 2: 0.7}.get(categories_matched, 0.9)
        confidence = min(raw_confidence, cap)

        # Determine is_non_production.
        is_non_production = predicted not in (
            EnvironmentLabel.PRODUCTION,
            EnvironmentLabel.UNKNOWN,
        )

        # Build risk factors from signal names.
        risk_factors: list[str] = []
        seen_risks: set[str] = set()
        for sig in signals:
            risk_label = _RISK_FACTOR_MAP.get(sig.signal_name)
            if risk_label and risk_label not in seen_risks:
                seen_risks.add(risk_label)
                risk_factors.append(risk_label)

        return EnvironmentClassification(
            entity_identifier=entity_identifier,
            predicted_environment=predicted,
            confidence=round(confidence, 4),
            signals=signals,
            is_non_production=is_non_production,
            risk_factors=risk_factors,
            categories_matched=categories_matched,
        )


__all__ = [
    "EnvironmentClassification",
    "EnvironmentClassifier",
    "EnvironmentLabel",
    "EnvironmentSignal",
    "SignalCategory",
]
