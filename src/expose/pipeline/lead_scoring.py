"""Lead scoring engine — aggregate multi-signal analysis into composite priority scores.

Combines signals from environment classification, WAF detection, DNSBL listings,
trust degradation events, SaaS alignment gaps, vision analysis, and observation-level
security indicators into a single 0-100 score per entity.  The score answers
"what should I investigate first?" and is deterministic given the same inputs.

This module is pure — no LLM calls, no external I/O, no side effects.  All
scoring logic is deterministic and operates on structured model instances and
observation dicts.

Architecture: open-core signal registry
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The engine ships with 5 **basic signals** (environment, open ports, deprecated
TLS, weak certificates, missing headers) that represent table-stakes checks
any EASM tool provides.  Advanced signals live in the commercial
``expose.modules.threat_context.scoring_signals`` module and are
auto-discovered at import time via the ``ADVANCED_SIGNALS`` registry.  When
the commercial module is not installed, the engine degrades gracefully to the
basic signal set.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field

from expose.pipeline.environment_classifier import EnvironmentClassification

# === Enums ====================================================================


class PriorityTier(StrEnum):
    CRITICAL = "critical"  # 70-100
    HIGH = "high"  # 40-69
    MEDIUM = "medium"  # 20-39
    LOW = "low"  # 0-19


# === Models ===================================================================


class ScoringSignal(BaseModel):
    """A single signal contributing to the composite lead score."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signal_name: str = Field(min_length=1)
    points: int = Field(ge=0, le=100)
    evidence: str
    source_module: str = Field(min_length=1)


class LeadScore(BaseModel):
    """Aggregated lead score for a single entity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_identifier: str = Field(min_length=1)
    score: int = Field(ge=0, le=100)
    priority_tier: PriorityTier
    contributing_signals: list[ScoringSignal]
    justification: str
    scored_at: datetime


# === Tier mapping =============================================================


def _score_to_tier(score: int) -> PriorityTier:
    """Map a numeric score to its priority tier."""
    if score >= 70:  # noqa: PLR2004
        return PriorityTier.CRITICAL
    if score >= 40:  # noqa: PLR2004
        return PriorityTier.HIGH
    if score >= 20:  # noqa: PLR2004
        return PriorityTier.MEDIUM
    return PriorityTier.LOW


# === Justification builder ====================================================

# Human-readable phrases for each signal name.
_SIGNAL_PHRASES: dict[str, str] = {
    "non_production_exposed": "non-production endpoint",
    "no_waf_protection": "no WAF protection",
    "dnsbl_listed": "blacklisted IP",
    "trust_degradation": "recent infrastructure changes",
    "post_acquisition_asset": "post-acquisition asset",
    "unexpected_saas_product": "shadow IT detected",
    "security_indicator_found": "security finding in page analysis",
    "missing_security_headers": "missing security headers",
    "weak_certificate": "weak/self-signed certificate",
    "debug_mode_detected": "debug mode enabled",
    "open_port_risk": "risky open ports",
    "deprecated_tls": "deprecated TLS configuration",
    "dns_exposure": "DNS misconfiguration",
    "http_technology_exposure": "HTTP technology exposure",
    "vendor_cve_density": "high vendor CVE density",
    "eol_product": "end-of-life product",
    "predicted_rce": "predicted RCE-class weakness",
    "active_exploitation": "actively exploited (CISA KEV)",
    "slow_patch_velocity": "slow patch velocity",
    "registrar_breach_history": "registrar with breach history",
    "single_registrar_dependency": "single-registrar NS dependency",
    "no_dnssec": "DNSSEC not enabled",
}


def _build_justification(
    entity: str,
    signals: list[ScoringSignal],
    score: int,
) -> str:
    """Build a one-line human-readable justification from the top signals."""
    if not signals:
        return f"{entity}: no risk signals detected (score: {score})"

    # Take the top 3 signals by points.
    top = sorted(signals, key=lambda s: s.points, reverse=True)[:3]
    phrases = [_SIGNAL_PHRASES.get(s.signal_name, s.signal_name.replace("_", " ")) for s in top]

    joined = phrases[0] if len(phrases) == 1 else ", ".join(phrases[:-1]) + " and " + phrases[-1]

    return f"{entity}: {joined} (score: {score})"


# === Signal registry ==========================================================

# Type alias for signal functions in the registry.
SignalFunc = Callable[..., list[ScoringSignal]]

# The registry holds advanced (commercial) signal functions.  Basic signals
# are always called directly by the engine; this list is for additional
# signals discovered from commercial modules.
_SIGNAL_REGISTRY: list[SignalFunc] = []

# Auto-discover commercial signals from the threat_context module.
try:
    from expose.modules.threat_context.scoring_signals import ADVANCED_SIGNALS

    _SIGNAL_REGISTRY.extend(ADVANCED_SIGNALS)
except ImportError:
    pass  # Commercial signals not available


# === Engine ===================================================================


class LeadScoringEngine:
    """Aggregates multi-signal analysis into composite lead scores.

    The engine always evaluates 5 basic (open-core) signals.  When the
    commercial ``expose.modules.threat_context.scoring_signals`` module is
    installed, its 14 advanced signals are auto-discovered and evaluated
    alongside the basic set.
    """

    # -- Port sets for risk classification (used by _check_open_ports) ---------
    _HIGH_RISK_PORTS: frozenset[int] = frozenset({
        3306, 5432, 27017, 6379,  # databases
        22, 3389, 5900,           # management
    })
    _MEDIUM_RISK_PORTS: frozenset[int] = frozenset({
        135, 445,   # RPC / SMB
        1883, 5672, # MQTT / AMQP
    })
    _WEB_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})

    _PASSIVE_SCANNER_IDS: frozenset[str] = frozenset({
        "scan-shodan", "scan-censys", "scan-binaryedge",
    })

    _PASSIVE_HIGH_RISK_PORTS: frozenset[int] = frozenset({
        22, 23, 3389, 8080, 445,
    })
    _PASSIVE_MEDIUM_RISK_PORTS: frozenset[int] = frozenset({
        135, 1883, 5672, 5900, 3306, 5432, 27017, 6379,
    })

    # Weak cipher keywords (case-insensitive substring match).
    _WEAK_CIPHER_KEYWORDS: tuple[str, ...] = ("RC4", "DES", "3DES", "NULL", "EXPORT")

    def score_entity(
        self,
        *,
        entity_identifier: str,
        observations: list[dict[str, Any]] | None = None,
        environment: EnvironmentClassification | None = None,
        trust_events: list[Any] | None = None,
        waf_detected: bool | None = None,
        dnsbl_listings: list[dict[str, Any]] | None = None,
        saas_gaps: list[Any] | None = None,
        vision_analysis: Any | None = None,
        is_transitive_ma: bool = False,
        entity_properties: dict[str, Any] | None = None,
    ) -> LeadScore:
        """Score a single entity based on all available signals.

        Parameters
        ----------
        entity_identifier:
            The canonical identifier of the entity (e.g. ``"staging.example.com"``).
        observations:
            Raw observation dicts from the pipeline run (used for header/cert checks).
        environment:
            Environment classification result from the environment classifier.
        trust_events:
            Trust degradation events detected for this entity.
        waf_detected:
            ``True`` if a WAF/CDN was detected, ``False`` if none was found,
            ``None`` if WAF detection was not run.
        dnsbl_listings:
            DNSBL listing dicts, each with ``listing_type``, ``severity``, etc.
        saas_gaps:
            Surface gaps from SaaS alignment analysis.
        vision_analysis:
            Screenshot/banner analysis result.
        is_transitive_ma:
            Whether the entity was discovered via M&A transitive search.
        entity_properties:
            Entity-level properties from RDAP/WHOIS and other collectors,
            including ``registrar``, ``nameservers``, and ``dnssec`` fields.

        Returns
        -------
        LeadScore
            Composite score with contributing signals and justification.
        """
        signals: list[ScoringSignal] = []
        obs = observations or []

        # --- Basic signals (open-core, always available) ---

        # 1. Environment risk (+30 for non-production)
        signals.extend(self._check_environment(environment))

        # 2. Open port risk (+5-20)
        signals.extend(self._check_open_ports(obs))

        # 3. Deprecated TLS (+10-15)
        signals.extend(self._check_deprecated_tls(obs))

        # 4. Self-signed/expiring cert (+5-10)
        signals.extend(self._check_weak_cert(obs))

        # 5. Missing security headers (+5)
        signals.extend(self._check_missing_headers(obs))

        # 6. Registrar / nameserver supply chain risk (+5-15)
        signals.extend(self._check_registrar_risk(entity_properties or {}))

        # --- Advanced signals (from commercial registry) ---
        # Each registry function receives the full kwargs and extracts
        # what it needs.
        signal_kwargs: dict[str, Any] = {
            "observations": obs,
            "environment": environment,
            "trust_events": trust_events,
            "waf_detected": waf_detected,
            "dnsbl_listings": dnsbl_listings,
            "saas_gaps": saas_gaps,
            "vision_analysis": vision_analysis,
            "is_transitive_ma": is_transitive_ma,
            "entity_properties": entity_properties or {},
        }
        for signal_fn in _SIGNAL_REGISTRY:
            signals.extend(signal_fn(**signal_kwargs))

        # Aggregate
        raw_score = sum(s.points for s in signals)
        score = min(100, raw_score)
        tier = _score_to_tier(score)
        justification = _build_justification(entity_identifier, signals, score)

        return LeadScore(
            entity_identifier=entity_identifier,
            score=score,
            priority_tier=tier,
            contributing_signals=signals,
            justification=justification,
            scored_at=datetime.now(tz=UTC),
        )

    def score_entities(
        self,
        entities: list[dict[str, Any]],
    ) -> list[LeadScore]:
        """Score multiple entities and return sorted by score descending.

        Each dict in *entities* is passed as keyword arguments to
        ``score_entity``.  At minimum, each must contain
        ``entity_identifier``.
        """
        scores = [self.score_entity(**e) for e in entities]
        return sorted(scores, key=lambda s: s.score, reverse=True)

    # -- Basic signal extraction methods (open-core) ---------------------------

    @staticmethod
    def _check_environment(
        environment: EnvironmentClassification | None,
    ) -> list[ScoringSignal]:
        """Non-production environment -> +30 points."""
        if environment is not None and environment.is_non_production:
            return [
                ScoringSignal(
                    signal_name="non_production_exposed",
                    points=30,
                    evidence=f"Classified as {environment.predicted_environment.value}",
                    source_module="environment_classifier",
                )
            ]
        return []

    @staticmethod
    def _check_open_ports(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """Open port risk -> +5 (web-only), +10 (medium), +20 (high) points.

        Examines ``active-port-surface`` observations for open ports and
        classifies them by risk tier.  Only the highest-risk tier fires --
        a target with both high-risk and web-only ports gets +20, not +25.
        """
        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")

            if cid == "active-port-surface":
                payload = obs.get("structured_payload", obs)
                open_ports: list[int] = payload.get("open_ports", [])
                if not open_ports:
                    continue

                port_set = frozenset(open_ports)

                if port_set & LeadScoringEngine._HIGH_RISK_PORTS:
                    hit = sorted(port_set & LeadScoringEngine._HIGH_RISK_PORTS)
                    return [
                        ScoringSignal(
                            signal_name="open_port_risk",
                            points=20,
                            evidence=f"High-risk ports open: {', '.join(str(p) for p in hit)}",
                            source_module="port_surface",
                        )
                    ]

                if port_set & LeadScoringEngine._MEDIUM_RISK_PORTS:
                    hit = sorted(port_set & LeadScoringEngine._MEDIUM_RISK_PORTS)
                    return [
                        ScoringSignal(
                            signal_name="open_port_risk",
                            points=10,
                            evidence=f"Medium-risk ports open: {', '.join(str(p) for p in hit)}",
                            source_module="port_surface",
                        )
                    ]

                if port_set <= LeadScoringEngine._WEB_PORTS:
                    return [
                        ScoringSignal(
                            signal_name="open_port_risk",
                            points=5,
                            evidence="Only web ports open",
                            source_module="port_surface",
                        )
                    ]

            elif cid in LeadScoringEngine._PASSIVE_SCANNER_IDS:
                payload = obs.get("structured_payload", obs)
                raw_ports: list[int] = payload.get("ports", [])
                single_port = payload.get("port")
                if single_port is not None and isinstance(single_port, int) and not raw_ports:
                    raw_ports = [single_port]
                if not raw_ports:
                    continue

                port_set = frozenset(raw_ports)

                if port_set & LeadScoringEngine._PASSIVE_HIGH_RISK_PORTS:
                    hit = sorted(port_set & LeadScoringEngine._PASSIVE_HIGH_RISK_PORTS)
                    return [
                        ScoringSignal(
                            signal_name="open_port_risk",
                            points=15,
                            evidence=f"High-risk ports observed ({cid}): {', '.join(str(p) for p in hit)}",
                            source_module="port_surface",
                        )
                    ]

                if port_set & LeadScoringEngine._PASSIVE_MEDIUM_RISK_PORTS:
                    hit = sorted(port_set & LeadScoringEngine._PASSIVE_MEDIUM_RISK_PORTS)
                    return [
                        ScoringSignal(
                            signal_name="open_port_risk",
                            points=10,
                            evidence=f"Medium-risk ports observed ({cid}): {', '.join(str(p) for p in hit)}",
                            source_module="port_surface",
                        )
                    ]

                return [
                    ScoringSignal(
                        signal_name="open_port_risk",
                        points=5,
                        evidence=f"Ports observed ({cid}): {', '.join(str(p) for p in sorted(port_set))}",
                        source_module="port_surface",
                    )
                ]

        return []

    @staticmethod
    def _check_deprecated_tls(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """Deprecated TLS version or weak ciphers -> +10-15 points.

        Examines ``active-tls-handshake`` observations.  Deprecated protocol
        versions (TLSv1.0, TLSv1.1) score +15.  Weak cipher suites (RC4,
        DES, 3DES, NULL, EXPORT) score +10.  Both can fire independently
        but the method returns at most one signal (the higher-scoring one)
        to avoid double-counting with the existing ``_check_weak_cert``.
        """
        _DEPRECATED = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}

        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")

            if cid == "active-tls-handshake":
                payload = obs.get("structured_payload", obs)
                tls_version: str = payload.get("tls_version") or ""
                cipher_suite: str = payload.get("cipher_suite") or ""

                if tls_version in _DEPRECATED:
                    return [
                        ScoringSignal(
                            signal_name="deprecated_tls",
                            points=15,
                            evidence=f"Deprecated TLS version: {tls_version}",
                            source_module="tls_handshake",
                        )
                    ]

                cipher_upper = cipher_suite.upper()
                for kw in LeadScoringEngine._WEAK_CIPHER_KEYWORDS:
                    if kw in cipher_upper:
                        return [
                            ScoringSignal(
                                signal_name="deprecated_tls",
                                points=10,
                                evidence=f"Weak cipher suite: {cipher_suite}",
                                source_module="tls_handshake",
                            )
                        ]

            elif cid in LeadScoringEngine._PASSIVE_SCANNER_IDS:
                payload = obs.get("structured_payload", obs)
                ssl_obj: dict[str, Any] = payload.get("ssl") or {}
                if not ssl_obj:
                    continue

                versions: list[str] = ssl_obj.get("versions") or []
                for ver in versions:
                    normalized = ver.lstrip("-")
                    if normalized in _DEPRECATED:
                        return [
                            ScoringSignal(
                                signal_name="deprecated_tls",
                                points=15,
                                evidence=f"Deprecated TLS version via {cid}: {normalized}",
                                source_module="tls_handshake",
                            )
                        ]

        return []

    @staticmethod
    def _check_weak_cert(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """Self-signed or near-expiry certificate -> +5-10 points."""
        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")

            if cid == "active-tls-handshake":
                payload = obs.get("structured_payload", obs)
                subject_cn = payload.get("cert_subject_cn") or ""
                issuer_cn = payload.get("cert_issuer_cn") or ""

                if subject_cn and issuer_cn and subject_cn == issuer_cn:
                    return [
                        ScoringSignal(
                            signal_name="weak_certificate",
                            points=10,
                            evidence=f"Self-signed certificate: subject=issuer={subject_cn}",
                            source_module="tls_handshake",
                        )
                    ]

                not_after = payload.get("cert_not_after")
                if not_after and isinstance(not_after, str):
                    try:
                        expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                        if expiry.tzinfo is None:
                            expiry = expiry.replace(tzinfo=UTC)
                        days_remaining = (expiry - datetime.now(tz=UTC)).days
                        if days_remaining < 30:  # noqa: PLR2004
                            return [
                                ScoringSignal(
                                    signal_name="weak_certificate",
                                    points=5,
                                    evidence=f"Certificate expires in {days_remaining} days",
                                    source_module="tls_handshake",
                                )
                            ]
                    except (ValueError, TypeError):
                        pass

            elif cid in LeadScoringEngine._PASSIVE_SCANNER_IDS:
                payload = obs.get("structured_payload", obs)
                ssl_obj: dict[str, Any] = payload.get("ssl") or {}
                if not ssl_obj:
                    continue

                subject_dict: dict[str, str] = ssl_obj.get("subject") or {}
                issuer_dict: dict[str, str] = ssl_obj.get("issuer") or {}
                subject_cn = subject_dict.get("CN") or ""
                issuer_cn = issuer_dict.get("CN") or ""

                if subject_cn and issuer_cn and subject_cn == issuer_cn:
                    return [
                        ScoringSignal(
                            signal_name="weak_certificate",
                            points=10,
                            evidence=f"Self-signed certificate via {cid}: subject=issuer={subject_cn}",
                            source_module="tls_handshake",
                        )
                    ]

                expires_raw = ssl_obj.get("expires") or ""
                if expires_raw and isinstance(expires_raw, str):
                    try:
                        expiry = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
                        if expiry.tzinfo is None:
                            expiry = expiry.replace(tzinfo=UTC)
                        days_remaining = (expiry - datetime.now(tz=UTC)).days
                        if days_remaining < 30:  # noqa: PLR2004
                            return [
                                ScoringSignal(
                                    signal_name="weak_certificate",
                                    points=5,
                                    evidence=f"Certificate expires in {days_remaining} days ({cid})",
                                    source_module="tls_handshake",
                                )
                            ]
                    except (ValueError, TypeError):
                        pass

        return []

    @staticmethod
    def _check_missing_headers(
        observations: list[dict[str, Any]],
    ) -> list[ScoringSignal]:
        """Missing HSTS or CSP headers -> +5 points."""
        _HEADER_COLLECTOR_IDS = {"active-http-fingerprint", "scan-censys"}

        for obs in observations:
            cid = obs.get("_collector_id") or obs.get("collector_id", "")
            if cid not in _HEADER_COLLECTOR_IDS:
                continue

            payload = obs.get("structured_payload", obs)
            headers: dict[str, str] = payload.get("headers", {})
            if not isinstance(headers, dict):
                continue

            missing = []
            if "strict-transport-security" not in headers:
                missing.append("HSTS")
            if "content-security-policy" not in headers:
                missing.append("CSP")

            if missing:
                return [
                    ScoringSignal(
                        signal_name="missing_security_headers",
                        points=5,
                        evidence=f"Missing headers: {', '.join(missing)}",
                        source_module="http_fingerprint",
                    )
                ]
        return []

    _BREACHED_REGISTRARS: dict[str, int] = {
        "godaddy": 15,
        "go daddy": 15,
        "wild west domains": 15,
        "namecheap": 10,
        "enom": 10,
        "network solutions": 10,
        "register.com": 10,
        "name.com": 8,
        "epik": 8,
        "tucows": 8,
        "hover": 8,
    }

    _REGISTRAR_NS_PATTERNS: dict[str, str] = {
        "domaincontrol.com": "GoDaddy",
        "registrar-servers.com": "Namecheap",
        "name-services.com": "Enom",
        "worldnic.com": "Network Solutions",
        "epik.com": "Epik",
        "hover.com": "Hover",
    }

    @staticmethod
    def _check_registrar_risk(
        entity_properties: dict[str, Any],
    ) -> list[ScoringSignal]:
        """Registrar / nameserver supply chain risk -> +5-15 points.

        Examines entity properties set by the RDAP/WHOIS collector for
        known-breached registrars, single-registrar nameserver dependency,
        and missing DNSSEC.
        """
        signals: list[ScoringSignal] = []
        if not entity_properties:
            return signals

        registrar: str = entity_properties.get("registrar") or ""
        nameservers: list[str] = entity_properties.get("nameservers") or []
        dnssec = entity_properties.get("dnssec")

        registrar_lower = registrar.lower()
        for keyword, points in LeadScoringEngine._BREACHED_REGISTRARS.items():
            if keyword in registrar_lower:
                signals.append(
                    ScoringSignal(
                        signal_name="registrar_breach_history",
                        points=points,
                        evidence=f"Registrar '{registrar}' has known breach history",
                        source_module="rdap_whois",
                    )
                )
                break

        if len(nameservers) >= 2:  # noqa: PLR2004
            providers: set[str] = set()
            for ns in nameservers:
                ns_lower = ns.lower()
                matched = False
                for domain, provider in LeadScoringEngine._REGISTRAR_NS_PATTERNS.items():
                    if ns_lower.endswith(domain) or ns_lower.endswith(domain + "."):
                        providers.add(provider)
                        matched = True
                        break
                if not matched:
                    parts = ns_lower.rstrip(".").rsplit(".", 2)
                    if len(parts) >= 2:  # noqa: PLR2004
                        providers.add(".".join(parts[-2:]))
            if len(providers) == 1:
                signals.append(
                    ScoringSignal(
                        signal_name="single_registrar_dependency",
                        points=10,
                        evidence=f"All {len(nameservers)} nameservers from {next(iter(providers))}",
                        source_module="rdap_whois",
                    )
                )

        if dnssec is not None and not dnssec:
            signals.append(
                ScoringSignal(
                    signal_name="no_dnssec",
                    points=5,
                    evidence="DNSSEC not enabled for domain",
                    source_module="rdap_whois",
                )
            )

        return signals


__all__ = [
    "LeadScore",
    "LeadScoringEngine",
    "PriorityTier",
    "ScoringSignal",
]
