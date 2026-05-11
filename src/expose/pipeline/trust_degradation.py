"""Trust degradation detection — identify changes that may indicate compromise.

Compares observations from the current pipeline run against previous runs for
the same entity to detect infrastructure changes that could signal domain
takeover, hosting compromise, certificate mis-issuance, or abandonment.

This module is pure — no LLM calls, no external I/O, no side effects. All
detection logic is deterministic and operates on structured observation dicts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# === Enums ====================================================================


class DegradationEventType(StrEnum):
    REGISTRAR_CHANGE = "registrar_change"
    DNS_PROVIDER_CHANGE = "dns_provider_change"
    HOSTING_MIGRATION = "hosting_migration"
    CERT_AUTHORITY_CHANGE = "cert_authority_change"
    CERT_EXPIRY_IMMINENT = "cert_expiry_imminent"
    NAMESERVER_CHANGE = "nameserver_change"
    IP_ADDRESS_CHANGE = "ip_address_change"
    TECH_STACK_CHANGE = "tech_stack_change"
    RESPONSE_ANOMALY = "response_anomaly"
    DISAPPEARED = "disappeared"


class DegradationSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# === Models ===================================================================


class TrustDegradationEvent(BaseModel):
    """A single detected trust-degradation event for an entity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entity_identifier: str = Field(min_length=1)
    event_type: DegradationEventType
    severity: DegradationSeverity
    previous_value: str | None = None
    current_value: str | None = None
    description: str
    detected_at: datetime
    confidence: float = Field(ge=0.0, le=1.0)


# === Severity mapping ========================================================

_SEVERITY_MAP: dict[DegradationEventType, DegradationSeverity] = {
    DegradationEventType.REGISTRAR_CHANGE: DegradationSeverity.HIGH,
    DegradationEventType.CERT_AUTHORITY_CHANGE: DegradationSeverity.HIGH,
    DegradationEventType.HOSTING_MIGRATION: DegradationSeverity.MEDIUM,
    DegradationEventType.DNS_PROVIDER_CHANGE: DegradationSeverity.MEDIUM,
    DegradationEventType.IP_ADDRESS_CHANGE: DegradationSeverity.LOW,
    DegradationEventType.TECH_STACK_CHANGE: DegradationSeverity.LOW,
    DegradationEventType.NAMESERVER_CHANGE: DegradationSeverity.LOW,
    DegradationEventType.RESPONSE_ANOMALY: DegradationSeverity.INFO,
    DegradationEventType.DISAPPEARED: DegradationSeverity.CRITICAL,
}

# Cert expiry thresholds (days).
_CERT_EXPIRY_CRITICAL_DAYS = 7
_CERT_EXPIRY_WARNING_DAYS = 30


# === Helpers ==================================================================


def _extract_field(
    observations: list[dict[str, Any]],
    collector_id: str,
    field: str,
) -> str | None:
    """Return the first non-empty value for *field* from observations matching *collector_id*."""
    for obs in observations:
        if obs.get("collector_id") == collector_id:
            value = obs.get(field)
            if value is not None and value != "":
                return str(value)
    return None


def _extract_set(
    observations: list[dict[str, Any]],
    collector_id: str,
    field: str,
) -> set[str]:
    """Return a set of values for *field* from all observations matching *collector_id*."""
    values: set[str] = set()
    for obs in observations:
        if obs.get("collector_id") == collector_id:
            raw = obs.get(field)
            if isinstance(raw, list):
                values.update(str(v) for v in raw if v is not None and v != "")
            elif raw is not None and raw != "":
                values.add(str(raw))
    return values


def _make_event(
    entity_identifier: str,
    event_type: DegradationEventType,
    *,
    previous_value: str | None = None,
    current_value: str | None = None,
    description: str,
    detected_at: datetime,
    confidence: float = 0.9,
    severity_override: DegradationSeverity | None = None,
) -> TrustDegradationEvent:
    """Build a ``TrustDegradationEvent`` with the standard severity mapping."""
    severity = severity_override or _SEVERITY_MAP[event_type]
    return TrustDegradationEvent(
        entity_identifier=entity_identifier,
        event_type=event_type,
        severity=severity,
        previous_value=previous_value,
        current_value=current_value,
        description=description,
        detected_at=detected_at,
        confidence=confidence,
    )


# === Detector =================================================================


class TrustDegradationDetector:
    """Compares current and previous run observations to detect trust-degrading changes.

    The detector is purely deterministic — no LLM, no external calls. It
    compares structured observation dicts keyed by ``collector_id`` and standard
    field names. Each check function is independent and produces zero or more
    ``TrustDegradationEvent`` values.
    """

    def detect(
        self,
        *,
        entity_identifier: str,
        current_observations: list[dict[str, Any]],
        previous_observations: list[dict[str, Any]],
    ) -> list[TrustDegradationEvent]:
        """Compare observations and return any degradation events.

        Parameters
        ----------
        entity_identifier:
            The canonical identifier of the entity (e.g. ``"example.com"``).
        current_observations:
            Observation dicts from the current pipeline run.
        previous_observations:
            Observation dicts from the previous pipeline run.

        Returns
        -------
        list[TrustDegradationEvent]
            Zero or more degradation events, sorted by severity (critical first).
        """
        now = datetime.now(tz=UTC)
        events: list[TrustDegradationEvent] = []

        # Disappeared: entity had observations before but none now.
        if previous_observations and not current_observations:
            events.append(
                _make_event(
                    entity_identifier,
                    DegradationEventType.DISAPPEARED,
                    description=(
                        f"Entity '{entity_identifier}' was present in the previous "
                        "run but has no observations in the current run"
                    ),
                    detected_at=now,
                    confidence=0.95,
                )
            )
            return events

        # No previous observations means first scan — nothing to compare.
        if not previous_observations:
            return events

        # Run all comparison checks.
        events.extend(self._check_registrar(entity_identifier, current_observations,
                                            previous_observations, now))
        events.extend(self._check_dns_provider(entity_identifier, current_observations,
                                               previous_observations, now))
        events.extend(self._check_nameservers(entity_identifier, current_observations,
                                              previous_observations, now))
        events.extend(self._check_hosting_migration(entity_identifier, current_observations,
                                                    previous_observations, now))
        events.extend(self._check_ip_address(entity_identifier, current_observations,
                                             previous_observations, now))
        events.extend(self._check_cert_authority(entity_identifier, current_observations,
                                                 previous_observations, now))
        events.extend(self._check_cert_expiry(entity_identifier, current_observations, now))
        events.extend(self._check_tech_stack(entity_identifier, current_observations,
                                             previous_observations, now))
        events.extend(self._check_response_anomaly(entity_identifier, current_observations,
                                                   previous_observations, now))

        return events

    # -- Individual checks -----------------------------------------------------

    def _check_registrar(
        self,
        entity_id: str,
        current: list[dict[str, Any]],
        previous: list[dict[str, Any]],
        now: datetime,
    ) -> list[TrustDegradationEvent]:
        """WHOIS registrar field differs between runs."""
        prev_reg = _extract_field(previous, "whois", "registrar")
        curr_reg = _extract_field(current, "whois", "registrar")
        if prev_reg and curr_reg and prev_reg != curr_reg:
            return [_make_event(
                entity_id,
                DegradationEventType.REGISTRAR_CHANGE,
                previous_value=prev_reg,
                current_value=curr_reg,
                description=(
                    f"Domain registrar changed from '{prev_reg}' to '{curr_reg}'"
                ),
                detected_at=now,
                confidence=0.95,
            )]
        return []

    def _check_dns_provider(
        self,
        entity_id: str,
        current: list[dict[str, Any]],
        previous: list[dict[str, Any]],
        now: datetime,
    ) -> list[TrustDegradationEvent]:
        """DNS provider (derived from nameserver TLD/brand) changed."""
        prev_provider = _extract_field(previous, "dns", "dns_provider")
        curr_provider = _extract_field(current, "dns", "dns_provider")
        if prev_provider and curr_provider and prev_provider != curr_provider:
            return [_make_event(
                entity_id,
                DegradationEventType.DNS_PROVIDER_CHANGE,
                previous_value=prev_provider,
                current_value=curr_provider,
                description=(
                    f"DNS provider changed from '{prev_provider}' to '{curr_provider}'"
                ),
                detected_at=now,
                confidence=0.85,
            )]
        return []

    def _check_nameservers(
        self,
        entity_id: str,
        current: list[dict[str, Any]],
        previous: list[dict[str, Any]],
        now: datetime,
    ) -> list[TrustDegradationEvent]:
        """Nameserver set differs between runs."""
        prev_ns = _extract_set(previous, "dns", "nameservers")
        curr_ns = _extract_set(current, "dns", "nameservers")
        if prev_ns and curr_ns and prev_ns != curr_ns:
            return [_make_event(
                entity_id,
                DegradationEventType.NAMESERVER_CHANGE,
                previous_value=",".join(sorted(prev_ns)),
                current_value=",".join(sorted(curr_ns)),
                description=(
                    f"Nameserver set changed from {sorted(prev_ns)} to {sorted(curr_ns)}"
                ),
                detected_at=now,
                confidence=0.85,
            )]
        return []

    def _check_hosting_migration(
        self,
        entity_id: str,
        current: list[dict[str, Any]],
        previous: list[dict[str, Any]],
        now: datetime,
    ) -> list[TrustDegradationEvent]:
        """Hosting provider (ASN/org) changed, indicating infrastructure migration."""
        prev_host = _extract_field(previous, "ip-geo", "hosting_provider")
        curr_host = _extract_field(current, "ip-geo", "hosting_provider")
        if prev_host and curr_host and prev_host != curr_host:
            return [_make_event(
                entity_id,
                DegradationEventType.HOSTING_MIGRATION,
                previous_value=prev_host,
                current_value=curr_host,
                description=(
                    f"Hosting provider changed from '{prev_host}' to '{curr_host}'"
                ),
                detected_at=now,
                confidence=0.8,
            )]
        return []

    def _check_ip_address(
        self,
        entity_id: str,
        current: list[dict[str, Any]],
        previous: list[dict[str, Any]],
        now: datetime,
    ) -> list[TrustDegradationEvent]:
        """Resolved IP addresses (A/AAAA records) differ between runs."""
        prev_ips = _extract_set(previous, "dns", "resolved_ips")
        curr_ips = _extract_set(current, "dns", "resolved_ips")
        if prev_ips and curr_ips and prev_ips != curr_ips:
            return [_make_event(
                entity_id,
                DegradationEventType.IP_ADDRESS_CHANGE,
                previous_value=",".join(sorted(prev_ips)),
                current_value=",".join(sorted(curr_ips)),
                description=(
                    f"Resolved IP addresses changed from {sorted(prev_ips)} "
                    f"to {sorted(curr_ips)}"
                ),
                detected_at=now,
                confidence=0.8,
            )]
        return []

    def _check_cert_authority(
        self,
        entity_id: str,
        current: list[dict[str, Any]],
        previous: list[dict[str, Any]],
        now: datetime,
    ) -> list[TrustDegradationEvent]:
        """TLS certificate issuer differs between runs."""
        prev_issuer = _extract_field(previous, "tls", "cert_issuer")
        curr_issuer = _extract_field(current, "tls", "cert_issuer")
        if prev_issuer and curr_issuer and prev_issuer != curr_issuer:
            return [_make_event(
                entity_id,
                DegradationEventType.CERT_AUTHORITY_CHANGE,
                previous_value=prev_issuer,
                current_value=curr_issuer,
                description=(
                    f"TLS certificate issuer changed from '{prev_issuer}' "
                    f"to '{curr_issuer}'"
                ),
                detected_at=now,
                confidence=0.9,
            )]
        return []

    def _check_cert_expiry(
        self,
        entity_id: str,
        current: list[dict[str, Any]],
        now: datetime,
    ) -> list[TrustDegradationEvent]:
        """Certificate expiry within the warning threshold."""
        for obs in current:
            if obs.get("collector_id") != "tls":
                continue
            expiry_raw = obs.get("cert_not_after")
            if expiry_raw is None:
                continue
            # Parse ISO 8601 date string or pass through datetime.
            if isinstance(expiry_raw, str):
                try:
                    expiry = datetime.fromisoformat(expiry_raw)
                except ValueError:
                    continue
            elif isinstance(expiry_raw, datetime):
                expiry = expiry_raw
            else:
                continue

            # Ensure timezone-aware comparison.
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)

            days_remaining = (expiry - now).days
            if days_remaining < _CERT_EXPIRY_WARNING_DAYS:
                severity = (
                    DegradationSeverity.CRITICAL
                    if days_remaining < _CERT_EXPIRY_CRITICAL_DAYS
                    else DegradationSeverity.HIGH
                )
                return [_make_event(
                    entity_id,
                    DegradationEventType.CERT_EXPIRY_IMMINENT,
                    current_value=f"{days_remaining} days remaining (expires {expiry.date()})",
                    description=(
                        f"TLS certificate expires in {days_remaining} days "
                        f"(on {expiry.date()})"
                    ),
                    detected_at=now,
                    confidence=1.0,
                    severity_override=severity,
                )]
        return []

    def _check_tech_stack(
        self,
        entity_id: str,
        current: list[dict[str, Any]],
        previous: list[dict[str, Any]],
        now: datetime,
    ) -> list[TrustDegradationEvent]:
        """Server or X-Powered-By headers changed between runs."""
        events: list[TrustDegradationEvent] = []

        prev_server = _extract_field(previous, "http", "server_header")
        curr_server = _extract_field(current, "http", "server_header")
        if prev_server and curr_server and prev_server != curr_server:
            events.append(_make_event(
                entity_id,
                DegradationEventType.TECH_STACK_CHANGE,
                previous_value=prev_server,
                current_value=curr_server,
                description=(
                    f"Server header changed from '{prev_server}' to '{curr_server}'"
                ),
                detected_at=now,
                confidence=0.8,
            ))

        prev_powered = _extract_field(previous, "http", "x_powered_by")
        curr_powered = _extract_field(current, "http", "x_powered_by")
        if prev_powered and curr_powered and prev_powered != curr_powered:
            events.append(_make_event(
                entity_id,
                DegradationEventType.TECH_STACK_CHANGE,
                previous_value=prev_powered,
                current_value=curr_powered,
                description=(
                    f"X-Powered-By header changed from '{prev_powered}' "
                    f"to '{curr_powered}'"
                ),
                detected_at=now,
                confidence=0.75,
            ))

        return events

    def _check_response_anomaly(
        self,
        entity_id: str,
        current: list[dict[str, Any]],
        previous: list[dict[str, Any]],
        now: datetime,
    ) -> list[TrustDegradationEvent]:
        """HTTP status code changed between runs (e.g. 200 -> 403)."""
        prev_status = _extract_field(previous, "http", "status_code")
        curr_status = _extract_field(current, "http", "status_code")
        if prev_status and curr_status and prev_status != curr_status:
            return [_make_event(
                entity_id,
                DegradationEventType.RESPONSE_ANOMALY,
                previous_value=prev_status,
                current_value=curr_status,
                description=(
                    f"HTTP status code changed from {prev_status} to {curr_status}"
                ),
                detected_at=now,
                confidence=0.7,
            )]
        return []


__all__ = [
    "DegradationEventType",
    "DegradationSeverity",
    "TrustDegradationDetector",
    "TrustDegradationEvent",
]
