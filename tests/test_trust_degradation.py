"""Tests for the trust degradation detection engine.

Covers all detection rules, severity mapping, edge cases, and model validation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from expose.pipeline.trust_degradation import (
    DegradationEventType,
    DegradationSeverity,
    TrustDegradationDetector,
    TrustDegradationEvent,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC)


def _obs(collector_id: str, **fields: object) -> dict[str, object]:
    """Build a minimal observation dict for a given collector."""
    return {"collector_id": collector_id, **fields}


def _detect(
    current: list[dict[str, object]],
    previous: list[dict[str, object]] | None = None,
    entity_identifier: str = "example.com",
) -> list[TrustDegradationEvent]:
    """Run detection and return events."""
    detector = TrustDegradationDetector()
    return detector.detect(
        entity_identifier=entity_identifier,
        current_observations=current,
        previous_observations=previous or [],
    )


# ---------------------------------------------------------------------------
# 1. No previous observations -> no events
# ---------------------------------------------------------------------------


def test_no_previous_observations_no_events() -> None:
    """First scan (no previous data) should produce zero events."""
    current = [_obs("dns", resolved_ips=["1.2.3.4"])]
    events = _detect(current, previous=[])
    assert events == []


# ---------------------------------------------------------------------------
# 2. Identical observations -> no events
# ---------------------------------------------------------------------------


def test_identical_observations_no_events() -> None:
    """When current and previous observations are identical, no events fire."""
    obs = [
        _obs("whois", registrar="Registrar Inc."),
        _obs("dns", nameservers=["ns1.example.com"], resolved_ips=["1.2.3.4"]),
        _obs("tls", cert_issuer="Let's Encrypt"),
        _obs("http", server_header="nginx/1.20", status_code="200"),
    ]
    events = _detect(current=obs, previous=obs)
    assert events == []


# ---------------------------------------------------------------------------
# 3. Registrar change -> HIGH severity
# ---------------------------------------------------------------------------


def test_registrar_change_detected() -> None:
    """A change in the WHOIS registrar triggers a HIGH-severity event."""
    previous = [_obs("whois", registrar="GoDaddy")]
    current = [_obs("whois", registrar="Namecheap")]
    events = _detect(current, previous)

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == DegradationEventType.REGISTRAR_CHANGE
    assert evt.severity == DegradationSeverity.HIGH
    assert evt.previous_value == "GoDaddy"
    assert evt.current_value == "Namecheap"
    assert evt.entity_identifier == "example.com"
    assert 0.0 <= evt.confidence <= 1.0


# ---------------------------------------------------------------------------
# 4. DNS provider change detected
# ---------------------------------------------------------------------------


def test_dns_provider_change_detected() -> None:
    """A DNS provider change triggers a MEDIUM-severity event."""
    previous = [_obs("dns", dns_provider="Cloudflare")]
    current = [_obs("dns", dns_provider="Route53")]
    events = _detect(current, previous)

    assert len(events) == 1
    assert events[0].event_type == DegradationEventType.DNS_PROVIDER_CHANGE
    assert events[0].severity == DegradationSeverity.MEDIUM
    assert events[0].previous_value == "Cloudflare"
    assert events[0].current_value == "Route53"


# ---------------------------------------------------------------------------
# 5. IP address change detected
# ---------------------------------------------------------------------------


def test_ip_address_change_detected() -> None:
    """A change in resolved IPs triggers a LOW-severity event."""
    previous = [_obs("dns", resolved_ips=["1.2.3.4"])]
    current = [_obs("dns", resolved_ips=["5.6.7.8"])]
    events = _detect(current, previous)

    assert len(events) == 1
    assert events[0].event_type == DegradationEventType.IP_ADDRESS_CHANGE
    assert events[0].severity == DegradationSeverity.LOW


# ---------------------------------------------------------------------------
# 6. Cert authority change detected
# ---------------------------------------------------------------------------


def test_cert_authority_change_detected() -> None:
    """A change in TLS certificate issuer triggers a HIGH-severity event."""
    previous = [_obs("tls", cert_issuer="Let's Encrypt")]
    current = [_obs("tls", cert_issuer="DigiCert")]
    events = _detect(current, previous)

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == DegradationEventType.CERT_AUTHORITY_CHANGE
    assert evt.severity == DegradationSeverity.HIGH
    assert evt.previous_value == "Let's Encrypt"
    assert evt.current_value == "DigiCert"


# ---------------------------------------------------------------------------
# 7. Cert expiry imminent (< 30 days) -> severity depends on threshold
# ---------------------------------------------------------------------------


def test_cert_expiry_imminent_critical() -> None:
    """Certificate expiring in < 7 days is CRITICAL."""
    expiry = (datetime.now(tz=UTC) + timedelta(days=3)).isoformat()
    current = [_obs("tls", cert_not_after=expiry)]
    events = _detect(current, previous=[_obs("tls", cert_issuer="LE")])

    assert len(events) == 1
    assert events[0].event_type == DegradationEventType.CERT_EXPIRY_IMMINENT
    assert events[0].severity == DegradationSeverity.CRITICAL
    assert events[0].confidence == 1.0


def test_cert_expiry_imminent_high() -> None:
    """Certificate expiring in 7-29 days is HIGH severity."""
    expiry = (datetime.now(tz=UTC) + timedelta(days=15)).isoformat()
    current = [_obs("tls", cert_not_after=expiry)]
    events = _detect(current, previous=[_obs("tls", cert_issuer="LE")])

    assert len(events) == 1
    assert events[0].event_type == DegradationEventType.CERT_EXPIRY_IMMINENT
    assert events[0].severity == DegradationSeverity.HIGH


def test_cert_expiry_not_imminent() -> None:
    """Certificate expiring in > 30 days produces no event."""
    expiry = (datetime.now(tz=UTC) + timedelta(days=90)).isoformat()
    current = [_obs("tls", cert_not_after=expiry)]
    events = _detect(current, previous=[_obs("tls", cert_issuer="LE")])

    # Filter to only cert_expiry events
    expiry_events = [e for e in events if e.event_type == DegradationEventType.CERT_EXPIRY_IMMINENT]
    assert expiry_events == []


# ---------------------------------------------------------------------------
# 8. Tech stack change (server header)
# ---------------------------------------------------------------------------


def test_tech_stack_server_header_change() -> None:
    """A change in the Server header triggers a LOW-severity event."""
    previous = [_obs("http", server_header="nginx/1.18")]
    current = [_obs("http", server_header="Apache/2.4.52")]
    events = _detect(current, previous)

    assert len(events) == 1
    assert events[0].event_type == DegradationEventType.TECH_STACK_CHANGE
    assert events[0].severity == DegradationSeverity.LOW
    assert events[0].previous_value == "nginx/1.18"
    assert events[0].current_value == "Apache/2.4.52"


def test_tech_stack_x_powered_by_change() -> None:
    """A change in X-Powered-By triggers a LOW-severity TECH_STACK_CHANGE."""
    previous = [_obs("http", x_powered_by="PHP/7.4")]
    current = [_obs("http", x_powered_by="PHP/8.2")]
    events = _detect(current, previous)

    assert len(events) == 1
    assert events[0].event_type == DegradationEventType.TECH_STACK_CHANGE
    assert events[0].severity == DegradationSeverity.LOW


# ---------------------------------------------------------------------------
# 9. Disappeared entity -> CRITICAL
# ---------------------------------------------------------------------------


def test_disappeared_entity() -> None:
    """Entity with previous observations but empty current triggers CRITICAL."""
    previous = [
        _obs("dns", resolved_ips=["1.2.3.4"]),
        _obs("http", status_code="200"),
    ]
    events = _detect(current=[], previous=previous)

    assert len(events) == 1
    evt = events[0]
    assert evt.event_type == DegradationEventType.DISAPPEARED
    assert evt.severity == DegradationSeverity.CRITICAL
    assert "example.com" in evt.description


# ---------------------------------------------------------------------------
# 10. Multiple changes on same entity -> multiple events
# ---------------------------------------------------------------------------


def test_multiple_changes_produce_multiple_events() -> None:
    """Multiple changes across different collectors each generate an event."""
    previous = [
        _obs("whois", registrar="GoDaddy"),
        _obs("dns", resolved_ips=["1.2.3.4"]),
        _obs("http", server_header="nginx/1.18"),
    ]
    current = [
        _obs("whois", registrar="Namecheap"),
        _obs("dns", resolved_ips=["5.6.7.8"]),
        _obs("http", server_header="Apache/2.4"),
    ]
    events = _detect(current, previous)

    event_types = {e.event_type for e in events}
    assert DegradationEventType.REGISTRAR_CHANGE in event_types
    assert DegradationEventType.IP_ADDRESS_CHANGE in event_types
    assert DegradationEventType.TECH_STACK_CHANGE in event_types
    assert len(events) >= 3


# ---------------------------------------------------------------------------
# 11. Empty current observations (disappeared)
# ---------------------------------------------------------------------------


def test_empty_current_is_disappeared() -> None:
    """Empty current_observations with non-empty previous is a disappearance."""
    previous = [_obs("whois", registrar="X")]
    events = _detect(current=[], previous=previous)

    assert len(events) == 1
    assert events[0].event_type == DegradationEventType.DISAPPEARED


# ---------------------------------------------------------------------------
# 12. TrustDegradationEvent model validation (frozen, bounds)
# ---------------------------------------------------------------------------


def test_event_model_is_frozen() -> None:
    """TrustDegradationEvent instances reject attribute mutation."""
    evt = TrustDegradationEvent(
        entity_identifier="example.com",
        event_type=DegradationEventType.REGISTRAR_CHANGE,
        severity=DegradationSeverity.HIGH,
        description="test",
        detected_at=_NOW,
        confidence=0.9,
    )
    with pytest.raises(Exception):  # noqa: B017
        evt.confidence = 0.5  # type: ignore[misc]


def test_event_model_rejects_extra_fields() -> None:
    """TrustDegradationEvent rejects unknown fields."""
    with pytest.raises(Exception):  # noqa: B017
        TrustDegradationEvent(
            entity_identifier="example.com",
            event_type=DegradationEventType.REGISTRAR_CHANGE,
            severity=DegradationSeverity.HIGH,
            description="test",
            detected_at=_NOW,
            confidence=0.9,
            bogus_field="nope",  # type: ignore[call-arg]
        )


def test_event_model_confidence_bounds() -> None:
    """Confidence must be in [0.0, 1.0]."""
    with pytest.raises(Exception):  # noqa: B017
        TrustDegradationEvent(
            entity_identifier="example.com",
            event_type=DegradationEventType.REGISTRAR_CHANGE,
            severity=DegradationSeverity.HIGH,
            description="test",
            detected_at=_NOW,
            confidence=1.5,  # out of bounds
        )
    with pytest.raises(Exception):  # noqa: B017
        TrustDegradationEvent(
            entity_identifier="example.com",
            event_type=DegradationEventType.REGISTRAR_CHANGE,
            severity=DegradationSeverity.HIGH,
            description="test",
            detected_at=_NOW,
            confidence=-0.1,  # out of bounds
        )


def test_event_model_entity_identifier_min_length() -> None:
    """entity_identifier must not be empty."""
    with pytest.raises(Exception):  # noqa: B017
        TrustDegradationEvent(
            entity_identifier="",
            event_type=DegradationEventType.REGISTRAR_CHANGE,
            severity=DegradationSeverity.HIGH,
            description="test",
            detected_at=_NOW,
            confidence=0.5,
        )


# ---------------------------------------------------------------------------
# 13. DegradationEventType enum values
# ---------------------------------------------------------------------------


def test_degradation_event_type_values() -> None:
    """All expected event type values are present."""
    expected = {
        "registrar_change",
        "dns_provider_change",
        "hosting_migration",
        "cert_authority_change",
        "cert_expiry_imminent",
        "nameserver_change",
        "ip_address_change",
        "tech_stack_change",
        "response_anomaly",
        "disappeared",
    }
    actual = {e.value for e in DegradationEventType}
    assert actual == expected


def test_degradation_severity_values() -> None:
    """All expected severity values are present."""
    expected = {"info", "low", "medium", "high", "critical"}
    actual = {s.value for s in DegradationSeverity}
    assert actual == expected


# ---------------------------------------------------------------------------
# 14. Confidence scores are reasonable (0.0-1.0)
# ---------------------------------------------------------------------------


def test_confidence_scores_in_range() -> None:
    """All produced events have confidence in [0.0, 1.0]."""
    previous = [
        _obs("whois", registrar="A"),
        _obs("dns", dns_provider="X", nameservers=["ns1.old.com"], resolved_ips=["1.1.1.1"]),
        _obs("tls", cert_issuer="OldCA"),
        _obs("http", server_header="nginx", status_code="200"),
        _obs("ip-geo", hosting_provider="AWS"),
    ]
    current = [
        _obs("whois", registrar="B"),
        _obs("dns", dns_provider="Y", nameservers=["ns1.new.com"], resolved_ips=["2.2.2.2"]),
        _obs("tls", cert_issuer="NewCA"),
        _obs("http", server_header="apache", status_code="403"),
        _obs("ip-geo", hosting_provider="GCP"),
    ]
    events = _detect(current, previous)
    assert len(events) > 0
    for evt in events:
        assert 0.0 <= evt.confidence <= 1.0


# ---------------------------------------------------------------------------
# 15. Response anomaly (status code change)
# ---------------------------------------------------------------------------


def test_response_anomaly_detected() -> None:
    """HTTP status code change (e.g. 200->403) triggers an INFO event."""
    previous = [_obs("http", status_code="200")]
    current = [_obs("http", status_code="403")]
    events = _detect(current, previous)

    assert len(events) == 1
    assert events[0].event_type == DegradationEventType.RESPONSE_ANOMALY
    assert events[0].severity == DegradationSeverity.INFO
    assert events[0].previous_value == "200"
    assert events[0].current_value == "403"


# ---------------------------------------------------------------------------
# 16. Hosting migration detected
# ---------------------------------------------------------------------------


def test_hosting_migration_detected() -> None:
    """Hosting provider change triggers MEDIUM severity."""
    previous = [_obs("ip-geo", hosting_provider="DigitalOcean")]
    current = [_obs("ip-geo", hosting_provider="AWS")]
    events = _detect(current, previous)

    assert len(events) == 1
    assert events[0].event_type == DegradationEventType.HOSTING_MIGRATION
    assert events[0].severity == DegradationSeverity.MEDIUM


# ---------------------------------------------------------------------------
# 17. Nameserver change detected
# ---------------------------------------------------------------------------


def test_nameserver_change_detected() -> None:
    """Nameserver set change triggers LOW severity."""
    previous = [_obs("dns", nameservers=["ns1.old.com", "ns2.old.com"])]
    current = [_obs("dns", nameservers=["ns1.new.com", "ns2.new.com"])]
    events = _detect(current, previous)

    assert len(events) == 1
    assert events[0].event_type == DegradationEventType.NAMESERVER_CHANGE
    assert events[0].severity == DegradationSeverity.LOW


# ---------------------------------------------------------------------------
# 18. Both empty -> no events
# ---------------------------------------------------------------------------


def test_both_empty_no_events() -> None:
    """Empty current and empty previous produce zero events."""
    events = _detect(current=[], previous=[])
    assert events == []


# ---------------------------------------------------------------------------
# 19. Cert expiry with datetime object (not string)
# ---------------------------------------------------------------------------


def test_cert_expiry_with_datetime_object() -> None:
    """cert_not_after as a datetime object (not string) is handled."""
    expiry = datetime.now(tz=UTC) + timedelta(days=5)
    current = [_obs("tls", cert_not_after=expiry)]
    events = _detect(current, previous=[_obs("tls", cert_issuer="LE")])

    expiry_events = [e for e in events if e.event_type == DegradationEventType.CERT_EXPIRY_IMMINENT]
    assert len(expiry_events) == 1
    assert expiry_events[0].severity == DegradationSeverity.CRITICAL


# ---------------------------------------------------------------------------
# 20. Entity identifier propagated to all events
# ---------------------------------------------------------------------------


def test_entity_identifier_propagated() -> None:
    """All events carry the correct entity_identifier."""
    previous = [_obs("whois", registrar="Old")]
    current = [_obs("whois", registrar="New")]
    events = _detect(current, previous, entity_identifier="special.example.org")

    assert len(events) == 1
    assert events[0].entity_identifier == "special.example.org"
